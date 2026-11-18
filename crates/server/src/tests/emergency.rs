//! Emergency access: every step and who may take it, the waiting period and the
//! sweeper, the admin switch, what the vault view returns and never returns,
//! attachments, and accounts that are disabled or deleted. The keys (v2): which
//! vaults confirming must wrap, adding wraps later, what removes wraps and what
//! marks vaults for a key replacement, and migration 13.

use std::collections::BTreeSet;

use passauth_core::keys::{EmergencyKey, NewEmergencyKey};

use super::attachments::{attach, download, files_app, item_in_vault, raw};
use super::*;

/// `{method} /api/emergency-access{path}` as `token`.
async fn ea(
    app: &Router,
    token: &str,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    call(
        app,
        method,
        &format!("/api/emergency-access{path}"),
        Some(token),
        body,
    )
    .await
}

/// [`ea`] that must succeed; returns the body.
async fn ea_ok(app: &Router, token: &str, method: Method, path: &str, body: Value) -> Value {
    let (s, v) = ea(app, token, method, path, body).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    v
}

/// Vault keys wrapped with `key` (of access `id`), as `vault_keys` takes them, each
/// with key epoch 0 (a vault whose key was never replaced).
fn wraps(key: &EmergencyKey, id: &str, vaults: &[(&str, &SymmetricKey)]) -> Value {
    assert_eq!(key.grant_id(), id);
    vaults
        .iter()
        .map(|(v, k)| {
            json!({ "vault_id": v, "wrapped_key": key.wrap_vault_key(k, v).unwrap(), "key_epoch": 0 })
        })
        .collect()
}

/// What the grantor's app sends to confirm access `id`: a new emergency key sealed to
/// the contact's public key, wrapped by the grantor's account key, and wrapping each
/// of `vaults`. Also returns the key.
fn confirm_body(
    grantor: &Client,
    contact_public_key: &str,
    id: &str,
    vaults: &[(&str, &SymmetricKey)],
) -> (Value, EmergencyKey) {
    let NewEmergencyKey { key, wrapped } = grantor.unlocked.new_emergency_key(id).unwrap();
    let sealed = key
        .seal_for(contact_public_key, &grantor.unlocked.account_id, id)
        .unwrap();
    let body = json!({ "sealed_key": sealed, "grantor_key": wrapped, "vault_keys": wraps(&key, id, vaults) });
    (body, key)
}

/// The contact's app opens the sealed key of access `id`.
fn open_sealed(contact: &Client, grantor_id: &str, id: &str, sealed: &str) -> EmergencyKey {
    contact
        .unlocked
        .open_sealed_emergency_key(grantor_id, id, sealed)
        .unwrap()
}

/// Access `id` as its grantor lists it.
async fn as_grantor(app: &Router, token: &str, id: &str) -> Value {
    let list = ea_ok(app, token, Method::GET, "", json!(null)).await;
    list["as_grantor"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("no access {id} in {list}"))
}

/// The ids in a JSON array, sorted.
fn ids(v: &Value) -> BTreeSet<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}

/// The grantor names the contact (7 days), the contact accepts, the grantor
/// confirms with the grantor's first vault (their only personal one): the access's id.
async fn confirmed(
    app: &Router,
    grantor: &Client,
    tg: &str,
    contact_email: &str,
    tc: &str,
) -> String {
    let vault = (grantor.vault_id.as_str(), &grantor.vault_key);
    confirmed_with(app, grantor, tg, contact_email, tc, &[vault])
        .await
        .0
}

/// [`confirmed`] wrapping `vaults`, which must be the grantor's personal vaults: the
/// access's id and its emergency key.
async fn confirmed_with(
    app: &Router,
    grantor: &Client,
    tg: &str,
    contact_email: &str,
    tc: &str,
    vaults: &[(&str, &SymmetricKey)],
) -> (String, EmergencyKey) {
    let g = ea_ok(
        app,
        tg,
        Method::POST,
        "",
        json!({ "grantee_email": contact_email, "wait_days": 7 }),
    )
    .await;
    let id = g["id"].as_str().unwrap().to_owned();
    let g = ea_ok(app, tc, Method::POST, &format!("/{id}/accept"), json!(null)).await;
    assert_eq!(g["status"], "accepted");
    let listed = as_grantor(app, tg, &id).await;
    let expected: BTreeSet<String> = vaults.iter().map(|(v, _)| (*v).to_owned()).collect();
    assert_eq!(ids(&listed["missing_vaults"]), expected);
    let (body, key) = confirm_body(
        grantor,
        g["grantee"]["public_key"].as_str().unwrap(),
        &id,
        vaults,
    );
    let g = ea_ok(app, tg, Method::POST, &format!("/{id}/confirm"), body).await;
    assert_eq!(g["status"], "confirmed");
    (id, key)
}

/// The grantor (signed in with `tg`; `login` is their email and master password)
/// approves access `id` with a fresh reauth token, as their app does.
async fn approve(app: &Router, login: (&str, &str), tg: &str, id: &str) -> Value {
    let reauth = reauth_token(app, login.0, login.1, tg).await;
    let (s, v) = call_with(
        app,
        Method::POST,
        &format!("/api/emergency-access/{id}/approve"),
        Some(tg),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// The contact asks and the grantor approves.
async fn approved(app: &Router, login: (&str, &str), tg: &str, tc: &str, id: &str) {
    ea_ok(
        app,
        tc,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    approve(app, login, tg, id).await;
}

/// The vault ids the contact's view of access `id` lists.
async fn viewed_vaults(app: &Router, tc: &str, id: &str) -> BTreeSet<String> {
    let view = ea_ok(app, tc, Method::GET, &format!("/{id}/vault"), json!(null)).await;
    view["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_owned())
        .collect()
}

/// The vaults with a wrap for access `id`, as stored.
async fn stored_wraps(state: &AppState, id: &str) -> BTreeSet<String> {
    sqlx::query_scalar("SELECT vault_id FROM emergency_vault_keys WHERE access_id = $1")
        .bind(id)
        .fetch_all(&state.db)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

/// `rotation_pending` of `vault`, as stored.
async fn rotation_pending(state: &AppState, vault: &str) -> i64 {
    sqlx::query_scalar("SELECT rotation_pending FROM vaults WHERE id = $1")
        .bind(vault)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

fn types(events: &[Value]) -> BTreeSet<String> {
    events
        .iter()
        .filter_map(|e| e["type"].as_str())
        .filter(|t| t.starts_with("emergency."))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn emergency_access_goes_step_by_step_and_each_side_takes_its_own_steps() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "ea-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "ea-b@example.com", "pw-bobby-123").await;
    let carol = register(&app, "ea-c@example.com", "pw-carol-123").await;
    let ta = token(&app, "ea-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "ea-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "ea-c@example.com", "pw-carol-123").await;
    let alice_id = user_id(&app, &ta).await;
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("emergency_access"))
    );

    // Naming a contact: a verified user of this server, 1–90 days, once.
    for (body, status) in [
        (
            json!({ "grantee_email": "nobody@example.com", "wait_days": 7 }),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({ "grantee_email": "ea-a@example.com", "wait_days": 7 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "grantee_email": "ea-b@example.com", "wait_days": 0 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "grantee_email": "ea-b@example.com", "wait_days": 91 }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(ea(&app, &ta, Method::POST, "", body).await.0, status);
    }
    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        "",
        json!({ "grantee_email": " EA-B@Example.com ", "wait_days": 7 }),
    )
    .await;
    assert_eq!(
        (&g["status"], &g["wait_days"]),
        (&json!("invited"), &json!(7))
    );
    assert_eq!(
        (&g["grantor"]["id"], &g["grantee"]["email"]),
        (&json!(alice_id), &json!("ea-b@example.com"))
    );
    assert!(g["grantee"]["public_key"].is_string() && g["grantor"]["public_key"].is_string());
    assert!(g.get("sealed_key").is_none() && g["auto_approve_at"].is_null());
    let id = g["id"].as_str().unwrap().to_owned();
    let (s, v) = ea(
        &app,
        &ta,
        Method::POST,
        "",
        json!({ "grantee_email": "ea-b@example.com", "wait_days": 3 }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );

    // Both sides see it, with each other's public key; nobody else does.
    let mine = ea_ok(&app, &ta, Method::GET, "", json!(null)).await;
    assert_eq!(
        (
            mine["as_grantor"].as_array().unwrap().len(),
            mine["as_grantee"].as_array().unwrap().len()
        ),
        (1, 0)
    );
    let theirs = ea_ok(&app, &tb, Method::GET, "", json!(null)).await;
    assert_eq!(theirs["as_grantee"][0]["id"], id);
    let (_, alice_account) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    let alice_bundle = synced(&app, &ta).await["bundle"].clone();
    assert_eq!(
        theirs["as_grantee"][0]["grantor"]["public_key"],
        alice_bundle["public_key"]
    );
    assert!(alice_account["fingerprint"].is_string());
    let others = ea_ok(&app, &tc, Method::GET, "", json!(null)).await;
    assert_eq!(
        others,
        json!({ "as_grantor": [], "as_grantee": [], "roster": null, "roster_seq": 0 })
    );
    // The grantor's listing adds what their apps need for the keys; the contact's doesn't.
    let listed = &mine["as_grantor"][0];
    assert_eq!(
        (
            &listed["key_version"],
            &listed["grantor_key"],
            &listed["reconfirm"],
            &listed["missing_vaults"]
        ),
        (&json!(2), &Value::Null, &json!(false), &json!([]))
    );
    for field in ["key_version", "grantor_key", "reconfirm", "missing_vaults"] {
        assert!(theirs["as_grantee"][0].get(field).is_none(), "{field}");
    }
    let bob_public_key = theirs["as_grantee"][0]["grantee"]["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let own_vault = (alice.vault_id.as_str(), &alice.vault_key);
    let (any_body, _) = confirm_body(&alice, &bob_public_key, &id, &[own_vault]);
    let steps = [
        (Method::POST, "/accept", json!(null)),
        (Method::POST, "/confirm", any_body.clone()),
        (Method::PUT, "/vault-keys", json!({ "vault_keys": [] })),
        (Method::POST, "/request", json!(null)),
        (Method::POST, "/approve", json!(null)),
        (Method::POST, "/reject", json!(null)),
        (Method::PUT, "", json!({ "wait_days": 3 })),
        (Method::GET, "/vault", json!(null)),
        (Method::DELETE, "", json!(null)),
    ];
    for (method, step, body) in &steps {
        let (s, _) = ea(
            &app,
            &tc,
            method.clone(),
            &format!("/{id}{step}"),
            body.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{step} by a stranger");
    }
    // Each step belongs to one side.
    for (method, step, body) in &steps[1..7] {
        if *step == "/request" {
            continue;
        }
        let (s, _) = ea(
            &app,
            &tb,
            method.clone(),
            &format!("/{id}{step}"),
            body.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{step} by the contact");
    }
    for step in ["/accept", "/request", "/vault"] {
        let method = if step == "/vault" {
            Method::GET
        } else {
            Method::POST
        };
        let (s, _) = ea(&app, &ta, method, &format!("/{id}{step}"), json!(null)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{step} by the grantor");
    }

    // In order: no confirming before the contact accepts, no asking before being confirmed.
    let (s, _) = ea(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/confirm"),
        any_body.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(
        ea(
            &app,
            &tb,
            Method::POST,
            &format!("/{id}/request"),
            json!(null)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        ea(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/approve"),
            json!(null)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        ea(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for _ in 0..2 {
        let g = ea_ok(
            &app,
            &tb,
            Method::POST,
            &format!("/{id}/accept"),
            json!(null),
        )
        .await;
        assert_eq!(g["status"], "accepted");
    }
    assert_eq!(
        ea(
            &app,
            &tb,
            Method::POST,
            &format!("/{id}/request"),
            json!(null)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    for field in ["sealed_key", "grantor_key"] {
        let mut bad = any_body.clone();
        bad[field] = "not base64!".into();
        let (s, _) = ea(&app, &ta, Method::POST, &format!("/{id}/confirm"), bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{field}");
    }
    // Before contacting the server, the listing says which vaults to wrap: her only one.
    assert_eq!(
        as_grantor(&app, &ta, &id).await["missing_vaults"],
        json!([alice.vault_id])
    );
    let (body, _) = confirm_body(&alice, &bob_public_key, &id, &[own_vault]);
    for _ in 0..2 {
        let g = ea_ok(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/confirm"),
            body.clone(),
        )
        .await;
        assert_eq!(g["status"], "confirmed");
    }
    let listed = as_grantor(&app, &ta, &id).await;
    assert_eq!(listed["grantor_key"], body["grantor_key"]);
    assert_eq!(
        (&listed["reconfirm"], &listed["missing_vaults"]),
        (&json!(false), &json!([]))
    );
    let (other, _) = confirm_body(&alice, &bob_public_key, &id, &[own_vault]);
    let (s, _) = ea(&app, &ta, Method::POST, &format!("/{id}/confirm"), other).await;
    assert_eq!(s, StatusCode::CONFLICT, "a confirmed key isn't replaced");
    assert_eq!(
        ea(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null))
            .await
            .0,
        StatusCode::FORBIDDEN
    );

    // Asking: the waiting period starts; asking again changes nothing.
    let g = ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    assert_eq!(g["status"], "requested");
    let asked = g["requested_at"].as_i64().unwrap();
    assert_eq!(g["auto_approve_at"], asked + 7 * 86_400);
    let g = ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    assert_eq!(
        (&g["status"], &g["requested_at"]),
        (&json!("requested"), &json!(asked))
    );
    assert_eq!(
        ea(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Rejected; asked again; approved.
    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/reject"),
        json!(null),
    )
    .await;
    assert_eq!(
        (&g["status"], &g["auto_approve_at"]),
        (&json!("rejected"), &Value::Null)
    );
    assert_eq!(
        ea(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/approve"),
            json!(null)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        ea_ok(
            &app,
            &tb,
            Method::POST,
            &format!("/{id}/request"),
            json!(null)
        )
        .await["status"],
        "requested"
    );

    // What Alice alone has: her own vaults (trash included). Not a vault she shares
    // (even only by invitation), not one shared with her.
    let personal = item_in_vault_named(
        &app,
        &ta,
        (&alice.vault_id, &alice.vault_key),
        "Alice's login",
    )
    .await;
    let trashed =
        item_in_vault_named(&app, &ta, (&alice.vault_id, &alice.vault_key), "Old login").await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{trashed}"),
        &ta,
        json!(null),
    )
    .await;
    let (second, second_key) = new_vault(&app, &alice, &ta).await;
    let in_second = item_in_vault_named(&app, &ta, (&second, &second_key), "Second").await;
    let (shared, shared_key) = new_vault(&app, &alice, &ta).await;
    let in_shared = item_in_vault_named(&app, &ta, (&shared, &shared_key), "Shared").await;
    let (s, _) = share_vault(
        &app,
        (&shared, &shared_key),
        &ta,
        "ea-c@example.com",
        "read",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        share(&app, &carol, &tc, "ea-a@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &ta, &carol.vault_id).await;
    let carols =
        item_in_vault_named(&app, &tc, (&carol.vault_id, &carol.vault_key), "Carol's").await;
    // The new personal vault waits for its wrap; the shared ones never get one.
    assert_eq!(
        as_grantor(&app, &ta, &id).await["missing_vaults"],
        json!([second])
    );
    let alices_key = alice
        .unlocked
        .open_emergency_key(&id, body["grantor_key"].as_str().unwrap())
        .unwrap();
    for wrong in [
        (shared.as_str(), &shared_key),
        (carol.vault_id.as_str(), &carol.vault_key),
    ] {
        let (s, v) = ea(
            &app,
            &ta,
            Method::PUT,
            &format!("/{id}/vault-keys"),
            json!({ "vault_keys": wraps(&alices_key, &id, &[wrong]) }),
        )
        .await;
        assert_eq!(
            (s, &v["error"], &v["expected"]),
            (
                StatusCode::CONFLICT,
                &json!("emergency_vaults_changed"),
                &json!([second])
            ),
            "{v}"
        );
    }
    let filled = ea_ok(
        &app,
        &ta,
        Method::PUT,
        &format!("/{id}/vault-keys"),
        json!({ "vault_keys": wraps(&alices_key, &id, &[(second.as_str(), &second_key)]) }),
    )
    .await;
    assert_eq!(filled["missing_vaults"], json!([]));
    assert_eq!(
        stored_wraps(&state, &id).await,
        BTreeSet::from([alice.vault_id.clone(), second.clone()])
    );

    // Approving needs the master password again (a reauth token).
    let (s, v) = ea(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/approve"),
        json!(null),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    let g = approve(&app, ("ea-a@example.com", "pw-alice-123"), &ta, &id).await;
    assert_eq!(g["status"], "approved");
    assert!(g["approved_at"].is_i64());
    assert_eq!(
        ea_ok(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/approve"),
            json!(null)
        )
        .await["status"],
        "approved"
    );
    let view = ea_ok(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null)).await;
    let keys: BTreeSet<&str> = view
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from(["grant", "items", "key_version", "sealed_key", "vaults"])
    );
    assert_eq!(view["key_version"], 2);
    assert_eq!(view["grant"]["status"], "approved");
    let vaults = view["vaults"].as_array().unwrap();
    let vault_ids: BTreeSet<&str> = vaults.iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert_eq!(
        vault_ids,
        BTreeSet::from([alice.vault_id.as_str(), second.as_str()])
    );
    for v in vaults {
        let fields: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "id",
                "key_epoch",
                "manifest",
                "manifest_seq",
                "meta",
                "wrapped_key"
            ])
        );
    }
    let items = view["items"].as_array().unwrap();
    let item_ids: BTreeSet<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(
        item_ids,
        BTreeSet::from([personal.as_str(), trashed.as_str(), in_second.as_str()])
    );
    assert!(items.iter().find(|i| i["id"] == trashed).unwrap()["deleted_at"].is_i64());
    // Nothing else of Alice's: no bundle, keys or other vaults.
    let text = view.to_string();
    for secret in ["wrapped_account_key", "wrapped_private_key"] {
        assert!(
            !text.contains(alice_bundle[secret].as_str().unwrap()),
            "{secret}"
        );
    }
    assert!(!text.contains(body["grantor_key"].as_str().unwrap()));
    for other in [&shared, &in_shared, &carol.vault_id, &carols] {
        assert!(!text.contains(other.as_str()), "{other}");
    }
    // The vault keys handed out are the emergency wraps, never the account-key ones.
    let synced_alice = synced(&app, &ta).await;
    let own = vault_in(&synced_alice, &alice.vault_id).unwrap()["wrapped_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!text.contains(&own));
    // Bob's app opens it all with the sealed key; the server never could.
    let alices = open_sealed(&bob, &alice_id, &id, view["sealed_key"].as_str().unwrap());
    let row = items.iter().find(|i| i["id"] == personal).unwrap();
    let wrapped = vaults.iter().find(|v| v["id"] == alice.vault_id).unwrap()["wrapped_key"]
        .as_str()
        .unwrap();
    let vault_key = alices.open_vault_key(&alice.vault_id, wrapped).unwrap();
    assert!(alices.open_vault_key(&second, wrapped).is_err());
    let item = EncryptedItem {
        id: personal.clone(),
        vault_id: alice.vault_id.clone(),
        key: row["item_key"].as_str().unwrap().into(),
        data: row["data"].as_str().unwrap().into(),
    }
    .decrypt(&vault_key)
    .unwrap();
    assert_eq!(item.name, "Alice's login");
    assert!(!text.contains("Alice's login"));

    // Alice ends it: no more views. The waiting period is hers to change.
    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/reject"),
        json!(null),
    )
    .await;
    assert_eq!(
        (&g["status"], &g["approved_at"]),
        (&json!("rejected"), &Value::Null)
    );
    assert_eq!(
        ea(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let g = ea_ok(
        &app,
        &ta,
        Method::PUT,
        &format!("/{id}"),
        json!({ "wait_days": 14 }),
    )
    .await;
    assert_eq!(g["wait_days"], 14);
    assert_eq!(
        ea(
            &app,
            &ta,
            Method::PUT,
            &format!("/{id}"),
            json!({ "wait_days": 91 })
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );

    // Both logs tell the story; the contact never sees Alice's addresses, nor which
    // vaults she added later.
    let mut expected: BTreeSet<String> = [
        "emergency.invited",
        "emergency.accepted",
        "emergency.confirmed",
        "emergency.requested",
        "emergency.rejected",
        "emergency.approved",
        "emergency.viewed",
        "emergency.updated",
    ]
    .map(str::to_owned)
    .into();
    let events = all_pages(&app, &tb, "/api/account/events", 200).await;
    assert_eq!(types(&events), expected);
    expected.insert("emergency.vaults_added".into());
    let events = all_pages(&app, &ta, "/api/account/events", 200).await;
    assert_eq!(types(&events), expected);
    let stored = stored_events(&state).await;
    assert_eq!(
        of_type(&stored, "emergency.confirmed")[0]["data"],
        json!({ "grant": id, "vaults": 1 })
    );
    assert_eq!(
        of_type(&stored, "emergency.vaults_added")[0]["data"],
        json!({ "grant": id, "vaults": 1 })
    );
    let viewed = of_type(&stored, "emergency.viewed");
    assert_eq!(
        viewed[0]["data"],
        json!({ "grant": id, "vaults": 2, "items": 3 })
    );
    assert_eq!(viewed[0]["target_user_id"], alice_id);

    // Either side removes it; then it's gone for both. The contact's answer names no
    // vaults (their apps never replace anyone's keys), though Alice's are marked below.
    assert_eq!(
        ea_ok(&app, &tb, Method::DELETE, &format!("/{id}"), json!(null)).await,
        json!({ "ok": true })
    );
    assert_eq!(
        ea_ok(&app, &ta, Method::GET, "", json!(null)).await["as_grantor"],
        json!([])
    );
    assert_eq!(
        ea(&app, &ta, Method::DELETE, &format!("/{id}"), json!(null))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ea(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let removed = stored_events(&state).await;
    let removed = of_type(&removed, "emergency.removed");
    assert_eq!(
        removed[0]["data"],
        json!({ "grant": id, "status": "rejected", "by": "grantee", "rotate_vaults": 2 })
    );
    // Bob may have kept the key: both vaults it opened are marked for a new key.
    assert!(stored_wraps(&state, &id).await.is_empty());
    for vault in [&alice.vault_id, &second] {
        assert_eq!(rotation_pending(&state, vault).await, 1, "{vault}");
    }
    assert_eq!(rotation_pending(&state, &shared).await, 0);
}

/// A new item named `name` in the vault (id, key): its id.
async fn item_in_vault_named(
    app: &Router,
    token: &str,
    vault: (&str, &SymmetricKey),
    name: &str,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let item = Item {
        format: ITEM_FORMAT,
        name: name.into(),
        ..Default::default()
    };
    let enc = EncryptedItem::encrypt(&item, &id, vault.0, vault.1).unwrap();
    ok(
        app,
        Method::POST,
        "/api/items",
        token,
        json!({ "id": id, "vault_id": vault.0, "key": enc.key, "data": enc.data }),
    )
    .await;
    id
}

#[tokio::test]
async fn requests_are_approved_when_the_waiting_period_ends_unless_turned_off() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "w-a@example.com", "pw-alice-123").await;
    register(&app, "w-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "w-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "w-b@example.com", "pw-bobby-123").await;
    let (alice_id, bob_id) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let id = confirmed(&app, &alice, &ta, "w-b@example.com", &tb).await;
    ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    let wait = |days: i64| {
        let (db, id) = (state.db.clone(), id.clone());
        async move {
            sqlx::query(
                "UPDATE emergency_access SET requested_at = requested_at - $1 WHERE id = $2",
            )
            .bind(days * 86_400 + 1)
            .bind(&id)
            .execute(&db)
            .await
            .unwrap();
        }
    };
    // Six days on, still waiting.
    wait(6).await;
    assert_eq!(crate::emergency::approve_waited(&state).await.unwrap(), 0);

    // A day later the period has ended, but the admin has turned emergency access
    // off: nothing is approved, and only taking access away still works.
    wait(1).await;
    assert_eq!(
        admin_set(&app, json!({ "emergency_access": false }))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(crate::emergency::approve_waited(&state).await.unwrap(), 0);
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        !config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("emergency_access"))
    );
    for (t, method, step) in [
        (&tb, Method::GET, "/vault"),
        (&tb, Method::POST, "/request"),
        (&ta, Method::POST, "/approve"),
    ] {
        let (s, v) = ea(&app, t, method, &format!("/{id}{step}"), json!(null)).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("emergency_access_disabled")),
            "{step}"
        );
    }
    let (s, v) = ea(
        &app,
        &ta,
        Method::POST,
        "",
        json!({ "grantee_email": "w-b@example.com", "wait_days": 2 }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("emergency_access_disabled"))
    );
    assert_eq!(
        ea_ok(&app, &ta, Method::GET, "", json!(null)).await["as_grantor"][0]["status"],
        "requested"
    );
    assert_eq!(
        ea_ok(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/reject"),
            json!(null)
        )
        .await["status"],
        "rejected"
    );

    // On again: a new request waits its own seven days, then the sweeper approves it.
    assert_eq!(
        admin_set(&app, json!({ "emergency_access": true })).await.0,
        StatusCode::OK
    );
    ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    assert_eq!(crate::emergency::approve_waited(&state).await.unwrap(), 0);
    wait(7).await;
    assert_eq!(crate::emergency::approve_waited(&state).await.unwrap(), 1);
    assert_eq!(crate::emergency::approve_waited(&state).await.unwrap(), 0);
    let g = &ea_ok(&app, &tb, Method::GET, "", json!(null)).await["as_grantee"][0];
    assert_eq!(g["status"], "approved");
    assert!(g["approved_at"].is_i64());
    ea_ok(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null)).await;
    // One event for each side, by nobody (the server).
    let events = stored_events(&state).await;
    let automatic: Vec<&Value> = of_type(&events, "emergency.approved")
        .into_iter()
        .filter(|e| e["data"]["automatic"] == true)
        .collect();
    assert_eq!(automatic.len(), 2);
    assert!(
        automatic
            .iter()
            .all(|e| e["actor_id"].is_null() && e["data"]["grant"] == id)
    );
    let targets: BTreeSet<&str> = automatic
        .iter()
        .map(|e| e["target_user_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        targets,
        BTreeSet::from([alice_id.as_str(), bob_id.as_str()])
    );
}

#[tokio::test]
async fn naming_contacts_is_rate_limited() {
    let app = app().await;
    register(&app, "rl@example.com", "pw-limit-123").await;
    let t = token(&app, "rl@example.com", "pw-limit-123").await;
    for i in 0..20 {
        let body = json!({ "grantee_email": format!("nobody{i}@example.com"), "wait_days": 7 });
        assert_eq!(
            ea(&app, &t, Method::POST, "", body).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let body = json!({ "grantee_email": "nobody@example.com", "wait_days": 7 });
    let (s, v) = ea(&app, &t, Method::POST, "", body).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited"))
    );
}

#[tokio::test]
async fn emergency_access_ends_with_either_account_and_waits_while_the_grantor_is_disabled() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "d-a@example.com", "pw-alice-123").await;
    register(&app, "d-b@example.com", "pw-bobby-123").await;
    register(&app, "d-c@example.com", "pw-carol-123").await;
    let mut ta = token(&app, "d-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "d-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "d-c@example.com", "pw-carol-123").await;
    let alice_id = user_id(&app, &ta).await;
    let to_bob = confirmed(&app, &alice, &ta, "d-b@example.com", &tb).await;
    ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{to_bob}/request"),
        json!(null),
    )
    .await;
    approve(&app, ("d-a@example.com", "pw-alice-123"), &ta, &to_bob).await;
    let view = format!("/{to_bob}/vault");
    ea_ok(&app, &tb, Method::GET, &view, json!(null)).await;

    // A disabled account's vaults stay closed until the admin enables it again.
    let admin = |action: &'static str| {
        let (app, alice_id) = (app.clone(), alice_id.clone());
        async move {
            let path = format!("/api/admin/users/{alice_id}/{action}");
            let (s, v) = call(&app, Method::POST, &path, Some("test-admin"), json!(null)).await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };
    admin("disable").await;
    assert_eq!(
        ea(&app, &tb, Method::GET, &view, json!(null)).await.0,
        StatusCode::NOT_FOUND
    );
    admin("enable").await;
    ea_ok(&app, &tb, Method::GET, &view, json!(null)).await;
    ta = token(&app, "d-a@example.com", "pw-alice-123").await;

    // Deleting the contact's account removes their access, and the vault wrapped for
    // them is marked for a new key (Bob's wraps stay)…
    let to_carol = confirmed(&app, &alice, &ta, "d-c@example.com", &tc).await;
    assert_eq!(rotation_pending(&state, &alice.vault_id).await, 0);
    let before = rev_of(&app, &ta).await;
    let reauth = reauth_token(&app, "d-c@example.com", "pw-carol-123", &tc).await;
    let (s, _) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&tc),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let left = ea_ok(&app, &ta, Method::GET, "", json!(null)).await;
    let ids: Vec<&str> = left["as_grantor"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [to_bob.as_str()]);
    assert!(!ids.contains(&to_carol.as_str()));
    assert_eq!(rotation_pending(&state, &alice.vault_id).await, 1);
    assert!(rev_of(&app, &ta).await > before, "Alice's apps are told");
    assert!(stored_wraps(&state, &to_carol).await.is_empty());
    assert_eq!(
        stored_wraps(&state, &to_bob).await,
        BTreeSet::from([alice.vault_id.clone()])
    );
    // …and deleting the grantor's removes theirs.
    let reauth = reauth_token(&app, "d-a@example.com", "pw-alice-123", &ta).await;
    let (s, _) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&ta),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        ea_ok(&app, &tb, Method::GET, "", json!(null)).await["as_grantee"],
        json!([])
    );
    for table in ["emergency_access", "emergency_vault_keys"] {
        let count: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[tokio::test]
async fn an_approved_contact_downloads_the_grantors_own_attachments_only() {
    let (app, _state, dir) = files_app().await;
    let alice = register(&app, "f-a@example.com", "pw-alice-123").await;
    register(&app, "f-b@example.com", "pw-bobby-123").await;
    register(&app, "f-c@example.com", "pw-carol-123").await;
    let ta = token(&app, "f-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "f-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "f-c@example.com", "pw-carol-123").await;
    let item = item_in_vault(&app, &ta, (&alice.vault_id, &alice.vault_key)).await;
    let own = attach(&app, &ta, &item, b"alice's file").await;
    let (shared, key) = new_vault(&app, &alice, &ta).await;
    let (s, _) = share_vault(&app, (&shared, &key), &ta, "f-c@example.com", "read", None).await;
    assert_eq!(s, StatusCode::OK);
    accept(&app, &tc, &shared).await;
    let shared_item = item_in_vault(&app, &ta, (&shared, &key)).await;
    let theirs = attach(&app, &ta, &shared_item, b"shared file").await;
    let id = confirmed(&app, &alice, &ta, "f-b@example.com", &tb).await;
    let get = |token: String, file: String| {
        let (app, id) = (app.clone(), id.clone());
        async move {
            let path = format!("/api/emergency-access/{id}/attachments/{file}");
            raw(&app, Method::GET, &path, Some(&token), &[], Body::empty()).await
        }
    };
    assert_eq!(
        get(tb.clone(), own.clone()).await.0,
        StatusCode::FORBIDDEN,
        "not approved yet"
    );
    ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/request"),
        json!(null),
    )
    .await;
    approve(&app, ("f-a@example.com", "pw-alice-123"), &ta, &id).await;

    let (s, h, bytes) = get(tb.clone(), own.clone()).await;
    assert_eq!(
        (s, bytes.as_slice()),
        (StatusCode::OK, b"alice's file".as_slice())
    );
    assert_eq!(h["content-disposition"], "attachment");
    assert_eq!(h["content-security-policy"], "default-src 'none'; sandbox");
    for file in [
        theirs.clone(),
        uuid::Uuid::new_v4().to_string(),
        "not-a-uuid".into(),
    ] {
        assert_eq!(get(tb.clone(), file).await.0, StatusCode::NOT_FOUND);
    }
    // Only through the access: not as a member, and not for anyone else.
    assert_eq!(download(&app, &tb, &own).await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(tc.clone(), own.clone()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        download(&app, &tc, &theirs).await.0,
        StatusCode::OK,
        "Carol reads the vault she is in"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn confirming_wraps_exactly_the_personal_vaults() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "cv-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "cv-b@example.com", "pw-bobby-123").await;
    let carol = register(&app, "cv-c@example.com", "pw-carol-123").await;
    let ta = token(&app, "cv-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "cv-b@example.com", "pw-bobby-123").await;
    let alice_id = user_id(&app, &ta).await;
    let (second, second_key) = new_vault(&app, &alice, &ta).await;
    // Shared by invitation only: no longer personal.
    let (shared, shared_key) = new_vault(&app, &alice, &ta).await;
    let (s, _) = share_vault(
        &app,
        (&shared, &shared_key),
        &ta,
        "cv-c@example.com",
        "read",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        "",
        json!({ "grantee_email": "cv-b@example.com", "wait_days": 3 }),
    )
    .await;
    let id = g["id"].as_str().unwrap().to_owned();
    assert_eq!(
        as_grantor(&app, &ta, &id).await["missing_vaults"],
        json!([])
    );
    let g = ea_ok(
        &app,
        &tb,
        Method::POST,
        &format!("/{id}/accept"),
        json!(null),
    )
    .await;
    let pk = g["grantee"]["public_key"].as_str().unwrap().to_owned();
    let personal = BTreeSet::from([alice.vault_id.clone(), second.clone()]);
    assert_eq!(
        ids(&as_grantor(&app, &ta, &id).await["missing_vaults"]),
        personal
    );
    let own = (alice.vault_id.as_str(), &alice.vault_key);
    let sec = (second.as_str(), &second_key);
    let shr = (shared.as_str(), &shared_key);
    let carols = (carol.vault_id.as_str(), &carol.vault_key);
    let confirm = format!("/{id}/confirm");

    // An app from before emergency keys sends the sealed key alone: it must update.
    let (body, _) = confirm_body(&alice, &pk, &id, &[own, sec]);
    for old in [
        json!({ "sealed_key": body["sealed_key"] }),
        json!({ "sealed_key": body["sealed_key"], "grantor_key": body["grantor_key"] }),
        json!({ "sealed_key": body["sealed_key"], "vault_keys": body["vault_keys"] }),
    ] {
        let (s, v) = ea(&app, &ta, Method::POST, &confirm, old).await;
        assert_eq!(
            (s, &v["error"]),
            (StatusCode::BAD_REQUEST, &json!("update_required")),
            "{v}"
        );
    }
    // One missing, one too many, a shared one, someone else's, none: 409 naming the
    // vaults to wrap, and nothing stored.
    for vaults in [
        vec![own],
        vec![own, sec, shr],
        vec![own, carols],
        vec![own, sec, carols],
        vec![],
    ] {
        let (body, _) = confirm_body(&alice, &pk, &id, &vaults);
        let (s, v) = ea(&app, &ta, Method::POST, &confirm, body).await;
        assert_eq!(
            (s, &v["error"]),
            (StatusCode::CONFLICT, &json!("emergency_vaults_changed")),
            "{v}"
        );
        assert_eq!(ids(&v["expected"]), personal);
        assert!(v["message"].is_string() && v["request_id"].is_string());
        assert_eq!(as_grantor(&app, &ta, &id).await["status"], "accepted");
        assert!(stored_wraps(&state, &id).await.is_empty());
    }
    // The same vault twice, or not a vault id: malformed.
    let (mut body, _) = confirm_body(&alice, &pk, &id, &[own, sec]);
    body["vault_keys"][1]["vault_id"] = alice.vault_id.clone().into();
    assert_eq!(
        ea(&app, &ta, Method::POST, &confirm, body.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
    body["vault_keys"][1]["vault_id"] = "not-a-vault".into();
    assert_eq!(
        ea(&app, &ta, Method::POST, &confirm, body).await.0,
        StatusCode::BAD_REQUEST
    );
    // Every wrap names the epoch of the key it wraps.
    let (mut body, _) = confirm_body(&alice, &pk, &id, &[own, sec]);
    body["vault_keys"][1]
        .as_object_mut()
        .unwrap()
        .remove("key_epoch");
    assert_eq!(
        ea(&app, &ta, Method::POST, &confirm, body).await.0,
        StatusCode::BAD_REQUEST
    );
    // A key the vault has replaced since: refused, nothing stored.
    let (mut body, key) = confirm_body(&alice, &pk, &id, &[own, sec]);
    body["vault_keys"][0]["key_epoch"] = 3.into();
    let (s, v) = ea(&app, &ta, Method::POST, &confirm, body.clone()).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("vault_key_changed"))
    );
    // Exactly the personal vaults, with their current keys.
    body["vault_keys"][0]["key_epoch"] = 0.into();
    let g = ea_ok(&app, &ta, Method::POST, &confirm, body.clone()).await;
    assert_eq!(g["status"], "confirmed");
    assert_eq!(stored_wraps(&state, &id).await, personal);
    let listed = as_grantor(&app, &ta, &id).await;
    assert_eq!(listed["missing_vaults"], json!([]));
    assert_eq!(listed["grantor_key"], body["grantor_key"]);

    // Approved, Bob sees those two and opens them with his own key alone.
    approved(&app, ("cv-a@example.com", "pw-alice-123"), &ta, &tb, &id).await;
    let view = ea_ok(&app, &tb, Method::GET, &format!("/{id}/vault"), json!(null)).await;
    let theirs = open_sealed(&bob, &alice_id, &id, view["sealed_key"].as_str().unwrap());
    for v in view["vaults"].as_array().unwrap() {
        let vault = v["id"].as_str().unwrap();
        let opened = theirs
            .open_vault_key(vault, v["wrapped_key"].as_str().unwrap())
            .unwrap();
        let expected = if vault == alice.vault_id {
            &alice.vault_key
        } else {
            &second_key
        };
        assert_eq!(opened.as_bytes(), expected.as_bytes());
    }
    assert_eq!(viewed_vaults(&app, &tb, &id).await, personal);
    // Adding wraps: only for a confirmed access, only personal vaults, only added.
    let fill = format!("/{id}/vault-keys");
    let (s, v) = ea(
        &app,
        &ta,
        Method::PUT,
        &fill,
        json!({ "vault_keys": wraps(&key, &id, &[shr]) }),
    )
    .await;
    assert_eq!(
        (s, &v["error"], &v["expected"]),
        (
            StatusCode::CONFLICT,
            &json!("emergency_vaults_changed"),
            &json!([])
        )
    );
    // Every wrap names the epoch of the key it wraps.
    let (s, _) = ea(
        &app,
        &ta,
        Method::PUT,
        &fill,
        json!({ "vault_keys": [{ "vault_id": alice.vault_id, "wrapped_key": "AQID" }] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let again = ea_ok(
        &app,
        &ta,
        Method::PUT,
        &fill,
        json!({ "vault_keys": [{ "vault_id": alice.vault_id, "wrapped_key": "AQID", "key_epoch": 0 }] }),
    )
    .await;
    assert_eq!(again["missing_vaults"], json!([]));
    let kept: String = sqlx::query_scalar(
        "SELECT wrapped_key FROM emergency_vault_keys WHERE access_id = $1 AND vault_id = $2",
    )
    .bind(&id)
    .bind(&alice.vault_id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_ne!(kept, "AQID", "a wrap is never replaced");
    assert!(
        of_type(&stored_events(&state).await, "emergency.vaults_added").is_empty(),
        "nothing was added"
    );
}

#[tokio::test]
async fn wraps_follow_the_personal_vaults_and_removing_a_contact_marks_them() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "wf-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "wf-b@example.com", "pw-bobby-123").await;
    register(&app, "wf-c@example.com", "pw-carol-123").await;
    register(&app, "wf-d@example.com", "pw-dave-1234").await;
    let ta = token(&app, "wf-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "wf-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "wf-c@example.com", "pw-carol-123").await;
    let td = token(&app, "wf-d@example.com", "pw-dave-1234").await;
    let alice_id = user_id(&app, &ta).await;
    let (second, second_key) = new_vault(&app, &alice, &ta).await;
    let own = (alice.vault_id.as_str(), &alice.vault_key);
    let sec = (second.as_str(), &second_key);
    let (to_bob, bob_key) =
        confirmed_with(&app, &alice, &ta, "wf-b@example.com", &tb, &[own, sec]).await;
    let (to_dave, _) =
        confirmed_with(&app, &alice, &ta, "wf-d@example.com", &td, &[own, sec]).await;
    approved(
        &app,
        ("wf-a@example.com", "pw-alice-123"),
        &ta,
        &tb,
        &to_bob,
    )
    .await;
    let both = BTreeSet::from([alice.vault_id.clone(), second.clone()]);
    assert_eq!(viewed_vaults(&app, &tb, &to_bob).await, both);

    // Shared (even by invitation only): its wraps go for every access, and Bob no
    // longer sees it.
    let (s, v) = share_vault(&app, sec, &ta, "wf-c@example.com", "read", None).await;
    assert_eq!(s, StatusCode::OK);
    // The answer tells Alice's app to replace the key now.
    assert_eq!(v["rotation_pending"], true, "{v}");
    let only_own = BTreeSet::from([alice.vault_id.clone()]);
    for access in [&to_bob, &to_dave] {
        assert_eq!(stored_wraps(&state, access).await, only_own);
        assert_eq!(
            as_grantor(&app, &ta, access).await["missing_vaults"],
            json!([])
        );
    }
    assert_eq!(viewed_vaults(&app, &tb, &to_bob).await, only_own);
    // Bob may still hold its key, and Carol never chose to trust him: a new key is due.
    assert_eq!(rotation_pending(&state, &second).await, 1);
    // Carol declines: the vault is personal again (and marked for a new key, as the
    // invitation handed her the key). It waits for its wraps.
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{second}/invitation"),
        Some(&tc),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        as_grantor(&app, &ta, &to_bob).await["missing_vaults"],
        json!([second])
    );
    assert_eq!(viewed_vaults(&app, &tb, &to_bob).await, only_own);

    // Its key is replaced (the old one went with the invitation): still waiting, and
    // a wrap of the old key is refused.
    let rotate = json!({
        "keys": [{ "user_id": alice_id, "wrapped_key": "a2V5", "key_kind": "account" }],
        "items": [],
    });
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{second}/rotate"),
        &ta,
        rotate.clone(),
    )
    .await;
    assert_eq!(rotation_pending(&state, &second).await, 0);
    let new_key = SymmetricKey::generate().unwrap();
    let mut body =
        json!({ "vault_keys": wraps(&bob_key, &to_bob, &[(second.as_str(), &new_key)]) });
    body["vault_keys"][0]["key_epoch"] = 0.into();
    let fill = format!("/{to_bob}/vault-keys");
    let (s, v) = ea(&app, &ta, Method::PUT, &fill, body.clone()).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("vault_key_changed"))
    );
    body["vault_keys"][0]["key_epoch"] = 1.into();
    let g = ea_ok(&app, &ta, Method::PUT, &fill, body).await;
    assert_eq!(g["missing_vaults"], json!([]));
    assert_eq!(viewed_vaults(&app, &tb, &to_bob).await, both);
    let view = ea_ok(
        &app,
        &tb,
        Method::GET,
        &format!("/{to_bob}/vault"),
        json!(null),
    )
    .await;
    let theirs = open_sealed(
        &bob,
        &alice_id,
        &to_bob,
        view["sealed_key"].as_str().unwrap(),
    );
    let wrapped = view["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == second)
        .unwrap()["wrapped_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        theirs.open_vault_key(&second, &wrapped).unwrap().as_bytes(),
        new_key.as_bytes()
    );
    // Dave's access waits for its own wrap of the new key.
    assert_eq!(
        as_grantor(&app, &ta, &to_dave).await["missing_vaults"],
        json!([second])
    );

    // Rotating her first vault clears its wraps too.
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/rotate", alice.vault_id),
        &ta,
        rotate,
    )
    .await;
    assert_eq!(
        stored_wraps(&state, &to_bob).await,
        BTreeSet::from([second.clone()])
    );
    // A deleted vault's wraps go with it.
    let (third, third_key) = new_vault(&app, &alice, &ta).await;
    ea_ok(
        &app,
        &ta,
        Method::PUT,
        &fill,
        json!({ "vault_keys": wraps(&bob_key, &to_bob, &[(third.as_str(), &third_key)]) }),
    )
    .await;
    assert!(stored_wraps(&state, &to_bob).await.contains(&third));
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{third}"),
        &ta,
        json!(null),
    )
    .await;
    assert!(!stored_wraps(&state, &to_bob).await.contains(&third));

    // Ending Bob's access while keeping him changes no key.
    ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{to_bob}/reject"),
        json!(null),
    )
    .await;
    assert_eq!(rotation_pending(&state, &second).await, 0);
    assert_eq!(rotation_pending(&state, &alice.vault_id).await, 0);
    // Removing him does: the vaults he had a wrap for are marked, Alice's apps are
    // told, and her answer names them. Dave's wraps stay.
    let before = rev_of(&app, &ta).await;
    let gone = ea_ok(
        &app,
        &ta,
        Method::DELETE,
        &format!("/{to_bob}"),
        json!(null),
    )
    .await;
    assert_eq!(gone, json!({ "ok": true, "rotation_pending": [second] }));
    assert_eq!(rotation_pending(&state, &second).await, 1);
    assert_eq!(rotation_pending(&state, &alice.vault_id).await, 0);
    assert!(rev_of(&app, &ta).await > before);
    let synced_alice = synced(&app, &ta).await;
    assert_eq!(
        vault_in(&synced_alice, &second).unwrap()["rotation_pending"],
        1
    );
    assert!(stored_wraps(&state, &to_bob).await.is_empty());
    // Dave's access stays; both of its wraps went with the key changes, so his
    // listing asks for them again.
    let dave = as_grantor(&app, &ta, &to_dave).await;
    assert_eq!(dave["status"], "confirmed");
    assert_eq!(ids(&dave["missing_vaults"]), both);
    let removed = stored_events(&state).await;
    assert_eq!(
        of_type(&removed, "emergency.removed")[0]["data"],
        json!({ "grant": to_bob, "status": "rejected", "by": "grantor", "rotate_vaults": 1 })
    );
    // An access that never held a key changes nothing.
    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        "",
        json!({ "grantee_email": "wf-c@example.com", "wait_days": 3 }),
    )
    .await;
    let id = g["id"].as_str().unwrap();
    assert_eq!(
        ea_ok(&app, &ta, Method::DELETE, &format!("/{id}"), json!(null)).await,
        json!({ "ok": true, "rotation_pending": [] })
    );
}

/// A sealed account key of an access removed before the upgrade (as long as a real one).
const V1_REMOVED_KEY: &str = "cmVtb3ZlZC1hY2Nlc3Mta2V5LXYxUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDEUXVvcnVtMDE";
/// A sealed account key as v1 stored it (as long as a real one).
const V1_KEY: &str = "djEtYWNjb3VudC1rZXkWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFz";
const V1_UPDATE: &str = "UPDATE emergency_access SET sealed_key = 'djEtYWNjb3VudC1rZXkWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFzWm9yYmFz' WHERE status <> 'invited' AND status <> 'accepted'";

/// Upgrading a database from before migration 13: accesses that held a sealed account
/// key go back to `accepted` without it, flagged to confirm again, with an event for
/// each side; the others stay as they were.
#[tokio::test]
async fn migration_13_asks_to_confirm_contacts_again() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config.clone()).await.unwrap();
    let app = crate::router(state.clone());
    let alice = register(&app, "m13-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "m13-b@example.com", "pw-bobby-123").await;
    register(&app, "m13-c@example.com", "pw-carol-123").await;
    register(&app, "m13-d@example.com", "pw-dave-1234").await;
    let ta = token(&app, "m13-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "m13-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "m13-c@example.com", "pw-carol-123").await;
    let (alice_id, bob_id) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let to_bob = confirmed(&app, &alice, &ta, "m13-b@example.com", &tb).await;
    approved(
        &app,
        ("m13-a@example.com", "pw-alice-123"),
        &ta,
        &tb,
        &to_bob,
    )
    .await;
    let name = |email: &str| json!({ "grantee_email": email, "wait_days": 5 });
    let to_carol = ea_ok(&app, &ta, Method::POST, "", name("m13-c@example.com")).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ea_ok(
        &app,
        &tc,
        Method::POST,
        &format!("/{to_carol}/accept"),
        json!(null),
    )
    .await;
    let to_dave = ea_ok(&app, &ta, Method::POST, "", name("m13-d@example.com")).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bobs = confirmed(&app, &bob, &tb, "m13-a@example.com", &ta).await;
    // Back to the schema of migration 12, the sealed keys as v1 stored them (on one
    // connection that overwrites what it frees, so only the rows hold them).
    let mut conn = state.db.acquire().await.unwrap();
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        sqlx::query("PRAGMA secure_delete = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    for &stmt in UNDO_MIGRATION_14 {
        sqlx::query(stmt).execute(&mut *conn).await.unwrap();
    }
    for stmt in [
        V1_UPDATE,
        "DROP TABLE emergency_vault_keys",
        "ALTER TABLE emergency_access DROP COLUMN key_version",
        "ALTER TABLE emergency_access DROP COLUMN grantor_key",
        "ALTER TABLE emergency_access DROP COLUMN reconfirm",
        "ALTER TABLE emergency_access DROP COLUMN v1_exposed",
        "ALTER TABLE users DROP COLUMN emergency_roster",
        "ALTER TABLE users DROP COLUMN emergency_roster_seq",
        "DELETE FROM schema_version WHERE version = 13",
    ] {
        sqlx::query(stmt).execute(&mut *conn).await.unwrap();
    }
    drop(conn);
    // An access confirmed and removed before the upgrade: its key stays in the space
    // the deletion freed (no secure_delete then), where only rebuilding the file reaches.
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        let mut conn = state.db.acquire().await.unwrap();
        sqlx::query("PRAGMA secure_delete = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        let removed = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO emergency_access (id, grantor_id, grantee_id, status, wait_days, sealed_key, created_at, updated_at)
             VALUES ($1, $2, $3, 'approved', 7, $4, 1, 1)",
        )
        .bind(&removed)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(V1_REMOVED_KEY)
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("DELETE FROM emergency_access WHERE id = $1")
            .bind(&removed)
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    drop(app);
    state.db.close().await;
    drop(state);

    let state = App::new(config).await.unwrap();
    let app = crate::router(state.clone());
    let mine = ea_ok(&app, &ta, Method::GET, "", json!(null)).await;
    let by_id = |id: &str| {
        mine["as_grantor"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["id"] == id)
            .unwrap()
            .clone()
    };
    let reset = by_id(&to_bob);
    assert_eq!(
        (
            &reset["status"],
            &reset["reconfirm"],
            &reset["grantor_key"],
            &reset["requested_at"],
            &reset["approved_at"],
            &reset["key_version"]
        ),
        (
            &json!("accepted"),
            &json!(true),
            &Value::Null,
            &Value::Null,
            &Value::Null,
            &json!(2)
        )
    );
    assert_eq!(reset["missing_vaults"], json!([alice.vault_id]));
    // Bob may keep the account key he had: said for good, also once confirmed again.
    assert_eq!(reset["v1_exposed"], true);
    assert_eq!(
        (
            &by_id(&to_carol)["status"],
            &by_id(&to_carol)["reconfirm"],
            &by_id(&to_carol)["v1_exposed"]
        ),
        (&json!("accepted"), &json!(false), &json!(false))
    );
    assert_eq!(
        (
            &by_id(&to_dave)["status"],
            &by_id(&to_dave)["reconfirm"],
            &by_id(&to_dave)["v1_exposed"]
        ),
        (&json!("invited"), &json!(false), &json!(false))
    );
    // The roster starts empty.
    assert_eq!(
        (&mine["roster"], &mine["roster_seq"]),
        (&Value::Null, &json!(0))
    );
    let theirs = &ea_ok(&app, &tb, Method::GET, "", json!(null)).await["as_grantor"][0];
    assert_eq!(
        (
            &theirs["id"],
            &theirs["status"],
            &theirs["reconfirm"],
            &theirs["v1_exposed"]
        ),
        (&json!(bobs), &json!("accepted"), &json!(true), &json!(true))
    );
    let sealed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM emergency_access WHERE sealed_key IS NOT NULL")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(sealed, 0);
    // The server did it: one event for each side of each access, by nobody.
    let events = stored_events(&state).await;
    let reconfirm = of_type(&events, "emergency.reconfirm");
    assert_eq!(reconfirm.len(), 4);
    assert!(reconfirm.iter().all(|e| e["actor_id"].is_null()));
    let seen: BTreeSet<(String, String, String)> = reconfirm
        .iter()
        .map(|e| {
            (
                e["data"]["grant"].as_str().unwrap().to_owned(),
                e["data"]["status"].as_str().unwrap().to_owned(),
                e["target_user_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        BTreeSet::from([
            (to_bob.clone(), "approved".into(), alice_id.clone()),
            (to_bob.clone(), "approved".into(), bob_id.clone()),
            (bobs.clone(), "confirmed".into(), alice_id.clone()),
            (bobs.clone(), "confirmed".into(), bob_id.clone()),
        ])
    );
    // Bob has no access now; Alice confirms him again with an emergency key.
    assert_eq!(
        ea(
            &app,
            &tb,
            Method::GET,
            &format!("/{to_bob}/vault"),
            json!(null)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let pk = reset["grantee"]["public_key"].as_str().unwrap();
    let own = (alice.vault_id.as_str(), &alice.vault_key);
    let (body, _) = confirm_body(&alice, pk, &to_bob, &[own]);
    let g = ea_ok(&app, &ta, Method::POST, &format!("/{to_bob}/confirm"), body).await;
    assert_eq!(g["status"], "confirmed");
    let listed = as_grantor(&app, &ta, &to_bob).await;
    assert_eq!(
        (&listed["reconfirm"], &listed["v1_exposed"]),
        (&json!(false), &json!(true))
    );
    // SQLite overwrote the cleared keys and rebuilt the file (VACUUM), then emptied the
    // write-ahead log: neither the cleared keys nor the one freed before are left.
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        for file in ["passauth.db", "passauth.db-wal"] {
            let bytes = std::fs::read(dir.join(file)).unwrap_or_default();
            for key in [V1_KEY, V1_REMOVED_KEY] {
                assert!(
                    !bytes.windows(key.len()).any(|w| w == key.as_bytes()),
                    "{file} still holds a v1 key"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sharing_a_vault_without_wraps_asks_for_no_new_key() {
    let app = app().await;
    let alice = register(&app, "nw-a@example.com", "pw-alice-123").await;
    register(&app, "nw-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "nw-a@example.com", "pw-alice-123").await;
    let (s, v) = share(&app, &alice, &ta, "nw-b@example.com", "read").await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("rotation_pending").is_none(), "{v}");
}

#[tokio::test]
async fn the_roster_changes_by_compare_and_swap_only() {
    let (app, state) = app_with_state().await;
    register(&app, "ro-a@example.com", "pw-alice-123").await;
    register(&app, "ro-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "ro-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "ro-b@example.com", "pw-bobby-123").await;
    let list = ea_ok(&app, &ta, Method::GET, "", json!(null)).await;
    assert_eq!(
        (&list["roster"], &list["roster_seq"]),
        (&Value::Null, &json!(0))
    );
    let put = |token: &str, roster: &str, seq: i64| {
        let (app, token, roster) = (app.clone(), token.to_owned(), roster.to_owned());
        async move {
            ea(
                &app,
                &token,
                Method::PUT,
                "/roster",
                json!({ "roster": roster, "seq": seq }),
            )
            .await
        }
    };
    // Only the next number stores it.
    for seq in [0, 2, -1] {
        let (s, v) = put(&ta, "AQID", seq).await;
        assert_eq!(
            (s, &v["error"]),
            (StatusCode::CONFLICT, &json!("roster_changed")),
            "{seq}"
        );
    }
    let (s, v) = put(&ta, "AQID", 1).await;
    assert_eq!((s, &v["roster_seq"]), (StatusCode::OK, &json!(1)));
    // Another app that read 0 too is refused; one that read 1 goes on.
    let (s, v) = put(&ta, "BAUG", 1).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("roster_changed"))
    );
    assert_eq!(put(&ta, "BAUG", 2).await.0, StatusCode::OK);
    let list = ea_ok(&app, &ta, Method::GET, "", json!(null)).await;
    assert_eq!(
        (&list["roster"], &list["roster_seq"]),
        (&json!("BAUG"), &json!(2))
    );
    // Opaque, but base64url and bounded.
    for bad in ["", "not base64!", &"A".repeat(48 * 1024 + 1)] {
        assert_eq!(put(&ta, bad, 3).await.0, StatusCode::BAD_REQUEST);
    }
    // Each account has its own; nobody else's appears.
    assert_eq!(put(&tb, "BwgJ", 1).await.0, StatusCode::OK);
    let theirs = ea_ok(&app, &tb, Method::GET, "", json!(null)).await;
    assert_eq!(
        (&theirs["roster"], &theirs["roster_seq"]),
        (&json!("BwgJ"), &json!(1))
    );
    assert_eq!(
        ea_ok(&app, &ta, Method::GET, "", json!(null)).await["roster"],
        "BAUG"
    );
    // Taking someone off it works while emergency access is turned off.
    assert_eq!(
        admin_set(&app, json!({ "emergency_access": false }))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(put(&ta, "CgsM", 3).await.0, StatusCode::OK);
    let stored: (String, i64) =
        sqlx::query_as("SELECT emergency_roster, emergency_roster_seq FROM users WHERE email = $1")
            .bind("ro-a@example.com")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(stored, ("CgsM".to_owned(), 3));
}

#[tokio::test]
async fn approving_and_shortening_the_wait_need_the_master_password() {
    let app = app().await;
    let alice = register(&app, "ra-a@example.com", "pw-alice-123").await;
    register(&app, "ra-b@example.com", "pw-bobby-123").await;
    register(&app, "ra-c@example.com", "pw-carol-123").await;
    let ta = token(&app, "ra-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "ra-b@example.com", "pw-bobby-123").await;
    let tc = token(&app, "ra-c@example.com", "pw-carol-123").await;
    let to_bob = confirmed(&app, &alice, &ta, "ra-b@example.com", &tb).await;
    let to_carol = confirmed(&app, &alice, &ta, "ra-c@example.com", &tc).await;
    for (id, t) in [(&to_bob, &tb), (&to_carol, &tc)] {
        ea_ok(
            &app,
            t,
            Method::POST,
            &format!("/{id}/request"),
            json!(null),
        )
        .await;
    }
    let with_token = |path: String, method: Method, reauth: Option<String>, body: Value| {
        let (app, ta) = (app.clone(), ta.clone());
        async move {
            let headers: Vec<(&str, &str)> = match &reauth {
                Some(r) => vec![("x-reauth-token", r.as_str())],
                None => vec![],
            };
            call_with(&app, method, &path, Some(&ta), &headers, body).await
        }
    };
    let approve_path = |id: &str| format!("/api/emergency-access/{id}/approve");
    // Approving: no token, or someone else's, is refused and changes nothing.
    let (s, v) = with_token(approve_path(&to_bob), Method::POST, None, json!(null)).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    let bobs = reauth_token(&app, "ra-b@example.com", "pw-bobby-123", &tb).await;
    let (s, _) = with_token(approve_path(&to_bob), Method::POST, Some(bobs), json!(null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(as_grantor(&app, &ta, &to_bob).await["status"], "requested");
    // Hers works, once.
    let reauth = reauth_token(&app, "ra-a@example.com", "pw-alice-123", &ta).await;
    let (s, v) = with_token(
        approve_path(&to_bob),
        Method::POST,
        Some(reauth.clone()),
        json!(null),
    )
    .await;
    assert_eq!((s, &v["status"]), (StatusCode::OK, &json!("approved")));
    let (s, v) = with_token(
        approve_path(&to_carol),
        Method::POST,
        Some(reauth),
        json!(null),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    assert_eq!(
        as_grantor(&app, &ta, &to_carol).await["status"],
        "requested"
    );

    // The waiting period: longer or the same needs nothing, shorter needs the token.
    let wait = |days: i64| json!({ "wait_days": days });
    let path = format!("/api/emergency-access/{to_carol}");
    for days in [7, 10] {
        let (s, v) = with_token(path.clone(), Method::PUT, None, wait(days)).await;
        assert_eq!((s, &v["wait_days"]), (StatusCode::OK, &json!(days)));
    }
    let (s, v) = with_token(path.clone(), Method::PUT, None, wait(2)).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    assert_eq!(as_grantor(&app, &ta, &to_carol).await["wait_days"], 10);
    let reauth = reauth_token(&app, "ra-a@example.com", "pw-alice-123", &ta).await;
    let (s, v) = with_token(path.clone(), Method::PUT, Some(reauth.clone()), wait(2)).await;
    assert_eq!((s, &v["wait_days"]), (StatusCode::OK, &json!(2)));
    // Used up.
    let (s, _) = with_token(path, Method::PUT, Some(reauth), wait(1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

/// Migration 13's cleanup of the SQLite files (`VACUUM`, then emptying the write-ahead
/// log) never stops the server: when it fails, or the disk lacks room for a copy of
/// the database plus the reserve, it stays pending and runs at a later start.
#[tokio::test]
async fn the_database_cleanup_never_stops_the_server_and_waits_until_it_can_run() {
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_ok() {
        return; // SQLite only
    }
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let pending = |db: crate::db::Db| async move {
        crate::db::setting(&db, crate::db::SCRUB_PENDING)
            .await
            .unwrap()
            .is_some()
    };
    // A new database ran migration 13 and its cleanup at once.
    let state = App::new(config.clone()).await.unwrap();
    assert!(!pending(state.db.clone()).await);
    // A cleanup that fails doesn't stop the start, and stays pending.
    crate::db::set_setting(&state.db, crate::db::SCRUB_PENDING, "1")
        .await
        .unwrap();
    crate::db::set_setting(&state.db, "test_fail_vacuum", "1")
        .await
        .unwrap();
    state.db.close().await;
    drop(state);
    let state = App::new(config.clone()).await.unwrap();
    assert!(pending(state.db.clone()).await);
    // Not enough free disk for a copy of the database plus the reserve: skipped, still pending.
    crate::db::delete_setting(&state.db, "test_fail_vacuum")
        .await
        .unwrap();
    state.disk.pretend_free(Some(1024));
    crate::db::scrub_if_pending(&state).await;
    assert!(pending(state.db.clone()).await);
    // With room, it runs and is done.
    state.disk.pretend_free(Some(1 << 50));
    crate::db::scrub_if_pending(&state).await;
    assert!(!pending(state.db.clone()).await);
    state.db.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}
