//! Emergency access: every step and who may take it, the waiting period and the
//! sweeper, the admin switch, what the vault view returns and never returns,
//! attachments, and accounts that are disabled or deleted.

use std::collections::BTreeSet;

use passauth_core::crypto::{KeyPair, seal_to};
use passauth_core::keys::UnlockedAccount;

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

/// The grantor's app seals its account key to the contact's public key. (The
/// associated data is this test's own; the apps' scheme belongs to the core.)
fn seal_account_key(grantor: &Client, contact_public_key: &str, grant: &str) -> String {
    let pk: [u8; 32] = unb64(contact_public_key).unwrap().try_into().unwrap();
    b64(&seal_to(
        &pk,
        grantor.unlocked.account_key.as_bytes(),
        grant.as_bytes(),
    )
    .unwrap())
}

/// The contact's app opens it: the grantor's account key, able to open their vault keys.
fn open_account_key(
    contact: &Client,
    grantor_id: &str,
    sealed: &str,
    grant: &str,
) -> UnlockedAccount {
    let raw = contact
        .unlocked
        .keypair
        .open(&unb64(sealed).unwrap(), grant.as_bytes())
        .unwrap();
    UnlockedAccount {
        account_id: grantor_id.to_owned(),
        account_key: SymmetricKey::from_slice(&raw).unwrap(),
        keypair: KeyPair::generate().unwrap(),
    }
}

/// The grantor names the contact (7 days), the contact accepts, the grantor
/// confirms: the access's id.
async fn confirmed(
    app: &Router,
    grantor: &Client,
    tg: &str,
    contact_email: &str,
    tc: &str,
) -> String {
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
    let sealed = seal_account_key(grantor, g["grantee"]["public_key"].as_str().unwrap(), &id);
    let g = ea_ok(
        app,
        tg,
        Method::POST,
        &format!("/{id}/confirm"),
        json!({ "sealed_key": sealed }),
    )
    .await;
    assert_eq!(g["status"], "confirmed");
    id
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
    assert_eq!(others, json!({ "as_grantor": [], "as_grantee": [] }));
    let any_key = seal_account_key(
        &alice,
        theirs["as_grantee"][0]["grantee"]["public_key"]
            .as_str()
            .unwrap(),
        &id,
    );
    let steps = [
        (Method::POST, "/accept", json!(null)),
        (Method::POST, "/confirm", json!({ "sealed_key": any_key })),
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
    for (method, step, body) in &steps[1..6] {
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
        json!({ "sealed_key": any_key }),
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
    let (s, _) = ea(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/confirm"),
        json!({ "sealed_key": "not base64!" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let sealed = seal_account_key(
        &alice,
        theirs["as_grantee"][0]["grantee"]["public_key"]
            .as_str()
            .unwrap(),
        &id,
    );
    for _ in 0..2 {
        let g = ea_ok(
            &app,
            &ta,
            Method::POST,
            &format!("/{id}/confirm"),
            json!({ "sealed_key": sealed }),
        )
        .await;
        assert_eq!(g["status"], "confirmed");
    }
    let other = seal_account_key(
        &alice,
        theirs["as_grantee"][0]["grantee"]["public_key"]
            .as_str()
            .unwrap(),
        &id,
    );
    let (s, _) = ea(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/confirm"),
        json!({ "sealed_key": other }),
    )
    .await;
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

    let g = ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/approve"),
        json!(null),
    )
    .await;
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
        BTreeSet::from(["grant", "items", "sealed_key", "vaults"])
    );
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
            BTreeSet::from(["id", "key_epoch", "meta", "wrapped_key"])
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
    for other in [&shared, &in_shared, &carol.vault_id, &carols] {
        assert!(!text.contains(other.as_str()), "{other}");
    }
    // Bob's app opens it all with the sealed key; the server never could.
    let alices = open_account_key(&bob, &alice_id, view["sealed_key"].as_str().unwrap(), &id);
    let row = items.iter().find(|i| i["id"] == personal).unwrap();
    let wrapped = vaults.iter().find(|v| v["id"] == alice.vault_id).unwrap()["wrapped_key"]
        .as_str()
        .unwrap();
    let vault_key = alices.open_vault_key(&alice.vault_id, wrapped).unwrap();
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

    // Both logs tell the story; the contact never sees Alice's addresses.
    let expected: BTreeSet<String> = [
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
    for t in [&ta, &tb] {
        let events = all_pages(&app, t, "/api/account/events", 200).await;
        assert_eq!(types(&events), expected);
    }
    let stored = stored_events(&state).await;
    let viewed = of_type(&stored, "emergency.viewed");
    assert_eq!(
        viewed[0]["data"],
        json!({ "grant": id, "vaults": 2, "items": 3 })
    );
    assert_eq!(viewed[0]["target_user_id"], alice_id);

    // Either side removes it; then it's gone for both.
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
        json!({ "grant": id, "status": "rejected", "by": "grantee" })
    );
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
    ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{to_bob}/approve"),
        json!(null),
    )
    .await;
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

    // Deleting the contact's account removes their access…
    let to_carol = confirmed(&app, &alice, &ta, "d-c@example.com", &tc).await;
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
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM emergency_access")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
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
    ea_ok(
        &app,
        &ta,
        Method::POST,
        &format!("/{id}/approve"),
        json!(null),
    )
    .await;

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
