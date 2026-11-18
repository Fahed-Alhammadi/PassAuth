//! Security round items 7–9: the account-wraps v2 compatibility hint in `/sync`, epoch
//! semantics for v2 account wraps (new vault, key replacement), Send v2's
//! `owner_content_key` (migration 16), and item edit counters through the API.

use super::*;
use crate::auth::reads_bound_wraps;

#[test]
fn bound_wrap_readers_are_known_apps_at_their_first_release() {
    for yes in [
        "web/0.12.0",
        "web/0.13.1",
        "desktop/0.9.0",
        "desktop/1.0",
        "macos-autofill/0.10.0",
        "extension/0.8.0",
        "extension/0.10.2",
        "ios/0.8.0",
        "ios/0.10.0",
        "android/0.8.0",
        "android/0.10.0-debug",
        "android/0.9.1+5",
        "ios/1",
    ] {
        assert!(reads_bound_wraps(Some(yes)), "{yes}");
    }
    for no in [
        "web/0.11.0",
        "web/unknown",
        "desktop/0.8.1",
        "macos-autofill/0.8.9",
        "extension/0.7.1",
        "ios/0.7.0",
        "ios/0",
        "android/0.7.9",
        "chrome/9.9.9",
        "ios-autofill/9.9.9",
        "cli/1.0.0",
        "ios",
        "ios/",
        "ios/0.8.0.1",
        "ios/0..8",
        "ios/v0.8.0",
        "ios/0.8.x",
        "ios/-1",
        "",
    ] {
        assert!(!reads_bound_wraps(Some(no)), "{no}");
    }
    assert!(!reads_bound_wraps(None));
}

async fn wraps_v2(app: &Router, token: &str) -> Value {
    synced(app, token).await["user"]["account_wraps_v2"].clone()
}

pub(super) async fn session_as(
    app: &Router,
    email: &str,
    pw: &str,
    client: Option<&str>,
) -> String {
    let headers: Vec<(&str, &str)> = client
        .map(|c| vec![("x-passauth-client", c)])
        .unwrap_or_default();
    let (s, v) = login_with(app, email, pw, &uuid::Uuid::new_v4().to_string(), &headers).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["access_token"].as_str().unwrap().to_owned()
}

pub(super) async fn expire_sessions_of(state: &AppState, client: Option<&str>) {
    let q = match client {
        Some(_) => "UPDATE sessions SET refresh_expires = 0, access_expires = 0 WHERE client = $1",
        None => "UPDATE sessions SET refresh_expires = 0, access_expires = 0 WHERE client IS NULL",
    };
    sqlx::query(q)
        .bind(client.unwrap_or_default())
        .execute(&state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn account_wraps_v2_only_while_every_signed_in_app_reads_them() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("wraps@example.com", "pw-wraps-123");
    register(&app, email, pw).await;
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    let features = config["features"].as_array().unwrap();
    assert!(features.contains(&json!("account_wraps_v2")), "{config}");
    assert!(features.contains(&json!("send_v2")), "{config}");

    let ios = session_as(&app, email, pw, Some("ios/0.10.0")).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(true));
    let web = session_as(&app, email, pw, Some("web/0.13.1")).await;
    assert_eq!(wraps_v2(&app, &web).await, json!(true));
    // An extension from before signed in: every app of the account hears "no".
    session_as(&app, email, pw, Some("extension/0.7.1")).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(false));
    assert_eq!(wraps_v2(&app, &web).await, json!(false));
    // Its session ended: yes again.
    expire_sessions_of(&state, Some("extension/0.7.1")).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(true));
    // An app that never said which it is (before API 2) counts as one that doesn't.
    session_as(&app, email, pw, None).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(false));
    expire_sessions_of(&state, None).await;
    // Unknown names too.
    session_as(&app, email, pw, Some("cli/9.9.9")).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(false));
    expire_sessions_of(&state, Some("cli/9.9.9")).await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(true));
    // Another account's sessions don't count.
    register(&app, "wraps-other@example.com", "pw-wraps-456").await;
    session_as(
        &app,
        "wraps-other@example.com",
        "pw-wraps-456",
        Some("ios/0.7.0"),
    )
    .await;
    assert_eq!(wraps_v2(&app, &ios).await, json!(true));
}

/// What apps write when the hint is on: a new vault's wrap is bound to epoch 0, a key
/// replacement's to the vault's `key_epoch` + 1 (the epoch the server gives it).
#[tokio::test]
async fn v2_wraps_are_bound_to_the_epoch_after_the_write() {
    let app = app().await;
    let c = register(&app, "bound@example.com", "pw-bound-123").await;
    let t = session_as(
        &app,
        "bound@example.com",
        "pw-bound-123",
        Some("ios/0.10.0"),
    )
    .await;
    let id = uuid::Uuid::new_v4().to_string();
    let (key, wrapped) = c.unlocked.new_vault_key_bound(&id, 0).unwrap();
    let meta = b64(&key.encrypt(br#"{"name":"Bound"}"#, b"meta").unwrap());
    ok(
        &app,
        Method::POST,
        "/api/vaults",
        &t,
        json!({ "id": id, "meta": meta, "wrapped_key": wrapped }),
    )
    .await;
    let sync = synced(&app, &t).await;
    let row = vault_in(&sync, &id).unwrap();
    let epoch = row["key_epoch"].as_u64().unwrap();
    assert_eq!(epoch, 0);
    let served = row["wrapped_key"].as_str().unwrap();
    assert!(passauth_core::keys::wrap_is_bound(served));
    let opened = c
        .unlocked
        .open_vault_key(&id, epoch, served, false)
        .unwrap();
    assert_eq!(opened.as_bytes(), key.as_bytes());

    // A key replacement: wrapped for row.key_epoch + 1.
    let (item_id, body) = new_item((&id, &key), "x");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let me = user_id(&app, &t).await;
    let new_key = SymmetricKey::generate().unwrap();
    let new_wrap = c
        .unlocked
        .wrap_vault_key_bound(&new_key, &id, epoch + 1)
        .unwrap();
    let current = synced(&app, &t).await;
    let stored = item_in(&current, &item_id).unwrap();
    let plain = EncryptedItem {
        id: item_id.clone(),
        vault_id: id.clone(),
        key: stored["item_key"].as_str().unwrap().into(),
        data: stored["data"].as_str().unwrap().into(),
    }
    .decrypt(&key)
    .unwrap();
    // Re-encrypted with a new item key (the decrypted item, so its counter + 1).
    let item = EncryptedItem::encrypt(&plain, &item_id, &id, &new_key).unwrap();
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{id}/rotate"),
        &t,
        json!({
            "key_epoch": epoch,
            "keys": [{ "user_id": me, "wrapped_key": new_wrap, "key_kind": "account" }],
            "items": [{ "id": item_id, "vault_id": id, "key": item.key, "data": item.data }],
        }),
    )
    .await;
    let sync = synced(&app, &t).await;
    let row = vault_in(&sync, &id).unwrap();
    let epoch = row["key_epoch"].as_u64().unwrap();
    assert_eq!(epoch, 1);
    let served = row["wrapped_key"].as_str().unwrap();
    let opened = c
        .unlocked
        .open_vault_key(&id, epoch, served, false)
        .unwrap();
    assert_eq!(opened.as_bytes(), new_key.as_bytes());
    // The re-encrypted item counted up (a new item is 1, its re-encryption 2).
    let enc = item_in(&sync, &item_id).unwrap();
    let back = EncryptedItem {
        id: item_id.clone(),
        vault_id: id.clone(),
        key: enc["item_key"].as_str().unwrap().into(),
        data: enc["data"].as_str().unwrap().into(),
    }
    .decrypt(&new_key)
    .unwrap();
    assert_eq!(back.rev, 2);
}

/// Item edit counters ride inside the ciphertext: the server stores and returns them
/// untouched; an older copy served later is what `item_rev_check` flags.
#[tokio::test]
async fn item_edit_counters_go_through_the_server_and_expose_rollbacks() {
    let app = app().await;
    let c = register(&app, "rev@example.com", "pw-rev-1234").await;
    let t = token(&app, "rev@example.com", "pw-rev-1234").await;
    let v = (c.vault_id.as_str(), &c.vault_key);
    let (id, body) = new_item(v, "first");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let stored = |sync: &Value| -> (EncryptedItem, i64) {
        let i = item_in(sync, &id).unwrap();
        (
            EncryptedItem {
                id: id.clone(),
                vault_id: c.vault_id.clone(),
                key: i["item_key"].as_str().unwrap().into(),
                data: i["data"].as_str().unwrap().into(),
            },
            i["revision"].as_i64().unwrap(),
        )
    };
    let (old, revision) = stored(&synced(&app, &t).await);
    let mut item = old.decrypt(&c.vault_key).unwrap();
    assert_eq!(item.rev, 1);
    item.name = "second".into();
    let upd = old.update(&item, &c.vault_key).unwrap();
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{id}"),
        &t,
        json!({ "id": id, "vault_id": c.vault_id, "key": upd.key, "data": upd.data, "revision": revision }),
    )
    .await;
    let (now, _) = stored(&synced(&app, &t).await);
    let served = now.decrypt(&c.vault_key).unwrap();
    assert_eq!((served.rev, served.name.as_str()), (2, "second"));
    let remembered = Some(served.rev);
    // A server serving the first ciphertext again: authentic, but older.
    let replayed = old.decrypt(&c.vault_key).unwrap();
    assert_eq!(
        passauth_core::item::item_rev_check(remembered, replayed.rev),
        passauth_core::item::RevCheck::Rollback
    );
}

#[tokio::test]
async fn send_v2_keeps_the_owner_content_key_with_the_password() {
    let app = app().await;
    register(&app, "send-v2@example.com", "pw-send-v2-1").await;
    let t = token(&app, "send-v2@example.com", "pw-send-v2-1").await;
    let ock = b64(b"wrapped content key");
    let pw = json!({ "access_salt": "c2FsdHNhbHRzYWx0", "access_verifier": "verifier-one-1" });

    // Without a password there is nothing to wrap.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/sends",
        Some(&t),
        send_with(json!({ "owner_content_key": ock })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // Too long.
    let mut long = pw.clone();
    long["owner_content_key"] = json!("x".repeat(4097));
    let (s, _) = call(&app, Method::POST, "/api/sends", Some(&t), send_with(long)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A v1 Send (no content key) lists it as null.
    let plain = new_send(&app, &t, json!({})).await;
    assert_eq!(plain["owner_content_key"], json!(null), "{plain}");

    // A v2 Send: kept, listed and read back for the owner, counted in its size.
    let mut body = pw.clone();
    body["owner_content_key"] = json!(ock);
    let s2 = new_send(&app, &t, body).await;
    let id = s2["id"].as_str().unwrap().to_owned();
    assert_eq!(s2["owner_content_key"], json!(ock));
    assert_eq!(
        s2["size"].as_u64().unwrap(),
        (b64(b"encrypted name").len()
            + b64(b"encrypted text").len()
            + b64(b"wrapped send key").len()
            + ock.len()) as u64
    );
    assert_eq!(
        my_send(&app, &t, &id).await["owner_content_key"],
        json!(ock)
    );
    let (_, list) = call(&app, Method::GET, "/api/sends", Some(&t), json!(null)).await;
    let listed = list["sends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == id)
        .unwrap();
    assert_eq!(listed["owner_content_key"], json!(ock));
    // Never to visitors.
    let ip = "198.51.100.90";
    let (_, info) = send_info(&app, ip, &id).await;
    assert!(info.get("owner_content_key").is_none(), "{info}");
    let (s, opened) = open_send(&app, ip, &id, Some("verifier-one-1")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(opened.get("owner_content_key").is_none(), "{opened}");

    // Other changes keep it (also the owner view sent back unchanged).
    let (s, v) = change_send(&app, &t, &id, json!({ "max_views": 5 })).await;
    assert_eq!((s, &v["owner_content_key"]), (StatusCode::OK, &json!(ock)));
    let (s, v) = change_send(&app, &t, &id, my_send(&app, &t, &id).await).await;
    assert_eq!((s, &v["owner_content_key"]), (StatusCode::OK, &json!(ock)));

    // A new password, or none, without the re-encrypted text and key: refused (an app
    // from before would leave the text under a password visitors no longer have).
    for change in [
        json!({ "access_salt": "bmV3c2FsdG5ld3NhbHQ", "access_verifier": "verifier-two-2" }),
        json!({ "access_salt": "bmV3c2FsdG5ld3NhbHQ", "access_verifier": "verifier-two-2", "owner_content_key": ock }),
        json!({ "access_verifier": null }),
        json!({ "access_verifier": null, "name": b64(b"n"), "data": b64(b"d") }),
    ] {
        let (s, v) = change_send(&app, &t, &id, change.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{change}: {v}");
    }
    assert_eq!(my_send(&app, &t, &id).await["has_password"], true);
    // A new password with everything re-encrypted.
    let ock2 = b64(b"wrapped content key two");
    let (s, v) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_salt": "bmV3c2FsdG5ld3NhbHQ", "access_verifier": "verifier-two-2",
                "name": b64(b"name two"), "data": b64(b"data two"), "owner_content_key": ock2 }),
    )
    .await;
    assert_eq!(
        (s, &v["owner_content_key"]),
        (StatusCode::OK, &json!(ock2)),
        "{v}"
    );
    assert_eq!(
        open_send(&app, "198.51.100.91", &id, Some("verifier-two-2"))
            .await
            .1["data"],
        json!(b64(b"data two"))
    );
    // A content key without a password is refused on change too.
    let pid = plain["id"].as_str().unwrap();
    let (s, _) = change_send(&app, &t, pid, json!({ "owner_content_key": ock })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Back to the link key alone: the text re-encrypted, the content key cleared.
    let (s, v) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_verifier": null, "name": b64(b"name three"), "data": b64(b"data three"),
                "owner_content_key": null }),
    )
    .await;
    assert_eq!(
        (s, &v["owner_content_key"], &v["has_password"]),
        (StatusCode::OK, &json!(null), &json!(false)),
        "{v}"
    );
    // A v1 Send with a password (from before) changes its password as it always did.
    let old = new_send(&app, &t, pw.clone()).await;
    let oid = old["id"].as_str().unwrap();
    let (s, v) = change_send(
        &app,
        &t,
        oid,
        json!({ "access_salt": "bmV3c2FsdG5ld3NhbHQ", "access_verifier": "verifier-two-2" }),
    )
    .await;
    assert_eq!(
        (s, &v["owner_content_key"]),
        (StatusCode::OK, &json!(null)),
        "{v}"
    );
    // …and removing it clears nothing it didn't have.
    let (s, _) = change_send(&app, &t, oid, json!({ "access_verifier": null })).await;
    assert_eq!(s, StatusCode::OK);
    // Upgrading a password Send to v2 in place (same password, text re-encrypted).
    let (s, v) = change_send(
        &app,
        &t,
        oid,
        json!({ "access_salt": "c2FsdHNhbHRzYWx0", "access_verifier": "verifier-one-1",
                "name": b64(b"n4"), "data": b64(b"d4"), "owner_content_key": ock }),
    )
    .await;
    assert_eq!(
        (s, &v["owner_content_key"]),
        (StatusCode::OK, &json!(ock)),
        "{v}"
    );
}
