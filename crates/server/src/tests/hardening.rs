//! Fixes from the server security review: floods that would reset per-target rate
//! limits, vault ids used again after deletion, the free-disk reserve, who pays for
//! and uploads an attachment, failed sign-ins answered before they are logged, the
//! master password for two-step changes, open sockets and the two-step policy,
//! quotas under concurrent writes, addresses of deleted accounts, housekeeping that
//! panics and admin invitations.

use std::time::Duration;

use super::attachments::{files_app, item_in_vault, pending, storage, upload};
use super::*;
use crate::state::Class;

const MB: u64 = 1024 * 1024;

/// `POST /api/auth/login/start` for `email` from `ip` (an unparsable message: the
/// limits apply before it is read, then it is a 400).
async fn login_start_from(app: &Router, ip: &str, email: &str) -> StatusCode {
    call_from(
        app,
        ip,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": "AAAA" }),
    )
    .await
    .0
}

/// The reviewer's two floods (an account asking for emergency accesses that don't
/// exist from one address; public Send requests from many IPv6 /64s of one /48),
/// against a small address map: neither resets a Send's wrong-password count nor
/// the per-email sign-in ceiling, and the map stays bounded.
#[tokio::test]
async fn floods_never_reset_per_target_limits() {
    let (app, state) = app_with_state().await;
    state.limiter.set_capacity(300);
    register(&app, "fl-a@example.com", "pw-alice-123").await;
    let ta = token(&app, "fl-a@example.com", "pw-alice-123").await;
    let send = new_send(
        &app,
        &ta,
        json!({ "access_salt": "sendpw-v1$salt-salt", "access_verifier": "right-verifier-1" }),
    )
    .await;
    let id = send["id"].as_str().unwrap().to_owned();
    for i in 0..100u32 {
        let ip = format!("10.9.{}.{}", i / 250, i % 250 + 1);
        let (s, v) = open_send(&app, &ip, &id, Some("wrong-verifier")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    }
    let locked = |app: Router, id: String, ip: &'static str| async move {
        for verifier in ["wrong-verifier", "right-verifier-1"] {
            let (s, v) = open_send(&app, ip, &id, Some(verifier)).await;
            assert_eq!(
                (s, &v["error"]),
                (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited")),
                "{verifier}"
            );
        }
    };
    locked(app.clone(), id.clone(), "10.9.200.1").await;
    // The per-email sign-in ceiling, used up from a hundred addresses.
    let victim = "fl-victim@example.com";
    register(&app, victim, "pw-victim-123").await;
    for i in 0..100u32 {
        let ip = format!("10.7.{}.{}", i / 250, i % 250 + 1);
        assert_eq!(
            login_start_from(&app, &ip, victim).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        login_start_from(&app, "10.7.200.1", victim).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    let targets = state.limiter.key_count(Class::Target);

    // Flood 1: an account asks for emergency accesses that don't exist. Their ids
    // make no keys at all: the limit counts once the access is known to be theirs.
    for _ in 0..600 {
        let (s, _) = call_from(
            &app,
            "203.0.113.7",
            Method::GET,
            &format!("/api/emergency-access/{}/vault", uuid::Uuid::new_v4()),
            Some(&ta),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    assert_eq!(state.limiter.key_count(Class::Target), targets);
    // Flood 2, no account needed: Sends that don't exist and sign-ins for emails
    // nobody has, each from its own /64 of one /48.
    for n in 0..600u32 {
        let ip = format!("[2001:db8:77:{n:x}::1]");
        let unknown = b64(&uuid::Uuid::new_v4().as_bytes()[..]);
        assert_eq!(
            open_send(&app, &ip, &unknown, None).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            login_start_from(&app, &ip, &format!("flood-{n}@example.com")).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        state.limiter.key_count(Class::Address) <= 300,
        "the address map stays bounded: {}",
        state.limiter.key_count(Class::Address)
    );
    // Still locked: the Send for everyone, the email from any address.
    locked(app.clone(), id.clone(), "10.9.201.1").await;
    assert_eq!(
        login_start_from(&app, "10.7.201.1", victim).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(my_send(&app, &ta, &id).await["views"], 0);
}

/// The Send's count lives in its row: a restart doesn't reset it, a new password does.
#[tokio::test]
async fn a_sends_wrong_password_count_survives_a_restart() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let app = crate::router(App::new(config.clone()).await.unwrap());
    register(&app, "restart@example.com", "pw-restart-12").await;
    let t = token(&app, "restart@example.com", "pw-restart-12").await;
    let send = new_send(
        &app,
        &t,
        json!({ "access_salt": "sendpw-v1$salt-salt", "access_verifier": "right-verifier-1" }),
    )
    .await;
    let id = send["id"].as_str().unwrap().to_owned();
    for i in 0..100u32 {
        let ip = format!("10.6.{}.{}", i / 250, i % 250 + 1);
        assert_eq!(
            open_send(&app, &ip, &id, Some("wrong-verifier")).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    drop(app);
    let app = crate::router(App::new(config).await.unwrap());
    let (s, v) = open_send(&app, "10.6.200.1", &id, Some("right-verifier-1")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    let (s, v) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_salt": "sendpw-v1$new-salt", "access_verifier": "new-verifier-2" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        open_send(&app, "10.6.200.2", &id, Some("new-verifier-2"))
            .await
            .0,
        StatusCode::OK
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reviewer's scenario: Bob, removed from Alice's vault, must not get its
/// activity log by creating a vault with its id once Alice deletes it. Ids of
/// vaults deleted with their owner's account, and of vaults deleted before the
/// migration, are retired too.
#[tokio::test]
async fn a_deleted_vaults_id_is_never_used_again() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "rv-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "rv-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "rv-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "rv-b@example.com", "pw-bobby-123").await;
    let bob_id = user_id(&app, &tb).await;
    let (v, key) = new_vault(&app, &alice, &ta).await;
    let (s, r) = share_vault(&app, (&v, &key), &ta, "rv-b@example.com", "write", None).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    accept(&app, &tb, &v).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v}/members/{bob_id}"),
        &ta,
        json!(null),
    )
    .await;
    let (_, body) = new_item((&v, &key), "after bob left");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v}"),
        &ta,
        json!(null),
    )
    .await;

    let recreate = |c: &Client, token: String, id: String| {
        let (key, wrapped) = c.unlocked.new_vault_key(&id).unwrap();
        let meta = b64(&key.encrypt(br#"{"name":"x"}"#, b"meta").unwrap());
        let app = app.clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/vaults",
                Some(&token),
                json!({ "id": id, "meta": meta, "wrapped_key": wrapped }),
            )
            .await
        }
    };
    let taken = |(s, v): (StatusCode, Value)| {
        assert_eq!(
            (s, &v["error"]),
            (StatusCode::CONFLICT, &json!("vault_exists")),
            "{v}"
        );
    };
    taken(recreate(&bob, tb.clone(), v.clone()).await);
    taken(recreate(&alice, ta.clone(), v.clone()).await);
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/vaults/{v}/events"),
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A vault that went with its owner's account.
    let carol = register(&app, "rv-c@example.com", "pw-carol-123").await;
    let tc = token(&app, "rv-c@example.com", "pw-carol-123").await;
    let reauth = reauth_token(&app, "rv-c@example.com", "pw-carol-123", &tc).await;
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
    taken(recreate(&bob, tb.clone(), carol.vault_id.clone()).await);

    // Vaults deleted before migration 12: it retires every id the database still
    // names, their activity log above all.
    sqlx::query("DELETE FROM vault_ids WHERE id = $1")
        .bind(&v)
        .execute(&state.db)
        .await
        .unwrap();
    sqlx::query(crate::db::RETIRE_KNOWN_VAULT_IDS)
        .execute(&state.db)
        .await
        .unwrap();
    taken(recreate(&bob, tb.clone(), v.clone()).await);
    // A new id still works.
    let (s, r) = recreate(&bob, tb, uuid::Uuid::new_v4().to_string()).await;
    assert_eq!(s, StatusCode::OK, "{r}");
}

/// Down to the reserve, nothing new is stored (507) while reading and deleting go
/// on; a file must fit above the reserve; 0 turns the check off.
#[tokio::test]
async fn the_free_disk_reserve_stops_new_data_but_not_deletes() {
    let (app, state, dir) = files_app().await;
    let c = register(&app, "disk@example.com", "pw-disk-1234").await;
    let t = token(&app, "disk@example.com", "pw-disk-1234").await;
    let mine = (c.vault_id.as_str(), &c.vault_key);
    let (_, settings) = call(
        &app,
        Method::GET,
        "/api/admin/settings",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(
        (
            &settings["min_free_disk_mb"],
            &settings["ranges"]["min_free_disk_mb"],
            &settings["max_attachment_storage_mb_per_user"],
        ),
        (
            &json!(1024),
            &json!({ "min": 0, "max": 1_048_576, "default": 1024 }),
            &json!(1024)
        )
    );

    state.disk.pretend_free(Some(2048 * MB));
    let item = item_in_vault(&app, &t, mine).await;
    let (s, v) = pending(&app, &t, &item, 1000).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let waiting = v["attachment"]["id"].as_str().unwrap().to_owned();

    state.disk.pretend_free(Some(1000 * MB));
    let (_, overview) = call(
        &app,
        Method::GET,
        "/api/admin/overview",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(overview["disk_free_bytes"], json!(1000 * MB));
    let full = |(s, v): (StatusCode, Value)| {
        assert_eq!(
            (s, &v["error"]),
            (
                StatusCode::INSUFFICIENT_STORAGE,
                &json!("insufficient_storage")
            ),
            "{v}"
        );
        assert!(v["message"].as_str().unwrap().contains("disk space"), "{v}");
    };
    let (_, body) = new_item(mine, "more");
    full(call(&app, Method::POST, "/api/items", Some(&t), body.clone()).await);
    full(
        call(
            &app,
            Method::POST,
            "/api/items/import",
            Some(&t),
            json!({ "items": [body] }),
        )
        .await,
    );
    full(
        call(
            &app,
            Method::PUT,
            &format!("/api/items/{item}"),
            Some(&t),
            item_body(&item, mine, "renamed"),
        )
        .await,
    );
    full(call(&app, Method::POST, "/api/sends", Some(&t), send_body(1)).await);
    full(pending(&app, &t, &item, 10).await);
    full(upload(&app, &t, &waiting, &[7u8; 1000]).await);
    // Reading and deleting still work.
    assert_eq!(
        call(&app, Method::GET, "/api/sync", Some(&t), json!(null))
            .await
            .0,
        StatusCode::OK
    );
    ok(
        &app,
        Method::DELETE,
        &format!("/api/attachments/{waiting}"),
        &t,
        json!(null),
    )
    .await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{item}"),
        &t,
        json!(null),
    )
    .await;

    // A file needs room above the reserve: 76 MB left here.
    state.disk.pretend_free(Some(1100 * MB));
    let other = item_in_vault(&app, &t, mine).await;
    full(pending(&app, &t, &other, 100 * MB as usize).await);
    assert_eq!(
        pending(&app, &t, &other, 10 * MB as usize).await.0,
        StatusCode::OK
    );

    // 0: no check.
    assert_eq!(
        admin_set(&app, json!({ "min_free_disk_mb": 0 })).await.0,
        StatusCode::OK
    );
    state.disk.pretend_free(Some(0));
    let (_, body) = new_item(mine, "fits again");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pending upload counts against whoever started it (not the vault's owner) and
/// only they can send its bytes; once ready it is the owner's. The attachment limit
/// per user applies to both.
#[tokio::test]
async fn uploads_belong_to_whoever_started_them_until_they_are_ready() {
    let (app, _state, dir) = files_app().await;
    let alice = register(&app, "up-a@example.com", "pw-alice-123").await;
    register(&app, "up-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "up-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "up-b@example.com", "pw-bobby-123").await;
    assert_eq!(
        share(&app, &alice, &ta, "up-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &tb, &alice.vault_id).await;
    let item = item_in_vault(&app, &ta, (&alice.vault_id, &alice.vault_key)).await;
    let (alice_before, bob_before) = (storage(&app, &ta).await, storage(&app, &tb).await);

    let (s, v) = pending(&app, &tb, &item, 5000).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let bobs = v["attachment"]["id"].as_str().unwrap().to_owned();
    assert_eq!(storage(&app, &ta).await, alice_before);
    assert_eq!(storage(&app, &tb).await, bob_before + 5000);
    // Alice may delete it, but not fill it with other bytes.
    let (s, v) = upload(&app, &ta, &bobs, &[1u8; 5000]).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, v) = upload(&app, &tb, &bobs, &[2u8; 5000]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(storage(&app, &ta).await, alice_before + 5000);
    assert_eq!(storage(&app, &tb).await, bob_before);
    let (_, me) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    assert_eq!(
        (
            &me["usage"]["attachment_bytes"],
            &me["limits"]["max_attachment_bytes"]
        ),
        (&json!(5000), &json!(1024 * MB))
    );

    // The attachment limit: pending uploads of Bob's, ready files in Alice's vault.
    assert_eq!(
        admin_set(&app, json!({ "max_attachment_storage_mb_per_user": 1 }))
            .await
            .0,
        StatusCode::OK
    );
    let kib600 = 600 * 1024;
    assert_eq!(pending(&app, &tb, &item, kib600).await.0, StatusCode::OK);
    let (s, v) = pending(&app, &tb, &item, kib600).await;
    assert_eq!(
        (s, &v["error"], &v["message"]),
        (
            StatusCode::FORBIDDEN,
            &json!("quota_exceeded"),
            &json!("attachment storage limit reached")
        )
    );
    let (s, v) = pending(&app, &ta, &item, MB as usize - 5000 + 1).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("quota_exceeded"))
    );
    assert_eq!(
        pending(&app, &ta, &item, MB as usize - 5000).await.0,
        StatusCode::OK
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wrong password for `email` from `ip`: the answer to `login/finish`, and how
/// long the server took for it (the key derivation on the "device" isn't timed).
async fn timed_failed_finish(app: &Router, ip: &str, email: &str) -> (StatusCode, Duration) {
    let master =
        derive_master_keys("not the password", None, "any account", &fast_kdf(), false).unwrap();
    let start = opaque::login_start(&master.login).unwrap();
    let (s, resp) = call_from(
        app,
        ip,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": start.message }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    let started = std::time::Instant::now();
    let (s, _) = call_from(
        app,
        ip,
        Method::POST,
        "/api/auth/login/finish",
        None,
        json!({
            "login_id": resp["login_id"], "message": b64(b"not a finalization"),
            "device": { "id": "d9", "name": "Test device", "kind": "cli" },
        }),
    )
    .await;
    (s, started.elapsed())
}

/// A failed sign-in answers without writing anything, with or without an account:
/// with the database's write lock held elsewhere it still answers at once, and the
/// failure is counted once the lock is gone.
#[tokio::test]
async fn failed_sign_ins_answer_before_they_are_logged() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config).await.unwrap();
    let app = crate::router(state.clone());
    let email = "timing@example.com";
    register(&app, email, "pw-timing-123").await;
    let mut blocker = state.db.begin().await.unwrap();
    let lock = if crate::db::is_postgres(&state.config.database_url) {
        "LOCK TABLE events IN EXCLUSIVE MODE"
    } else {
        "INSERT INTO server_settings (name, value) VALUES ('test-write-lock', '1')"
    };
    sqlx::query(lock).execute(&mut *blocker).await.unwrap();
    for who in [email, "nobody-here@example.com"] {
        let (s, took) = tokio::time::timeout(
            Duration::from_secs(3),
            timed_failed_finish(&app, "192.0.2.80", who),
        )
        .await
        .expect("answered without waiting for the database");
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{who}");
        assert!(took < Duration::from_secs(2), "{who}: {took:?}");
    }
    drop(blocker);
    let events = stored_events(&state).await;
    let failed = of_type(&events, "auth.signin_failed");
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(
        (&failed[0]["data"], &failed[0]["ip"]),
        (
            &json!({ "reason": "password", "count": 1 }),
            &json!("192.0.2.80")
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Email codes, like the authenticator app, need the master password confirmed;
/// every two-step change is emailed to the account.
#[tokio::test]
async fn two_step_changes_need_the_master_password_and_are_emailed() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("ts-mail@example.com", "pw-two-step-mail");
    register(&app, email, pw).await;
    let t = token(&app, email, pw).await;
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/account/2fa/email/enable",
        Some(&t),
        json!({ "code": "123456" }),
    )
    .await;
    assert_eq!(
        (s, &v["error"], &v["message"]),
        (
            StatusCode::FORBIDDEN,
            &json!("reauth_required"),
            &json!(crate::auth::REAUTH_FIRST)
        )
    );
    enable_totp(&app, email, pw, &t).await;
    let reauth = reauth_token(&app, email, pw, &t).await;
    let (s, _) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/recovery",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let reauth = reauth_token(&app, email, pw, &t).await;
    let (s, _) = call_with(
        &app,
        Method::DELETE,
        "/api/account/2fa/totp",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let mails: Vec<(String, String)> = state
        .mailer
        .outbox
        .lock()
        .unwrap()
        .iter()
        .filter(|(to, ..)| to == email)
        .map(|(_, subject, body)| (subject.clone(), body.clone()))
        .collect();
    let changes: Vec<&str> = mails
        .iter()
        .filter(|(subject, _)| subject == "Two-step login changed on your PassAuth account")
        .map(|(_, body)| body.lines().next().unwrap())
        .collect();
    assert_eq!(
        changes,
        [
            "Two-step login with an authenticator app was turned on.",
            "New recovery codes were created; the old ones no longer work.",
            "Two-step login with an authenticator app was turned off.",
        ]
    );
}

/// Sockets opened before the admin required two-step login are held to it at the
/// next connection check: an account without a method is told and closed.
#[tokio::test]
async fn open_sockets_follow_a_two_step_policy_turned_on_later() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let (app, state) = app_with_state().await;
    register(&app, "ws-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "ws-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "ws-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "ws-b@example.com", "pw-bobby-123").await;
    enable_totp(&app, "ws-b@example.com", "pw-bobby-123", &tb).await;
    state
        .numbers
        .set(crate::settings::Num::WebsocketPingSeconds, 1);
    let addr = serve(state.clone()).await;
    let mut wa = socket(addr, &ta).await;
    let mut wb = socket(addr, &tb).await;
    assert_eq!(
        admin_set(&app, json!({ "require_two_step": true })).await.0,
        StatusCode::OK
    );
    let mut texts = Vec::new();
    let closed = loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), wa.next())
            .await
            .expect("closed within a check");
        match frame {
            Some(Ok(Message::Text(text))) => {
                texts.push(serde_json::from_str::<Value>(text.as_str()).unwrap());
            }
            Some(Ok(Message::Close(frame))) => break frame,
            Some(Ok(_)) => continue,
            other => panic!("unexpected {other:?}"),
        }
    };
    assert_eq!(texts, [json!({ "type": "two_step_required" })]);
    let closed = closed.expect("a close frame with a reason");
    assert_eq!(
        (u16::from(closed.code), closed.reason.as_str()),
        (1008, "two_step_required")
    );
    // Bob, who has a method, stays connected and hears about his changes.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (_, body) = new_item((&bob.vault_id, &bob.vault_key), "still here");
    ok(&app, Method::POST, "/api/items", &tb, body).await;
    let msg = next_message(&mut wb).await.expect("still open");
    assert_eq!(msg["type"], "sync", "{msg}");
}

/// PostgreSQL runs vault writes and Sends of one owner side by side: the owner's row
/// is locked before the quota check, so writes at once can't each pass alone and
/// together go over (SQLite's writers take turns anyway).
#[tokio::test]
async fn writes_at_once_by_one_owner_stay_within_the_quota() {
    let app = app().await;
    let alice = register(&app, "par@example.com", "pw-alice-123").await;
    let t = token(&app, "par@example.com", "pw-alice-123").await;
    let (second, _) = new_vault(&app, &alice, &t).await;
    assert_eq!(
        admin_set(&app, json!({ "max_storage_mb_per_user": 1 }))
            .await
            .0,
        StatusCode::OK
    );
    let big = |vault: &str| {
        json!({
            "id": uuid::Uuid::new_v4().to_string(), "vault_id": vault,
            "key": "a2V5", "data": "A".repeat(600 * 1024),
        })
    };
    let (one, two) = tokio::join!(
        call(
            &app,
            Method::POST,
            "/api/items",
            Some(&t),
            big(&alice.vault_id)
        ),
        call(&app, Method::POST, "/api/items", Some(&t), big(&second)),
    );
    let mut statuses = [one.0, two.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::FORBIDDEN],
        "{} / {}",
        one.1,
        two.1
    );
    // Sends count toward the same quota.
    let send = || {
        let mut body = send_body(1);
        body["data"] = json!("B".repeat(300 * 1024));
        body
    };
    let (one, two) = tokio::join!(
        call(&app, Method::POST, "/api/sends", Some(&t), send()),
        call(&app, Method::POST, "/api/sends", Some(&t), send()),
    );
    let refused = [one.0, two.0]
        .iter()
        .filter(|s| **s == StatusCode::FORBIDDEN)
        .count();
    assert_eq!(refused, 1, "{} / {}", one.1, two.1);
}

/// An account deleted for good leaves its events in the log for `event_days`, but
/// not its addresses; those of others who acted on it stay.
#[tokio::test]
async fn deleting_an_account_erases_its_addresses_from_the_log() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "ip-a@example.com", "pw-alice-123").await;
    let bob = register(&app, "ip-b@example.com", "pw-bobby-123").await;
    let ta = token(&app, "ip-a@example.com", "pw-alice-123").await;
    let tb = token(&app, "ip-b@example.com", "pw-bobby-123").await;
    let bob_id = user_id(&app, &tb).await;
    failed_login_from(&app, "192.0.2.61", "ip-b@example.com").await;
    let (_, body) = new_item((&bob.vault_id, &bob.vault_key), "bob's");
    let (s, _) = call_from(
        &app,
        "192.0.2.62",
        Method::POST,
        "/api/items",
        Some(&tb),
        body,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, found) = call(
        &app,
        Method::GET,
        "/api/users/lookup?email=ip-b@example.com",
        Some(&ta),
        json!(null),
    )
    .await;
    let sealed = share_vault_key(
        &alice.vault_id,
        &alice.vault_key,
        found["public_key"].as_str().unwrap(),
    )
    .unwrap();
    let (s, v) = call_from(
        &app,
        "192.0.2.63",
        Method::POST,
        &format!("/api/vaults/{}/members", alice.vault_id),
        Some(&ta),
        json!({ "user_id": bob_id, "role": "read", "sealed_key": sealed }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call_from(
        &app,
        "10.9.8.7",
        Method::POST,
        &format!("/api/admin/users/{bob_id}/two-factor/reset"),
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    state.failures.flush().await;
    let reauth = reauth_token(&app, "ip-b@example.com", "pw-bobby-123", &tb).await;
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/api/account")
        .header("authorization", format!("Bearer {tb}"))
        .header("x-reauth-token", &reauth)
        .body(Body::empty())
        .unwrap();
    let mut req = req;
    // Bob deletes his account from an address of his own.
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [192, 0, 2, 64],
            40000,
        ))));
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let events = stored_events(&state).await;
    let ip_of = |kind: &str| -> Value {
        events
            .iter()
            .find(|e| e["type"] == kind)
            .unwrap_or_else(|| panic!("{kind}"))["ip"]
            .clone()
    };
    for kind in ["auth.signin_failed", "item.created", "account.deleted"] {
        assert_eq!(ip_of(kind), json!(null), "{kind}");
    }
    assert!(
        events
            .iter()
            .filter(|e| e["actor_id"] == json!(bob_id))
            .all(|e| e["ip"].is_null()),
        "none of Bob's own"
    );
    assert_eq!(
        ip_of("member.invited"),
        json!("192.0.2.63"),
        "Alice's stays"
    );
    assert_eq!(
        ip_of("admin.two_step_reset"),
        json!("10.9.8.7"),
        "the admin page's stays"
    );
}

/// One housekeeping step that panics doesn't stop the sweeper or its other steps.
#[tokio::test]
async fn a_panicking_housekeeping_step_leaves_the_others_running() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let boom = std::hint::black_box(true);
    crate::sweep_step("a step that panics", async move {
        if boom {
            panic!("boom");
        }
        Ok::<_, std::convert::Infallible>(())
    })
    .await;
    let ran = AtomicBool::new(false);
    crate::sweep_step("the next step", async {
        ran.store(true, Ordering::SeqCst);
        Ok::<_, std::convert::Infallible>(())
    })
    .await;
    assert!(ran.load(Ordering::SeqCst));
}

/// Invitations made and withdrawn on the admin page are in the activity log.
#[tokio::test]
async fn admin_invitations_are_logged() {
    let (app, state) = app_with_state().await;
    for (method, path, body) in [
        (
            Method::POST,
            "/api/admin/invites",
            json!({ "email": "New@Example.com" }),
        ),
        (
            Method::DELETE,
            "/api/admin/invites/new@example.com",
            json!(null),
        ),
        (
            Method::DELETE,
            "/api/admin/invites/nobody@example.com",
            json!(null),
        ),
    ] {
        let (s, v) = call_from(&app, "10.9.8.7", method, path, Some("test-admin"), body).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
    }
    let events = stored_events(&state).await;
    for kind in ["admin.invite_created", "admin.invite_deleted"] {
        let found = of_type(&events, kind);
        assert_eq!(found.len(), 1, "{kind}: {found:?}");
        assert_eq!(
            (&found[0]["data"], &found[0]["ip"], &found[0]["actor_id"]),
            (
                &json!({ "email": "new@example.com" }),
                &json!("10.9.8.7"),
                &json!(null)
            ),
            "{kind}"
        );
    }
}

#[test]
fn shown_text_loses_control_and_format_characters() {
    use crate::auth::display_text;
    assert_eq!(
        display_text("  Pay\u{202E}lapyaP\u{200B}\u{2028}\u{7}\u{E0041} ", 100),
        "PaylapyaP"
    );
    assert_eq!(display_text(&"é".repeat(80), 64).chars().count(), 64);
    assert_eq!(display_text("Pixel 9 (Ana's)", 64), "Pixel 9 (Ana's)");
}

/// Upgrading a database from before migration 12: the ids of vaults deleted before
/// it are retired, and Sends get their wrong-password count.
#[tokio::test]
async fn migration_12_retires_the_ids_of_vaults_deleted_before_it() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config.clone()).await.unwrap();
    let app = crate::router(state.clone());
    let alice = register(&app, "mig@example.com", "pw-alice-123").await;
    let t = token(&app, "mig@example.com", "pw-alice-123").await;
    let (gone, _) = new_vault(&app, &alice, &t).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{gone}"),
        &t,
        json!(null),
    )
    .await;
    let send = new_send(
        &app,
        &t,
        json!({ "access_salt": "sendpw-v1$salt-salt", "access_verifier": "right-verifier-1" }),
    )
    .await;
    // Back to the schema of migration 11.
    for stmt in [
        "DROP TABLE vault_ids",
        "DROP INDEX attachments_creator",
        "ALTER TABLE sends DROP COLUMN wrong_passwords",
        "ALTER TABLE sends DROP COLUMN wrong_since",
        "DELETE FROM schema_version WHERE version = 12",
    ] {
        sqlx::query(stmt).execute(&state.db).await.unwrap();
    }
    drop(app);
    state.db.close().await;
    drop(state);

    let app = crate::router(App::new(config).await.unwrap());
    for id in [&gone, &alice.vault_id] {
        let (key, wrapped) = alice.unlocked.new_vault_key(id).unwrap();
        let meta = b64(&key.encrypt(br#"{"name":"x"}"#, b"meta").unwrap());
        let (s, v) = call(
            &app,
            Method::POST,
            "/api/vaults",
            Some(&t),
            json!({ "id": id, "meta": meta, "wrapped_key": wrapped }),
        )
        .await;
        assert_eq!(
            (s, &v["error"]),
            (StatusCode::CONFLICT, &json!("vault_exists")),
            "{id}"
        );
    }
    let id = send["id"].as_str().unwrap();
    assert_eq!(
        open_send(&app, "10.5.0.1", id, Some("wrong-verifier"))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        open_send(&app, "10.5.0.1", id, Some("right-verifier-1"))
            .await
            .0,
        StatusCode::OK
    );
    let _ = std::fs::remove_dir_all(&dir);
}
