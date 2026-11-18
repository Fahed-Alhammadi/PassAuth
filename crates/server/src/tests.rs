//! End-to-end API tests: a real client flow (core crypto + OPAQUE) against
//! the router with an in-memory SQLite database.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passauth_core::crypto::SymmetricKey;
use passauth_core::item::{EncryptedItem, ITEM_FORMAT, Item, Login, b64, unb64};
use passauth_core::kdf::KdfParams;
use passauth_core::keys::{AccountBundle, UnlockedAccount, derive_master_keys, share_vault_key};
use passauth_core::opaque;
use passauth_core::totp::Totp;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::Config;
use crate::state::{App, AppState};

mod attachments;
mod device_login;
mod emergency;
mod hardening;
mod manifest;
mod sec789;
mod signing;

/// Undoes migrations 17 (vault manifests), 16 (Send v2), 15 (profile pictures) and 14
/// (signed sharing), for tests that go back to an older schema.
const UNDO_MIGRATION_14: &[&str] = &[
    "DROP TABLE vault_manifest_log",
    "ALTER TABLE vaults DROP COLUMN manifest",
    "ALTER TABLE vaults DROP COLUMN manifest_seq",
    "ALTER TABLE vaults DROP COLUMN manifest_prev",
    "DELETE FROM schema_version WHERE version = 17",
    "ALTER TABLE sends DROP COLUMN owner_content_key",
    "DELETE FROM schema_version WHERE version = 16",
    "ALTER TABLE users DROP COLUMN avatar",
    "ALTER TABLE users DROP COLUMN avatar_seq",
    "DELETE FROM schema_version WHERE version = 15",
    "DROP TABLE vault_rosters",
    "ALTER TABLE vaults DROP COLUMN member_roster",
    "ALTER TABLE vaults DROP COLUMN member_roster_seq",
    "ALTER TABLE vault_members DROP COLUMN share_signature",
    "ALTER TABLE vault_members DROP COLUMN share_signer",
    "ALTER TABLE vault_members DROP COLUMN share_signer_identity",
    "ALTER TABLE users DROP COLUMN signing_key",
    "ALTER TABLE users DROP COLUMN identity_signature",
    "ALTER TABLE users DROP COLUMN x25519_signature",
    "ALTER TABLE users DROP COLUMN wrapped_signing_key",
    "ALTER TABLE users DROP COLUMN identity_at",
    "ALTER TABLE users DROP COLUMN key_pins",
    "ALTER TABLE users DROP COLUMN key_pins_seq",
    "DELETE FROM schema_version WHERE version = 14",
];

fn fast_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        salt: b64(&[9; 16]),
    }
}

/// Test configuration. With `PASSAUTH_TEST_DATABASE_URL=postgres://…` every
/// test gets its own fresh PostgreSQL database; otherwise in-memory SQLite.
async fn test_config() -> Config {
    let mut config = Config::for_tests();
    if let Ok(base) = std::env::var("PASSAUTH_TEST_DATABASE_URL") {
        use sqlx::Connection;
        sqlx::any::install_default_drivers();
        let name = format!("passauth_test_{}", uuid::Uuid::new_v4().simple());
        let mut admin = sqlx::AnyConnection::connect(&base).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        let (prefix, _) = base.rsplit_once('/').expect("database URL ends in /<db>");
        config.database_url = format!("{prefix}/{name}");
    }
    config
}

async fn app() -> Router {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("warn")
        .try_init();
    crate::router(App::new(test_config().await).await.unwrap())
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    call_with(app, method, path, token, &[], body).await
}

/// `call` with extra request headers (e.g. `x-reauth-token`).
async fn call_with(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

struct Client {
    unlocked: UnlockedAccount,
    vault_id: String,
    vault_key: SymmetricKey,
}

async fn register(app: &Router, email: &str, pw: &str) -> Client {
    let (s, init) = call(
        app,
        Method::POST,
        "/api/auth/register/init",
        None,
        json!({ "email": email }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{init}");
    let account_id = init["account_id"].as_str().unwrap();
    let acct = AccountBundle::create_with_kdf(account_id, pw, false, fast_kdf()).unwrap();
    let start = opaque::register_start(&acct.master.login).unwrap();
    let (s, resp) = call(
        app,
        Method::POST,
        "/api/auth/register/start",
        None,
        json!({ "registration_id": init["registration_id"], "message": start.message }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    let upload = opaque::register_finish(
        &start.state,
        &acct.master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let vault_id = uuid::Uuid::new_v4().to_string();
    let (vault_key, wrapped) = acct.unlocked.new_vault_key(&vault_id).unwrap();
    let meta = b64(&vault_key
        .encrypt(br#"{"name":"Personal"}"#, b"meta")
        .unwrap());
    let (s, done) = call(app, Method::POST, "/api/auth/register/finish", None, json!({
        "registration_id": init["registration_id"], "upload": upload, "bundle": acct.bundle, "name": "Test",
        "vault": { "id": vault_id, "meta": meta, "wrapped_key": wrapped },
    })).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    Client {
        unlocked: acct.unlocked,
        vault_id,
        vault_key,
    }
}

/// Runs prelogin + OPAQUE login; returns the login/finish response.
async fn login(app: &Router, email: &str, pw: &str, device: &str) -> (StatusCode, Value) {
    login_with(app, email, pw, device, &[]).await
}

/// [`login`] with extra headers on `login/finish` (e.g. `x-passauth-client`).
async fn login_with(
    app: &Router,
    email: &str,
    pw: &str,
    device: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let (_, pre) = call(
        app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": email }),
    )
    .await;
    let kdf: KdfParams = serde_json::from_value(pre["kdf"].clone()).unwrap();
    let master =
        derive_master_keys(pw, None, pre["account_id"].as_str().unwrap(), &kdf, false).unwrap();
    let start = opaque::login_start(&master.login).unwrap();
    let (s, resp) = call(
        app,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": start.message }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    // A wrong password fails client-side; send garbage so the server rejects it too.
    let fin = opaque::login_finish(
        &start.state,
        &master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap_or_else(|_| b64(&[0; 64]));
    call_with(app, Method::POST, "/api/auth/login/finish", None, headers, json!({
        "login_id": resp["login_id"], "message": fin, "device": { "id": device, "name": "Test device", "kind": "cli" },
    }))
    .await
}

async fn token(app: &Router, email: &str, pw: &str) -> String {
    let (s, v) = login(app, email, pw, "dev-1").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["access_token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn register_login_and_reject_bad_credentials() {
    let app = app().await;
    register(&app, "alice@example.com", "correct horse").await;

    let (s, ok) = login(&app, "Alice@Example.com ", "correct horse", "d1").await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert!(ok["refresh_token"].is_string());
    assert_eq!(ok["bundle"]["account_id"], ok["user_id"]);

    let (wrong, _) = login(&app, "alice@example.com", "wrong", "d1").await;
    let (unknown, _) = login(&app, "nobody@example.com", "whatever", "d1").await;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown,
        StatusCode::UNAUTHORIZED,
        "unknown emails must look like wrong passwords"
    );

    let (_, p1) = call(
        &app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": "ghost@example.com" }),
    )
    .await;
    let (_, p2) = call(
        &app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": "ghost@example.com" }),
    )
    .await;
    assert_eq!(p1, p2, "fake prelogin must be stable");

    let (dup, _) = call(
        &app,
        Method::POST,
        "/api/auth/register/init",
        None,
        json!({ "email": "alice@example.com" }),
    )
    .await;
    assert_eq!(dup, StatusCode::CONFLICT);
}

#[tokio::test]
async fn items_sync_and_trash() {
    let app = app().await;
    let c = register(&app, "bob@example.com", "pw-bob-123").await;
    let t = token(&app, "bob@example.com", "pw-bob-123").await;

    let item = Item {
        format: ITEM_FORMAT,
        name: "GitHub".into(),
        login: Some(Login {
            username: "bob".into(),
            password: "s3cret".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let id = uuid::Uuid::new_v4().to_string();
    let enc = EncryptedItem::encrypt(&item, &id, &c.vault_id, &c.vault_key).unwrap();
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&t),
        json!({ "id": id, "vault_id": c.vault_id, "key": enc.key, "data": enc.data }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&t), json!(null)).await;
    let row = &sync["items"][0];
    assert!(
        !row["data"].as_str().unwrap().contains("GitHub"),
        "server must only see ciphertext"
    );
    let back = EncryptedItem {
        id: row["id"].as_str().unwrap().into(),
        vault_id: row["vault_id"].as_str().unwrap().into(),
        key: row["item_key"].as_str().unwrap().into(),
        data: row["data"].as_str().unwrap().into(),
    };
    let wk = sync["vaults"][0]["wrapped_key"].as_str().unwrap();
    let vk = c.unlocked.open_vault_key(&c.vault_id, 0, wk, true).unwrap();
    assert_eq!(back.decrypt(&vk).unwrap(), Item { rev: 1, ..item });

    let stale = row["revision"].as_i64().unwrap() - 1;
    let (s, _) = call(&app, Method::PUT, &format!("/api/items/{id}"), Some(&t),
        json!({ "id": id, "vault_id": c.vault_id, "key": enc.key, "data": enc.data, "revision": stale })).await;
    assert_eq!(s, StatusCode::CONFLICT);

    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/items/{id}"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&t), json!(null)).await;
    assert!(sync["items"][0]["deleted_at"].is_i64());

    let (s, _) = call(&app, Method::GET, "/api/sync", None, json!(null)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rotation_detects_reuse() {
    let app = app().await;
    register(&app, "carol@example.com", "pw-carol-1").await;
    let (_, l) = login(&app, "carol@example.com", "pw-carol-1", "d").await;
    let r1 = l["refresh_token"].as_str().unwrap();
    let (s, r) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": r1 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": r1 }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "reused refresh token");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": r["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "session revoked after reuse");
}

#[tokio::test]
async fn totp_two_factor() {
    let app = app().await;
    register(&app, "dave@example.com", "pw-dave-12").await;
    let t = token(&app, "dave@example.com", "pw-dave-12").await;
    let (_, setup) = call(
        &app,
        Method::POST,
        "/api/account/2fa/totp/setup",
        Some(&t),
        json!({}),
    )
    .await;
    let totp = Totp::parse(setup["uri"].as_str().unwrap()).unwrap();
    let now = crate::db::now() as u64;
    // Turning it on needs the master password confirmed (a stolen session alone
    // can't add its own authenticator); older apps get a message they can show.
    let enable = |reauth: Option<String>, code: String| {
        let (app, t) = (app.clone(), t.clone());
        async move {
            let headers: Vec<(&str, &str)> = reauth
                .as_deref()
                .map(|r| vec![("x-reauth-token", r)])
                .unwrap_or_default();
            call_with(
                &app,
                Method::POST,
                "/api/account/2fa/totp/enable",
                Some(&t),
                &headers,
                json!({ "code": code }),
            )
            .await
        }
    };
    let (s, v) = enable(None, totp.generate(now)).await;
    assert_eq!(
        (s, &v["error"], &v["message"]),
        (
            StatusCode::FORBIDDEN,
            &json!("reauth_required"),
            &json!("Confirm your master password first. Update the app if it doesn't ask for it.")
        )
    );
    let (s, _) = enable(Some("not-a-token".into()), totp.generate(now)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // A mistyped code doesn't use the confirmation up.
    let reauth = reauth_token(&app, "dave@example.com", "pw-dave-12", &t).await;
    let wrong = if totp.generate(now) == "000000" {
        "111111"
    } else {
        "000000"
    };
    let (s, v) = enable(Some(reauth.clone()), wrong.into()).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_code"))
    );
    let (s, en) = enable(Some(reauth.clone()), totp.generate(now)).await;
    assert_eq!(s, StatusCode::OK, "{en}");
    let recovery = en["recovery_codes"][0].as_str().unwrap().to_owned();
    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(acct["two_factor"], json!(["totp"]));

    let (s, l) = login(&app, "dave@example.com", "pw-dave-12", "d2").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(l["two_factor_required"], true);
    assert!(l.get("access_token").is_none());
    let tf = l["two_factor_token"].clone();

    // The code used to enable is consumed; the next step's code works.
    let (s, wrong) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/verify",
        None,
        json!({ "two_factor_token": tf, "provider": "totp", "code": "000000" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(wrong["error"], "invalid_code");
    assert_eq!(wrong["message"], "invalid two-factor code");
    let (s, ok) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/verify",
        None,
        json!({ "two_factor_token": tf, "provider": "recovery", "code": recovery }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert!(ok["access_token"].is_string());

    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(acct["recovery_codes_left"], 9);
}

#[tokio::test]
async fn vault_sharing_and_permissions() {
    let app = app().await;
    let alice = register(&app, "a@example.com", "pw-alice-1").await;
    let bob = register(&app, "b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "a@example.com", "pw-alice-1").await;
    let tb = token(&app, "b@example.com", "pw-bobby-1").await;

    let (_, found) = call(
        &app,
        Method::GET,
        "/api/users/lookup?email=b@example.com",
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
    let path = format!("/api/vaults/{}/members", alice.vault_id);
    let (s, v) = call(
        &app,
        Method::POST,
        &path,
        Some(&ta),
        json!({ "user_id": found["user_id"], "role": "read", "sealed_key": sealed }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "invited");
    accept(&app, &tb, &alice.vault_id).await;

    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&tb), json!(null)).await;
    let shared = sync["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["key_kind"] == "sealed")
        .unwrap();
    let vk = bob
        .unlocked
        .open_shared_vault_key(&alice.vault_id, shared["wrapped_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(vk.as_bytes(), alice.vault_key.as_bytes());

    let id = uuid::Uuid::new_v4().to_string();
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&tb),
        json!({ "id": id, "vault_id": alice.vault_id, "key": "k", "data": "d" }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "read-only member cannot write");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&tb),
        json!({ "id": id, "vault_id": bob.vault_id, "key": "k", "data": "d" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/items/{id}"),
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "non-members cannot see other vaults' items"
    );
}

#[tokio::test]
async fn admin_requires_token() {
    let app = app().await;
    let (s, _) = call(&app, Method::GET, "/api/admin/users", None, json!(null)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("wrong"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(
        &app,
        Method::GET,
        "/api/admin/overview",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let expected = if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_ok() {
        "postgresql"
    } else {
        "sqlite"
    };
    assert_eq!(v["config"]["database"], expected);
}

async fn password_admin_app(password: &str) -> Router {
    let config = Config {
        admin_token: Some("old-token".into()),
        admin_username: "boss".into(),
        admin_password: Some(password.into()),
        ..test_config().await
    };
    crate::router(App::new(config).await.unwrap())
}

#[tokio::test]
async fn admin_signs_in_with_user_name_and_password() {
    let app = password_admin_app("a long admin password").await;
    let (s, v) = call(&app, Method::GET, "/api/admin/login", None, json!(null)).await;
    assert_eq!((s, &v["mode"]), (StatusCode::OK, &json!("password")));
    for (user, pw) in [
        ("boss", "wrong password!"),
        ("admin", "a long admin password"),
    ] {
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/admin/login",
            None,
            json!({ "username": user, "password": pw }),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{user}/{pw}");
    }
    // The password itself and the ignored ADMIN_TOKEN are not bearer tokens.
    for bearer in ["a long admin password", "old-token"] {
        let (s, _) = call(
            &app,
            Method::GET,
            "/api/admin/overview",
            Some(bearer),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "username": " boss ", "password": "a long admin password" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let token = v["token"].as_str().unwrap().to_owned();
    let (s, v) = call(
        &app,
        Method::GET,
        "/api/admin/overview",
        Some(&token),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["config"]["admin_login"], "password");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/logout",
        Some(&token),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/overview",
        Some(&token),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_page_stays_off_with_the_example_or_a_short_password() {
    for pw in [crate::config::ADMIN_PASSWORD_EXAMPLE, "short pw"] {
        let app = password_admin_app(pw).await;
        let (_, v) = call(&app, Method::GET, "/api/admin/login", None, json!(null)).await;
        assert_eq!(v, json!({ "mode": "off", "weak_password": true }));
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/admin/login",
            None,
            json!({ "username": "boss", "password": pw }),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = call(
            &app,
            Method::GET,
            "/api/admin/overview",
            Some("old-token"),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}

/// Admin session token from `/admin/login`, entering `code` when two-step login is on.
/// Clears the rate limits first (10 admin sign-ins a minute).
async fn admin_session(app: &Router, state: &AppState, code: Option<&str>) -> (StatusCode, Value) {
    state.limiter.clear();
    let (s, v) = call(
        app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "token": "test-admin" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    match (v["two_factor"].as_bool(), code) {
        (Some(true), Some(code)) => {
            call(
                app,
                Method::POST,
                "/api/admin/login/2fa",
                None,
                json!({ "pending": v["pending"], "code": code }),
            )
            .await
        }
        _ => (s, v),
    }
}

#[tokio::test]
async fn admin_two_step_login() {
    let state = App::new(test_config().await).await.unwrap();
    let app = crate::router(state.clone());
    let (_, v) = admin_session(&app, &state, None).await;
    let session = v["token"].as_str().unwrap().to_owned();
    let admin = Some(session.as_str());

    let (_, v) = call(&app, Method::GET, "/api/admin/2fa", admin, json!(null)).await;
    assert_eq!(v, json!({ "enabled": false, "recovery_codes_left": 0 }));
    let (s, v) = call(&app, Method::POST, "/api/admin/2fa/setup", admin, json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/PassAuth%20admin:localhost?")
    );
    let totp = Totp::parse(v["secret"].as_str().unwrap()).unwrap();
    let t = crate::db::now() as u64;
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/2fa/enable",
        admin,
        json!({ "code": "000000x" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/admin/2fa/enable",
        admin,
        json!({ "code": totp.generate(t) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let recovery: Vec<String> = serde_json::from_value(v["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 10);

    // ADMIN_TOKEN as a bearer token no longer gets around the code; the open session stays.
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(&app, Method::GET, "/api/admin/overview", admin, json!(null)).await;
    assert_eq!(
        (s, &v["config"]["admin_2fa"]),
        (StatusCode::OK, &json!(true))
    );

    // The code used to turn it on can't be used again; the next one works once.
    let (s, _) = admin_session(&app, &state, Some(&totp.generate(t))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let next = totp.generate(t + 30);
    let (s, v) = admin_session(&app, &state, Some(&next)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["token"].is_string());
    let (s, _) = admin_session(&app, &state, Some(&next)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "replayed code");

    // A recovery code works once, with or without the dash.
    let (s, _) = admin_session(
        &app,
        &state,
        Some(&recovery[0].replace('-', "").to_lowercase()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = admin_session(&app, &state, Some(&recovery[0])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, v) = call(&app, Method::GET, "/api/admin/2fa", admin, json!(null)).await;
    assert_eq!(v["recovery_codes_left"], 9);

    // Five wrong codes end the pending sign-in.
    state.limiter.clear();
    let (_, v) = call(
        &app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "token": "test-admin" }),
    )
    .await;
    for _ in 0..5 {
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/admin/login/2fa",
            None,
            json!({ "pending": v["pending"], "code": "123456" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let (s, e) = call(
        &app,
        Method::POST,
        "/api/admin/login/2fa",
        None,
        json!({ "pending": v["pending"], "code": recovery[1] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(e["message"].as_str().unwrap().contains("expired"), "{e}");

    // New recovery codes replace the old ones; turning it off needs a code.
    state.limiter.clear();
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/admin/2fa/recovery-codes",
        admin,
        json!({ "code": recovery[2] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fresh: Vec<String> = serde_json::from_value(v["recovery_codes"].clone()).unwrap();
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/2fa/disable",
        admin,
        json!({ "code": recovery[3] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "old recovery codes are gone");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/2fa/disable",
        admin,
        json!({ "code": fresh[0] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = admin_session(&app, &state, None).await;
    assert!(v["token"].is_string(), "password alone signs in again");
}

#[tokio::test]
async fn admin_page_only_from_allowed_networks() {
    let config = Config {
        admin_networks: Some(vec![crate::config::IpNet::parse("10.0.0.0/8").unwrap()]),
        ..test_config().await
    };
    let app = crate::router(App::new(config).await.unwrap());
    let (s, v) = call(&app, Method::GET, "/api/admin/login", None, json!(null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("PASSAUTH_ADMIN_ALLOWED_NETWORKS")
    );
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "token": "test-admin" }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // The rest of the server is not affected.
    let (s, _) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn admin_token_still_signs_in() {
    let app = app().await;
    let (_, v) = call(&app, Method::GET, "/api/admin/login", None, json!(null)).await;
    assert_eq!(v["mode"], "token");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "token": "nope" }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/admin/login",
        None,
        json!({ "token": "test-admin" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        v["token"].as_str(),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn admin_settings_apply_at_once_and_are_saved() {
    let dir = std::env::temp_dir().join(format!("passauth-test-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut config = test_config().await;
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        config.database_url = format!("sqlite://{}/passauth.db?mode=rwc", dir.display());
    }
    let admin = Some("test-admin");
    let app = crate::router(App::new(config.clone()).await.unwrap());

    let (s, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["icons"], &v["smtp"], &v["signups_verify"]),
        (&json!(true), &json!(null), &json!(false))
    );

    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        json!({ "log_level": "debug", "icons": false, "signups_verify": true, "session_days": 45, "breach_check": false }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["log_level"], "debug");
    assert_eq!(
        (&v["session_days"], &v["breach_check"]),
        (&json!(45), &json!(false))
    );
    let resp = get_raw(&app, "/api/icons/github.com").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "icons are off at once"
    );
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        json!({ "log_level": "loud", "icons": false, "signups_verify": true }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let smtp = json!({
        "host": "smtp.example.com", "security": "starttls", "username": "mailer",
        "password": "secret", "from": "not an address", "from_name": ""
    });
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings/smtp",
        admin,
        smtp.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let mut good = smtp.clone();
    good["from"] = json!("passauth@example.com");
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings/smtp",
        admin,
        good.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["smtp"]["port"], 587);
    assert_eq!(v["smtp"]["password_set"], true);
    assert_eq!(v["smtp"]["from_name"], "PassAuth");
    assert!(
        v["smtp"].get("password").is_none(),
        "the password is never sent back"
    );
    let (_, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(v["email_enabled"], true);
    // Saving without a password keeps the saved one.
    good.as_object_mut().unwrap().remove("password");
    good["port"] = json!(2525);
    let (_, v) = call(&app, Method::PUT, "/api/admin/settings/smtp", admin, good).await;
    assert_eq!(
        (&v["smtp"]["port"], &v["smtp"]["password_set"]),
        (&json!(2525), &json!(true))
    );

    // A restart keeps everything saved on the admin page (file database only).
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        drop(app);
        let app = crate::router(App::new(config.clone()).await.unwrap());
        let (_, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
        assert_eq!(v["log_level"], "debug");
        assert_eq!(v["icons"], false);
        assert_eq!(v["signups_verify"], true);
        assert_eq!(v["smtp"]["port"], 2525);
        assert_eq!(
            (&v["session_days"], &v["breach_check"]),
            (&json!(45), &json!(false))
        );
        assert_eq!(v["refresh_days"], 30, "never changed: still the default");
        let (s, v) = call(
            &app,
            Method::DELETE,
            "/api/admin/settings/smtp",
            admin,
            json!(null),
        )
        .await;
        assert_eq!((s, &v["smtp"]), (StatusCode::OK, &json!(null)));
        let (_, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
        assert_eq!(v["email_enabled"], false);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

async fn get_raw(app: &Router, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn icons_off_returns_404() {
    let config = Config {
        icon_service: false,
        ..test_config().await
    };
    let app = crate::router(App::new(config).await.unwrap());
    // `/api/config` says whether to ask at all, following the admin page at once.
    let offers_icons = || async {
        let (_, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
        v["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "icons")
    };
    let off_answer = || async {
        let resp = get_raw(&app, "/api/icons/github.com").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(resp.headers()["cache-control"], "no-store");
    };
    assert!(!offers_icons().await);
    off_answer().await;
    assert_eq!(
        admin_set(&app, json!({ "icons": true })).await.0,
        StatusCode::OK
    );
    assert!(offers_icons().await);
    assert_eq!(
        admin_set(&app, json!({ "icons": false })).await.0,
        StatusCode::OK
    );
    assert!(!offers_icons().await);
    off_answer().await;
}

#[tokio::test]
async fn icons_reject_invalid_hosts_without_fetching() {
    let app = app().await;
    for host in [
        "localhost",
        "127.0.0.1",
        "169.254.169.254",
        "%5B%3A%3A1%5D",
        "printer.local",
        "metadata.google.internal",
        "nas.lan",
        "example..com",
        "exa_mple.com",
        "127.1",
    ] {
        let resp = get_raw(&app, &format!("/api/icons/{host}")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{host}");
        let h = resp.headers();
        assert_eq!(h["content-security-policy"], "default-src 'none'");
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["cache-control"], "public, max-age=86400");
    }
}

#[tokio::test]
async fn icons_serve_cached_entries() {
    use crate::icons::{Icon, ImageKind};
    let state = App::new(test_config().await).await.unwrap();
    let png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    let icon = Icon {
        bytes: png.clone().into(),
        kind: ImageKind::Png,
    };
    state.icons.store("example.com", Some(&icon)).await;
    state.icons.store("example.org", None).await;
    let app = crate::router(state);

    let resp = get_raw(&app, "/api/icons/Example.COM").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h["content-type"], "image/png");
    assert_eq!(h["cache-control"], "public, max-age=604800");
    assert_eq!(h["content-security-policy"], "default-src 'none'");
    assert_eq!(h["x-content-type-options"], "nosniff");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), png.as_slice());

    let resp = get_raw(&app, "/api/icons/example.org").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.headers()["cache-control"], "public, max-age=86400");
}

#[tokio::test]
async fn admin_can_close_signups() {
    let app = app().await;
    let admin = Some("test-admin");
    let init = |email: &'static str| {
        let app = app.clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/auth/register/init",
                None,
                json!({ "email": email }),
            )
            .await
            .0
        }
    };
    let policy = |body: Value| {
        call(
            &app,
            Method::PUT,
            "/api/admin/settings/signups",
            admin,
            body,
        )
    };

    let (s, v) = policy(json!({ "allowed": false, "domains": [] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, cfg) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(cfg["signups_allowed"], false);
    assert_eq!(init("a@example.com").await, StatusCode::FORBIDDEN);

    let (s, _) = policy(json!({ "allowed": true, "domains": ["not a domain"] })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, v) = policy(json!({ "allowed": true, "domains": ["@Example.ORG"] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["domains"], json!(["example.org"]));
    assert_eq!(init("a@example.com").await, StatusCode::FORBIDDEN);
    assert_eq!(init("b@example.org").await, StatusCode::OK);

    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings/signups",
        None,
        json!({ "allowed": true, "domains": [] }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_api_path_is_404() {
    let app = app().await;
    let (s, _) = call(&app, Method::GET, "/api/nope", None, json!(null)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

async fn app_with_state() -> (Router, crate::state::AppState) {
    let state = App::new(test_config().await).await.unwrap();
    (crate::router(state.clone()), state)
}

/// Shares `owner`'s first vault with `email` at `role`; returns the status.
async fn share(
    app: &Router,
    owner: &Client,
    owner_token: &str,
    email: &str,
    role: &str,
) -> (StatusCode, Value) {
    share_vault(
        app,
        (&owner.vault_id, &owner.vault_key),
        owner_token,
        email,
        role,
        None,
    )
    .await
}

/// Shares a vault (id, key) with `email` at `role`, sending `key_epoch` if given.
async fn share_vault(
    app: &Router,
    (vault_id, vault_key): (&str, &SymmetricKey),
    token: &str,
    email: &str,
    role: &str,
    key_epoch: Option<i64>,
) -> (StatusCode, Value) {
    let (_, found) = call(
        app,
        Method::GET,
        &format!("/api/users/lookup?email={email}"),
        Some(token),
        json!(null),
    )
    .await;
    let sealed =
        share_vault_key(vault_id, vault_key, found["public_key"].as_str().unwrap()).unwrap();
    let mut body = json!({ "user_id": found["user_id"], "role": role, "sealed_key": sealed });
    if let Some(e) = key_epoch {
        body["key_epoch"] = e.into();
    }
    call(
        app,
        Method::POST,
        &format!("/api/vaults/{vault_id}/members"),
        Some(token),
        body,
    )
    .await
}

/// The invitee (signed in with `token`) accepts the invitation to `vault`.
async fn accept(app: &Router, token: &str, vault: &str) {
    let (s, v) = call(
        app,
        Method::POST,
        &format!("/api/vaults/{vault}/invitation/accept"),
        Some(token),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "active", "{v}");
}

#[tokio::test]
async fn ownership_cannot_be_granted_or_taken() {
    let app = app().await;
    let alice = register(&app, "own-a@example.com", "pw-alice-1").await;
    let bob = register(&app, "own-b@example.com", "pw-bobby-1").await;
    register(&app, "own-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "own-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "own-b@example.com", "pw-bobby-1").await;

    let (s, v) = share(&app, &alice, &ta, "own-b@example.com", "owner").await;
    assert_eq!(s, StatusCode::FORBIDDEN, "owner can't be granted: {v}");
    let (s, v) = share(&app, &alice, &ta, "own-b@example.com", "admin").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    accept(&app, &tb, &alice.vault_id).await;

    // Bob (admin) can't demote or overwrite the owner's key…
    let (_, me) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    let alice_id = me["user_id"].as_str().unwrap();
    let path = format!("/api/vaults/{}/members", alice.vault_id);
    let (s, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&tb),
        json!({ "user_id": alice_id, "role": "read", "sealed_key": "junk" }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // …nor remove the owner, nor share to someone who doesn't exist.
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}/{alice_id}"),
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let ghost = uuid::Uuid::new_v4().to_string();
    let (s, _) = call(
        &app,
        Method::POST,
        &path,
        Some(&tb),
        json!({ "user_id": ghost, "role": "read", "sealed_key": "junk" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // An admin can't share with a higher role than their own either.
    let (s, _) = share(&app, &alice, &tb, "own-c@example.com", "write").await;
    assert_eq!(s, StatusCode::OK);
    let _ = bob;
}

fn encrypted(c: &Client, name: &str) -> (String, EncryptedItem) {
    let item = Item {
        format: ITEM_FORMAT,
        name: name.into(),
        ..Default::default()
    };
    let id = uuid::Uuid::new_v4().to_string();
    let enc = EncryptedItem::encrypt(&item, &id, &c.vault_id, &c.vault_key).unwrap();
    (id, enc)
}

#[tokio::test]
async fn concurrent_edits_conflict_instead_of_overwriting() {
    let app = app().await;
    let c = register(&app, "race@example.com", "pw-race-123").await;
    let t = token(&app, "race@example.com", "pw-race-123").await;
    let (id, enc) = encrypted(&c, "A");
    let body = json!({ "id": id, "vault_id": c.vault_id, "key": enc.key, "data": enc.data });
    let (s, created) = call(&app, Method::POST, "/api/items", Some(&t), body).await;
    assert_eq!(s, StatusCode::OK, "{created}");
    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&t), json!(null)).await;
    let r0 = sync["items"][0]["revision"].as_i64().unwrap();

    // Two devices edit from the same revision: the second one must get 409.
    let edit = |rev: i64| json!({ "id": id, "vault_id": c.vault_id, "key": enc.key, "data": enc.data, "revision": rev });
    let path = format!("/api/items/{id}");
    let (s, first) = call(&app, Method::PUT, &path, Some(&t), edit(r0)).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    let (s, _) = call(&app, Method::PUT, &path, Some(&t), edit(r0)).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Trash with a stale revision is refused too; with the current one it works.
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}?revision={r0}"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let r1 = first["revision"].as_i64().unwrap();
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("{path}?revision={r1}"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Revisions keep increasing for the client.
    let (_, after) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&t),
        json!(null),
    )
    .await;
    assert!(after["revision"].as_i64().unwrap() > sync["revision"].as_i64().unwrap());
}

#[tokio::test]
async fn revision_never_goes_backwards() {
    let (app, state) = app_with_state().await;
    register(&app, "clock@example.com", "pw-clock-12").await;
    let t = token(&app, "clock@example.com", "pw-clock-12").await;
    let future = crate::db::now_ms() + 3_600_000;
    sqlx::query("UPDATE users SET revision = $1 WHERE email = 'clock@example.com'")
        .bind(future)
        .execute(&state.db)
        .await
        .unwrap();
    let vault =
        json!({ "id": uuid::Uuid::new_v4().to_string(), "meta": "bWV0YQ", "wrapped_key": "a2V5" });
    let (s, v) = call(&app, Method::POST, "/api/vaults", Some(&t), vault).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revision"].as_i64().unwrap(), future + 1);
}

#[tokio::test]
async fn rotation_rejects_duplicates_and_foreign_account_keys() {
    let app = app().await;
    let alice = register(&app, "rot-a@example.com", "pw-alice-1").await;
    register(&app, "rot-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "rot-a@example.com", "pw-alice-1").await;
    let (s, _) = share(&app, &alice, &ta, "rot-b@example.com", "read").await;
    assert_eq!(s, StatusCode::OK);
    let mut ids = Vec::new();
    for name in ["x", "y"] {
        let (id, enc) = encrypted(&alice, name);
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/items",
            Some(&ta),
            json!({ "id": id, "vault_id": alice.vault_id, "key": enc.key, "data": enc.data }),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        ids.push((id, enc));
    }
    let path = format!("/api/vaults/{}/members", alice.vault_id);
    let (_, m) = call(&app, Method::GET, &path, Some(&ta), json!(null)).await;
    let members: Vec<String> = m["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user_id"].as_str().unwrap().to_owned())
        .collect();
    let (_, me) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    let me = me["user_id"].as_str().unwrap().to_owned();
    let keys = |other_kind: &str| -> Vec<Value> {
        members
            .iter()
            .map(|u| {
                json!({
                    "user_id": u, "wrapped_key": "a2V5",
                    "key_kind": if *u == me { "account" } else { other_kind },
                })
            })
            .collect()
    };
    let item = |(id, enc): &(String, EncryptedItem)| json!({ "id": id, "vault_id": alice.vault_id, "key": enc.key, "data": enc.data });
    let rotate = format!("/api/vaults/{}/rotate", alice.vault_id);

    // Item x twice, y missing: the count matches but y would be left on the old key.
    let (s, v) = call(
        &app,
        Method::POST,
        &rotate,
        Some(&ta),
        json!({ "keys": keys("sealed"), "items": [item(&ids[0]), item(&ids[0])] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = call(
        &app,
        Method::POST,
        &rotate,
        Some(&ta),
        json!({ "keys": keys("account"), "items": [item(&ids[0]), item(&ids[1])] }),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "only the member can wrap with their account key"
    );
    let (s, v) = call(
        &app,
        Method::POST,
        &rotate,
        Some(&ta),
        json!({ "keys": keys("sealed"), "items": [item(&ids[0]), item(&ids[1])], "meta": "bmV3" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&ta), json!(null)).await;
    assert_eq!(
        sync["vaults"][0]["meta"], "bmV3",
        "meta is stored with the rotation"
    );
}

/// Signed sharing review round 4 L5: key replacements per vault are rate limited (each
/// adds a retired key id to every member's key pins).
#[tokio::test]
async fn key_replacements_per_vault_are_limited() {
    let app = app().await;
    let alice = register(&app, "rot-limit@example.com", "pw-alice-1").await;
    let ta = token(&app, "rot-limit@example.com", "pw-alice-1").await;
    let (_, me) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    let me = me["user_id"].as_str().unwrap().to_owned();
    let rotate = format!("/api/vaults/{}/rotate", alice.vault_id);
    let body = json!({
        "keys": [{ "user_id": me, "wrapped_key": "a2V5", "key_kind": "account" }],
        "items": [],
    });
    // Review round 5 L: refused requests (here: no key for the only member) don't count.
    let incomplete = json!({ "keys": [], "items": [] });
    for _ in 0..crate::vault::KEY_REPLACEMENTS_PER_HOUR {
        let (s, v) = call(&app, Method::POST, &rotate, Some(&ta), incomplete.clone()).await;
        assert!(
            s.is_client_error() && s != StatusCode::TOO_MANY_REQUESTS,
            "{s} {v}"
        );
    }
    for _ in 0..crate::vault::KEY_REPLACEMENTS_PER_HOUR {
        let (s, v) = call(&app, Method::POST, &rotate, Some(&ta), body.clone()).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (s, v) = call(&app, Method::POST, &rotate, Some(&ta), body.clone()).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
    assert_eq!(v["error"], "rate_limited");
    // Nothing changed: the epoch is the one after the last allowed replacement.
    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&ta), json!(null)).await;
    let vault = sync["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == alice.vault_id.as_str())
        .unwrap();
    assert_eq!(
        vault["key_epoch"],
        u64::from(crate::vault::KEY_REPLACEMENTS_PER_HOUR)
    );
}

#[tokio::test]
async fn deleting_an_account_keeps_vaults_with_another_owner() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "del-a@example.com", "pw-alice-1").await;
    register(&app, "del-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "del-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "del-b@example.com", "pw-bobby-1").await;
    let (s, _) = share(&app, &alice, &ta, "del-b@example.com", "admin").await;
    assert_eq!(s, StatusCode::OK);
    accept(&app, &tb, &alice.vault_id).await;
    let (id, enc) = encrypted(&alice, "shared");
    call(
        &app,
        Method::POST,
        "/api/items",
        Some(&ta),
        json!({ "id": id, "vault_id": alice.vault_id, "key": enc.key, "data": enc.data }),
    )
    .await;
    // A co-owner from before ownership grants were removed.
    sqlx::query("UPDATE vault_members SET role = 'owner' WHERE vault_id = $1")
        .bind(&alice.vault_id)
        .execute(&state.db)
        .await
        .unwrap();
    let (_, before) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&tb),
        json!(null),
    )
    .await;
    let (_, me) = call(&app, Method::GET, "/api/account", Some(&ta), json!(null)).await;
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/admin/users/{}", me["user_id"].as_str().unwrap()),
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&tb), json!(null)).await;
    let kept = sync["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["id"] == alice.vault_id.as_str());
    assert!(kept, "the co-owned vault survives");
    assert_eq!(sync["items"].as_array().unwrap().len(), 1);
    assert!(
        sync["revision"].as_i64() > before["revision"].as_i64(),
        "the co-owner is told to re-sync"
    );
}

#[tokio::test]
async fn two_factor_guessing_locks_the_account() {
    let app = app().await;
    register(&app, "lock@example.com", "pw-lock-123").await;
    let t = token(&app, "lock@example.com", "pw-lock-123").await;
    let (_, setup) = call(
        &app,
        Method::POST,
        "/api/account/2fa/totp/setup",
        Some(&t),
        json!({}),
    )
    .await;
    let totp = Totp::parse(setup["uri"].as_str().unwrap()).unwrap();
    let now = crate::db::now() as u64;
    let reauth = reauth_token(&app, "lock@example.com", "pw-lock-123", &t).await;
    let (s, _) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/totp/enable",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!({ "code": totp.generate(now) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let wrong = if totp.generate(now + 30) == "000000" {
        "111111"
    } else {
        "000000"
    };
    let mut locked = false;
    for _attempt in 0..4 {
        let (_, l) = login(&app, "lock@example.com", "pw-lock-123", "d-lock").await;
        let tf = l["two_factor_token"].clone();
        for _ in 0..5 {
            let (s, _) = call(
                &app,
                Method::POST,
                "/api/auth/2fa/verify",
                None,
                json!({ "two_factor_token": tf, "provider": "totp", "code": wrong }),
            )
            .await;
            if s == StatusCode::TOO_MANY_REQUESTS {
                locked = true;
                break;
            }
        }
        if locked {
            break;
        }
    }
    assert!(
        locked,
        "fresh tokens per login must not reset the per-account limit"
    );
    let (_, l) = login(&app, "lock@example.com", "pw-lock-123", "d-lock").await;
    let (s, _) = call(&app, Method::POST, "/api/auth/2fa/verify", None,
        json!({ "two_factor_token": l["two_factor_token"], "provider": "totp", "code": totp.generate(now + 30) })).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "even the right code waits out the lockout"
    );
}

#[tokio::test]
async fn api_errors_are_json_and_tokens_stay_out_of_urls() {
    let app = app().await;
    register(&app, "json@example.com", "pw-json-123").await;
    let t = token(&app, "json@example.com", "pw-json-123").await;
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/auth/prelogin")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(resp.headers()["content-type"], "application/json");
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "bad_request");

    let big = "x".repeat(100 * 1024);
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": big }),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    assert_eq!(v["error"], "too_large");

    // Item routes still take a full-size encrypted item.
    let (_, sync) = call(&app, Method::GET, "/api/sync", Some(&t), json!(null)).await;
    let vault = sync["vaults"][0]["id"].as_str().unwrap();
    let blob = "A".repeat(1024 * 1024);
    let item = json!({
        "id": uuid::Uuid::new_v4().to_string(), "vault_id": vault, "key": "k", "data": blob,
    });
    let (s, v) = call(&app, Method::POST, "/api/items", Some(&t), item).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/sync?access_token={t}"),
        None,
        json!(null),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "query tokens only work for /api/ws"
    );
}

#[test]
fn client_ip_trusts_only_proxies() {
    use axum::http::{HeaderMap, HeaderValue};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let state = rt
        .block_on(async {
            App::new(Config {
                ip_header: Some("x-forwarded-for".into()),
                ..test_config().await
            })
            .await
        })
        .unwrap();
    let ip = |peer: &str, xff: &str| {
        let mut h = HeaderMap::new();
        h.insert(
            crate::auth::PEER_IP_HEADER,
            HeaderValue::from_str(peer).unwrap(),
        );
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        crate::auth::client_ip(&state, &h)
    };
    // Behind a local proxy: the right-most untrusted hop, not the client-written first entry.
    assert_eq!(ip("172.18.0.2", "6.6.6.6, 203.0.113.9"), "203.0.113.9");
    assert_eq!(ip("127.0.0.1", "203.0.113.9, 10.0.0.5"), "203.0.113.9");
    // A direct connection from the internet can't pick its own address.
    assert_eq!(ip("198.51.100.7", "1.2.3.4"), "198.51.100.7");
    // IPv6 is bucketed by /64.
    assert_eq!(ip("2001:db8:1:2:aaaa::1", "x"), "2001:db8:1:2::/64");
    assert_eq!(ip("::ffff:198.51.100.7", "1.2.3.4"), "198.51.100.7");
}

#[test]
fn healthcheck_connects_to_the_bound_address() {
    use crate::healthcheck_target as t;
    assert_eq!(t(None).to_string(), "127.0.0.1:8080");
    assert_eq!(t(Some("0.0.0.0:9000")).to_string(), "127.0.0.1:9000");
    assert_eq!(t(Some("[::]:8080")).to_string(), "[::1]:8080");
    assert_eq!(t(Some("10.0.0.4:8080")).to_string(), "10.0.0.4:8080");
}

// ------------------------------------------------- security keys / passkeys

/// A reauth token for `email` (OPAQUE login with `purpose: "reauth"` on the session `token`).
async fn reauth_token(app: &Router, email: &str, pw: &str, token: &str) -> String {
    let (_, pre) = call(
        app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": email }),
    )
    .await;
    let kdf: KdfParams = serde_json::from_value(pre["kdf"].clone()).unwrap();
    let master =
        derive_master_keys(pw, None, pre["account_id"].as_str().unwrap(), &kdf, false).unwrap();
    let start = opaque::login_start(&master.login).unwrap();
    let (_, resp) = call(
        app,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": start.message }),
    )
    .await;
    let fin = opaque::login_finish(
        &start.state,
        &master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let (s, v) = call(
        app,
        Method::POST,
        "/api/auth/login/finish",
        Some(token),
        json!({
            "login_id": resp["login_id"], "message": fin, "purpose": "reauth",
            "device": { "id": "dev-1", "name": "Test device", "kind": "cli" },
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v["reauth_token"].as_str().unwrap().to_owned()
}

/// The test server's relying party (`Config::for_tests` domain).
const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost";

/// Soft authenticator: the core's passkey crypto plays the security key.
struct SoftKey(passauth_core::passkey::NewPasskey);

impl SoftKey {
    fn create(options: &Value) -> (Self, Value) {
        use passauth_core::passkey::{client_data_json, create};
        let pk = &options["publicKey"];
        assert_eq!(pk["rp"]["id"], RP_ID, "{options}");
        assert_eq!(
            pk["authenticatorSelection"]["userVerification"], "preferred",
            "{options}"
        );
        assert!(pk.get("hints").is_none(), "{options}");
        // Chrome: NotSupportedError when credProtect is requested with UV "preferred".
        assert!(
            pk["extensions"].get("credentialProtectionPolicy").is_none(),
            "{options}"
        );
        let key = create(RP_ID).unwrap();
        let client_data = client_data_json(
            "webauthn.create",
            pk["challenge"].as_str().unwrap(),
            RP_ORIGIN,
        );
        let credential = json!({
            "id": b64(&key.credential_id), "rawId": b64(&key.credential_id), "type": "public-key",
            "response": { "attestationObject": b64(&key.attestation_object), "clientDataJSON": b64(client_data.as_bytes()) },
        });
        (Self(key), credential)
    }

    fn id(&self) -> String {
        b64(&self.0.credential_id)
    }

    /// An assertion for `options`; `valid = false` corrupts the signature.
    fn assert(&self, options: &Value, valid: bool) -> Value {
        use passauth_core::passkey::{assert, client_data_json, sha256};
        let pk = &options["publicKey"];
        assert_eq!(pk["rpId"], RP_ID, "{options}");
        let client_data =
            client_data_json("webauthn.get", pk["challenge"].as_str().unwrap(), RP_ORIGIN);
        let a = assert(
            &self.0.private_key_pkcs8,
            RP_ID,
            &sha256(client_data.as_bytes()),
        )
        .unwrap();
        let mut sig = a.signature;
        if !valid {
            let last = sig.len() - 1;
            sig[last] ^= 1;
        }
        json!({
            "id": self.id(), "rawId": self.id(), "type": "public-key",
            "response": {
                "authenticatorData": b64(&a.authenticator_data), "clientDataJSON": b64(client_data.as_bytes()),
                "signature": b64(&sig), "userHandle": null,
            },
        })
    }
}

/// Password login, then the security-key challenge; returns (two-factor token, options).
async fn passkey_challenge(app: &Router, email: &str, pw: &str) -> (StatusCode, Value, Value) {
    let (s, l) = login(app, email, pw, "d2").await;
    assert_eq!(s, StatusCode::OK, "{l}");
    assert_eq!(l["two_factor_required"], true);
    assert!(
        l["providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "passkey"),
        "{l}"
    );
    let tf = l["two_factor_token"].clone();
    let (s, o) = call(
        app,
        Method::POST,
        "/api/auth/2fa/passkey/start",
        None,
        json!({ "two_factor_token": tf }),
    )
    .await;
    (s, tf, o["options"].clone())
}

#[tokio::test]
async fn passkey_two_factor() {
    let app = app().await;
    let (email, pw) = ("gail@example.com", "pw-gail-12");
    register(&app, email, pw).await;
    let t = token(&app, email, pw).await;

    // Registration needs a fresh reauth token.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/start",
        Some(&t),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let ra = reauth_token(&app, email, pw, &t).await;
    let (s, start) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/start",
        Some(&t),
        &[("x-reauth-token", &ra)],
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let (key, credential) = SoftKey::create(&start["options"]);
    let (s, v) = call(&app, Method::POST, "/api/account/2fa/passkey/register/finish", Some(&t),
        json!({ "registration_id": start["registration_id"], "name": "  ", "credential": credential })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, done) = call(&app, Method::POST, "/api/account/2fa/passkey/register/finish", Some(&t),
        json!({ "registration_id": start["registration_id"], "name": "Blue key", "credential": credential })).await;
    assert_eq!(s, StatusCode::OK, "{done}");
    assert_eq!(done["id"], key.id());
    // First method → recovery codes, shown once.
    assert_eq!(done["recovery_codes"].as_array().unwrap().len(), 10);
    // The registration id is single-use.
    let (s, v) = call(&app, Method::POST, "/api/account/2fa/passkey/register/finish", Some(&t),
        json!({ "registration_id": start["registration_id"], "name": "Again", "credential": credential })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(acct["two_factor"], json!(["passkey"]));
    assert_eq!(acct["passkeys"][0]["name"], "Blue key");
    assert_eq!(acct["passkeys"][0]["id"], key.id());
    assert!(acct["passkeys"][0]["last_used_at"].is_null());
    assert_eq!(acct["recovery_codes_left"], 10);

    // Sign in: a bad assertion is a wrong code; a good one gives a session.
    let (s, tf, options) = passkey_challenge(&app, email, pw).await;
    assert_eq!(s, StatusCode::OK, "{options}");
    assert_eq!(
        options["publicKey"]["allowCredentials"][0]["id"],
        key.id(),
        "{options}"
    );
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/finish",
        None,
        json!({ "two_factor_token": tf, "credential": key.assert(&options, false) }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // The challenge is gone after a failure: finish needs a new start.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/finish",
        None,
        json!({ "two_factor_token": tf, "credential": key.assert(&options, true) }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, o) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/start",
        None,
        json!({ "two_factor_token": tf }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{o}");
    let (s, ok) = call(&app, Method::POST, "/api/auth/2fa/passkey/finish", None,
        json!({ "two_factor_token": tf, "credential": key.assert(&o["options"], true), "remember": true })).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert!(ok["access_token"].is_string());
    assert!(ok["remember_token"].is_string());
    // A code sent to the classic endpoint for this provider is refused.
    let (s, l) = login(&app, email, pw, "d3").await;
    assert_eq!(s, StatusCode::OK, "{l}");
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/verify",
        None,
        json!({ "two_factor_token": l["two_factor_token"], "provider": "passkey", "code": "x" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert!(acct["passkeys"][0]["last_used_at"].is_i64(), "{acct}");

    // Removing the only key turns the method off and drops the recovery codes.
    let (s, v) = call(
        &app,
        Method::DELETE,
        &format!("/api/account/2fa/passkey/{}", key.id()),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let ra = reauth_token(&app, email, pw, &t).await;
    let (s, v) = call_with(
        &app,
        Method::DELETE,
        &format!("/api/account/2fa/passkey/{}", key.id()),
        Some(&t),
        &[("x-reauth-token", &ra)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(acct["two_factor"], json!([]));
    assert_eq!(acct["passkeys"], json!([]));
    assert_eq!(acct["recovery_codes_left"], 0);
    let (s, l) = login(&app, email, pw, "d4").await;
    assert_eq!(s, StatusCode::OK);
    assert!(l["access_token"].is_string(), "{l}");
}

#[tokio::test]
async fn passkey_failures_lock_the_account() {
    let app = app().await;
    let (email, pw) = ("hank@example.com", "pw-hank-12");
    register(&app, email, pw).await;
    let t = token(&app, email, pw).await;
    let ra = reauth_token(&app, email, pw, &t).await;
    let (s, start) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/start",
        Some(&t),
        &[("x-reauth-token", &ra)],
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let (key, credential) = SoftKey::create(&start["options"]);
    let (s, done) = call(&app, Method::POST, "/api/account/2fa/passkey/register/finish", Some(&t),
        json!({ "registration_id": start["registration_id"], "name": "Key", "credential": credential })).await;
    assert_eq!(s, StatusCode::OK, "{done}");

    // Each wrong assertion counts against the account (across sign-in tokens);
    // the 10th pauses two-step sign-in. A token takes 5 tries, then a new login is needed.
    let mut locked = false;
    'logins: for _ in 0..3 {
        let (s, tf, mut options) = passkey_challenge(&app, email, pw).await;
        assert_eq!(s, StatusCode::OK, "{options}");
        for _ in 0..5 {
            let (s, _) = call(
                &app,
                Method::POST,
                "/api/auth/2fa/passkey/finish",
                None,
                json!({ "two_factor_token": tf, "credential": key.assert(&options, false) }),
            )
            .await;
            if s == StatusCode::TOO_MANY_REQUESTS {
                locked = true;
                break 'logins;
            }
            assert_eq!(s, StatusCode::BAD_REQUEST);
            let (s, o) = call(
                &app,
                Method::POST,
                "/api/auth/2fa/passkey/start",
                None,
                json!({ "two_factor_token": tf }),
            )
            .await;
            if s != StatusCode::OK {
                break; // token used up after 5 tries
            }
            options = o["options"].clone();
        }
    }
    assert!(
        locked,
        "fresh tokens per login must not reset the per-account limit"
    );
    let (s, _, o) = passkey_challenge(&app, email, pw).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{o}");
}

#[tokio::test]
async fn passkey_challenges_are_rate_limited() {
    let app = app().await;
    let (email, pw) = ("ivy@example.com", "pw-ivy-123");
    register(&app, email, pw).await;
    let t = token(&app, email, pw).await;
    let ra = reauth_token(&app, email, pw, &t).await;
    let (s, start) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/start",
        Some(&t),
        &[("x-reauth-token", &ra)],
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let (_, credential) = SoftKey::create(&start["options"]);
    let (s, done) = call(&app, Method::POST, "/api/account/2fa/passkey/register/finish", Some(&t),
        json!({ "registration_id": start["registration_id"], "name": "Key", "credential": credential })).await;
    assert_eq!(s, StatusCode::OK, "{done}");

    // 20 challenges per account per 5 minutes; the sign-in token survives the refusal.
    let (s, tf, o) = passkey_challenge(&app, email, pw).await;
    assert_eq!(s, StatusCode::OK, "{o}");
    for _ in 1..20 {
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/auth/2fa/passkey/start",
            None,
            json!({ "two_factor_token": tf }),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/start",
        None,
        json!({ "two_factor_token": tf }),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/start",
        None,
        json!({ "two_factor_token": tf }),
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "token kept: {v}");
}

#[tokio::test]
async fn admin_resets_two_step_login() {
    let app = app().await;
    register(&app, "lost@example.com", "pw-lost-123").await;
    let t = token(&app, "lost@example.com", "pw-lost-123").await;
    let (_, setup) = call(
        &app,
        Method::POST,
        "/api/account/2fa/totp/setup",
        Some(&t),
        json!({}),
    )
    .await;
    let totp = Totp::parse(setup["uri"].as_str().unwrap()).unwrap();
    let reauth = reauth_token(&app, "lost@example.com", "pw-lost-123", &t).await;
    let (s, _) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/totp/enable",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!({ "code": totp.generate(crate::db::now() as u64) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, l) = login(&app, "lost@example.com", "pw-lost-123", "new-phone").await;
    assert_eq!(l["two_factor_required"], true);

    let (_, users) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    let user = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "lost@example.com")
        .unwrap()
        .clone();
    assert_eq!(user["two_factor"], 1);
    let path = format!(
        "/api/admin/users/{}/two-factor/reset",
        user["id"].as_str().unwrap()
    );
    // Only the admin can do it; the user's own token is not enough.
    let (s, _) = call(&app, Method::POST, &path, Some(&t), json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(&app, Method::POST, &path, Some("test-admin"), json!({})).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/admin/users/nobody/two-factor/reset",
        Some("test-admin"),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Signing in now needs only the master password, and nothing is left behind.
    let (s, l) = login(&app, "lost@example.com", "pw-lost-123", "new-phone-2").await;
    assert_eq!(s, StatusCode::OK);
    assert!(l["access_token"].is_string(), "{l}");
    let (_, acct) = call(&app, Method::GET, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(acct["two_factor"], json!([]));
    assert_eq!(acct["recovery_codes_left"], 0);
    assert_eq!(acct["passkeys"], json!([]));
}

#[tokio::test]
async fn removing_a_member_rotates_in_one_step_and_leaving_marks_the_vault() {
    let app = app().await;
    let alice = register(&app, "rm-a@example.com", "pw-alice-1").await;
    register(&app, "rm-b@example.com", "pw-bobby-1").await;
    register(&app, "rm-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "rm-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "rm-b@example.com", "pw-bobby-1").await;
    let tc = token(&app, "rm-c@example.com", "pw-carol-1").await;
    assert_eq!(
        share(&app, &alice, &ta, "rm-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        share(&app, &alice, &ta, "rm-c@example.com", "read").await.0,
        StatusCode::OK
    );
    accept(&app, &tb, &alice.vault_id).await;
    accept(&app, &tc, &alice.vault_id).await;
    let (id, enc) = encrypted(&alice, "shared");
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&ta),
        json!({ "id": id, "vault_id": alice.vault_id, "key": enc.key, "data": enc.data }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let uid = |t: &str| {
        let app = app.clone();
        let t = t.to_owned();
        async move {
            call(&app, Method::GET, "/api/account", Some(&t), json!(null))
                .await
                .1["user_id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let (a, b, c) = (uid(&ta).await, uid(&tb).await, uid(&tc).await);
    let key = |u: &str| json!({ "user_id": u, "wrapped_key": "a2V5", "key_kind": if u == a { "account" } else { "sealed" } });
    let items = json!([{ "id": id, "vault_id": alice.vault_id, "key": enc.key, "data": enc.data }]);
    let remove = |u: &str| format!("/api/vaults/{}/members/{u}/remove", alice.vault_id);
    let pending = |t: &str| {
        let app = app.clone();
        let t = t.to_owned();
        async move {
            call(&app, Method::GET, "/api/sync", Some(&t), json!(null))
                .await
                .1["vaults"][0]["rotation_pending"]
                .clone()
        }
    };

    // A key for the removed member too: rejected, and nobody is removed.
    let (s, _) = call(
        &app,
        Method::POST,
        &remove(&c),
        Some(&ta),
        json!({ "keys": [key(&a), key(&b), key(&c)], "items": items }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let in_vault = |t: &str| {
        let app = app.clone();
        let (t, v) = (t.to_owned(), alice.vault_id.clone());
        async move {
            call(&app, Method::GET, "/api/sync", Some(&t), json!(null))
                .await
                .1["vaults"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["id"] == v.as_str())
        }
    };
    assert!(in_vault(&tc).await);
    // A writer can't remove anyone, and nobody removes themselves this way.
    let (s, _) = call(
        &app,
        Method::POST,
        &remove(&c),
        Some(&tb),
        json!({ "keys": [
            { "user_id": a, "wrapped_key": "a2V5", "key_kind": "sealed" },
            { "user_id": b, "wrapped_key": "a2V5", "key_kind": "account" },
        ], "items": items }),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &app,
        Method::POST,
        &remove(&a),
        Some(&ta),
        json!({ "keys": [key(&b), key(&c)], "items": items }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Removal and rotation in one step: Carol is out, nothing is left pending.
    let (s, v) = call(
        &app,
        Method::POST,
        &remove(&c),
        Some(&ta),
        json!({ "keys": [key(&a), key(&b)], "items": items }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!in_vault(&tc).await);
    assert_eq!(pending(&ta).await, 0);

    // Bob leaves on his own (he can't rotate): the vault is marked for an admin.
    let (s, v) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}/members/{b}", alice.vault_id),
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["rotation_required"], true);
    assert_eq!(pending(&ta).await, 1);
    let (s, v) = call(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/rotate", alice.vault_id),
        Some(&ta),
        json!({ "keys": [key(&a)], "items": items }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(pending(&ta).await, 0, "rotating clears the mark");
}

// ------------------------------------------------------------------ API v2

async fn user_id(app: &Router, token: &str) -> String {
    let (_, me) = call(app, Method::GET, "/api/account", Some(token), json!(null)).await;
    me["user_id"].as_str().unwrap().to_owned()
}

async fn synced(app: &Router, token: &str) -> Value {
    let (s, v) = call(app, Method::GET, "/api/sync", Some(token), json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn rev_of(app: &Router, token: &str) -> i64 {
    let (_, v) = call(
        app,
        Method::GET,
        "/api/sync/revision",
        Some(token),
        json!(null),
    )
    .await;
    v["revision"].as_i64().unwrap()
}

fn vault_in<'a>(sync: &'a Value, id: &str) -> Option<&'a Value> {
    sync["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
}

fn item_in<'a>(sync: &'a Value, id: &str) -> Option<&'a Value> {
    sync["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
}

/// A second vault of `c`'s account: its id and key.
async fn new_vault(app: &Router, c: &Client, token: &str) -> (String, SymmetricKey) {
    let id = uuid::Uuid::new_v4().to_string();
    let (key, wrapped) = c.unlocked.new_vault_key(&id).unwrap();
    let meta = b64(&key.encrypt(br#"{"name":"Second"}"#, b"meta").unwrap());
    let (s, v) = call(
        app,
        Method::POST,
        "/api/vaults",
        Some(token),
        json!({ "id": id, "meta": meta, "wrapped_key": wrapped }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    (id, key)
}

/// `name` encrypted as item `id` of `(vault id, vault key)`, as a request body.
fn item_body(id: &str, (vault_id, key): (&str, &SymmetricKey), name: &str) -> Value {
    let item = Item {
        format: ITEM_FORMAT,
        name: name.into(),
        ..Default::default()
    };
    let enc = EncryptedItem::encrypt(&item, id, vault_id, key).unwrap();
    json!({ "id": id, "vault_id": vault_id, "key": enc.key, "data": enc.data })
}

/// A new item for a vault: its id and request body.
fn new_item(vault: (&str, &SymmetricKey), name: &str) -> (String, Value) {
    let id = uuid::Uuid::new_v4().to_string();
    let body = item_body(&id, vault, name);
    (id, body)
}

#[tokio::test]
async fn config_lists_the_api_version_and_features() {
    let app = app().await;
    let (s, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["api"], 2);
    assert_eq!(
        v["features"],
        json!([
            "key_epoch",
            "idempotent_create",
            "error_codes",
            "revoke_others",
            "trash_retention",
            "delta_sync",
            "vault_invitations",
            "activity_log",
            "policies",
            "forget_device",
            "emergency_vault_keys",
            "signed_sharing",
            "avatar",
            "account_wraps_v2",
            "send_v2",
            "vault_manifest",
            "breach_check",
            "item_history",
            "sends",
            "emergency_access",
            "login_with_device",
            "icons"
        ])
    );
    assert_eq!(v["trash_days"], 0);
    assert_eq!(
        v["limits"],
        json!({
            "max_import_items": 10000, "max_item_kib": 2048, "item_versions_kept": 10,
            "send_max_days": 30, "send_max_bytes": 1_048_576, "max_attachment_mb": 100,
        })
    );
    assert_eq!(
        v["policies"],
        json!({
            "require_two_step": false, "require_secret_key": false,
            "min_kdf_memory_mib": 64, "min_kdf_iterations": 3,
            "master_password_min_length": 10, "max_vault_timeout_minutes": 0,
            "disable_export": false,
        })
    );
}

#[tokio::test]
async fn a_replaced_vault_key_is_refused_and_nothing_is_written() {
    let app = app().await;
    let alice = register(&app, "ep-a@example.com", "pw-alice-1").await;
    register(&app, "ep-b@example.com", "pw-bobby-1").await;
    register(&app, "ep-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "ep-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "ep-b@example.com", "pw-bobby-1").await;
    let (a, b) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let v = alice.vault_id.as_str();
    let mine = (v, &alice.vault_key);
    let keys = |members: &[&str]| -> Value {
        members
            .iter()
            .map(|u| json!({ "user_id": u, "wrapped_key": "a2V5", "key_kind": if *u == a { "account" } else { "sealed" } }))
            .collect()
    };
    let stale = |(s, v): (StatusCode, Value)| {
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["error"], "vault_key_changed", "{v}");
    };

    assert_eq!(
        vault_in(&synced(&app, &ta).await, v).unwrap()["key_epoch"],
        0
    );
    let (s, r) = share_vault(&app, mine, &ta, "ep-b@example.com", "admin", Some(0)).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    accept(&app, &tb, v).await;

    // Rotating moves the epoch to 1, for every member.
    let rotate = format!("/api/vaults/{v}/rotate");
    let (s, r) = call(
        &app,
        Method::POST,
        &rotate,
        Some(&ta),
        json!({ "keys": keys(&[&a, &b]), "items": [], "key_epoch": 0 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["key_epoch"], 1);
    assert!(r["revision"].is_i64());
    assert_eq!(
        vault_in(&synced(&app, &tb).await, v).unwrap()["key_epoch"],
        1
    );

    // Everything that carries data under the old key is refused, and nothing changes.
    let before = synced(&app, &ta).await;
    let (x, mut body) = new_item(mine, "x");
    body["key_epoch"] = json!(0);
    stale(call(&app, Method::POST, "/api/items", Some(&ta), body.clone()).await);
    stale(
        call(
            &app,
            Method::POST,
            "/api/items/import",
            Some(&ta),
            json!({ "items": [body.clone()] }),
        )
        .await,
    );
    stale(
        call(
            &app,
            Method::PUT,
            &format!("/api/vaults/{v}"),
            Some(&ta),
            json!({ "meta": "bmV3", "key_epoch": 0 }),
        )
        .await,
    );
    stale(share_vault(&app, mine, &ta, "ep-c@example.com", "read", Some(0)).await);
    stale(
        call(
            &app,
            Method::POST,
            &rotate,
            Some(&ta),
            json!({ "keys": keys(&[&a, &b]), "items": [], "key_epoch": 0 }),
        )
        .await,
    );
    let remove_b = format!("/api/vaults/{v}/members/{b}/remove");
    stale(
        call(
            &app,
            Method::POST,
            &remove_b,
            Some(&ta),
            json!({ "keys": keys(&[&a]), "items": [], "key_epoch": 0 }),
        )
        .await,
    );
    let after = synced(&app, &ta).await;
    assert_eq!(after["items"], before["items"]);
    assert_eq!(after["vaults"], before["vaults"]);
    assert_eq!(
        after["revision"], before["revision"],
        "nobody is told about a change"
    );
    let (_, members) = call(
        &app,
        Method::GET,
        &format!("/api/vaults/{v}/members"),
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(members["members"].as_array().unwrap().len(), 2);

    // With the current epoch the same writes work.
    body["key_epoch"] = json!(1);
    let (s, r) = call(&app, Method::POST, "/api/items", Some(&ta), body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let mut edit = body.clone();
    edit["revision"] = r["revision"].clone();
    edit["key_epoch"] = json!(0);
    let path = format!("/api/items/{x}");
    stale(call(&app, Method::PUT, &path, Some(&ta), edit.clone()).await);
    assert_eq!(
        item_in(&synced(&app, &ta).await, &x).unwrap()["revision"],
        r["revision"]
    );
    edit["key_epoch"] = json!(1);
    let (s, r) = call(&app, Method::PUT, &path, Some(&ta), edit).await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // A move is checked against the target vault's epoch (0 for a new vault).
    let (v2, k2) = new_vault(&app, &alice, &ta).await;
    let mut moved = item_body(&x, (&v2, &k2), "x");
    moved["revision"] = r["revision"].clone();
    moved["key_epoch"] = json!(1);
    stale(call(&app, Method::PUT, &path, Some(&ta), moved.clone()).await);
    assert_eq!(
        item_in(&synced(&app, &ta).await, &x).unwrap()["vault_id"],
        v
    );
    moved["key_epoch"] = json!(0);
    let (s, r) = call(&app, Method::PUT, &path, Some(&ta), moved).await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // Older clients send no epoch: accepted as before.
    let (s, r) = call(
        &app,
        Method::PUT,
        &format!("/api/vaults/{v}"),
        Some(&ta),
        json!({ "meta": "bmV3" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");

    // Removing Bob with the current epoch replaces the key again.
    let (s, r) = call(
        &app,
        Method::POST,
        &remove_b,
        Some(&ta),
        json!({ "keys": keys(&[&a]), "items": [], "key_epoch": 1 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["key_epoch"], 2);
    assert_eq!(
        vault_in(&synced(&app, &ta).await, v).unwrap()["key_epoch"],
        2
    );

    // Bob is no longer a member: an old epoch tells him nothing about the vault.
    let (_, mut body) = new_item(mine, "y");
    body["key_epoch"] = json!(0);
    let (s, _) = call(&app, Method::POST, "/api/items", Some(&tb), body).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn retried_creates_and_imports_succeed_once() {
    let app = app().await;
    let c = register(&app, "retry@example.com", "pw-retry-12").await;
    let t = token(&app, "retry@example.com", "pw-retry-12").await;
    let mine = (c.vault_id.as_str(), &c.vault_key);
    let (x, body) = new_item(mine, "x");
    let (s, first) = call(&app, Method::POST, "/api/items", Some(&t), body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    assert_eq!(
        item_in(&synced(&app, &t).await, &x).unwrap()["revision"],
        first["revision"],
        "the create answers with the item's stored revision"
    );
    let rev = rev_of(&app, &t).await;

    // The same create again (its answer was lost): the same answer, nothing new.
    let (s, again) = call(&app, Method::POST, "/api/items", Some(&t), body.clone()).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again, first);
    assert_eq!(rev_of(&app, &t).await, rev, "a repeat changes nothing");
    assert_eq!(synced(&app, &t).await["items"].as_array().unwrap().len(), 1);

    // The same id with other contents is another item.
    let mut clash = new_item(mine, "other").1;
    clash["id"] = json!(x);
    let (s, v) = call(&app, Method::POST, "/api/items", Some(&t), clash.clone()).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["error"], "item_exists");
    assert_eq!(v["message"], "item id already exists");

    // Import: repeats count as imported; a clash stops the whole batch.
    let (y, ybody) = new_item(mine, "y");
    let both = json!({ "items": [body.clone(), ybody.clone()] });
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/items/import",
        Some(&t),
        both.clone(),
    )
    .await;
    assert_eq!((s, &v["imported"]), (StatusCode::OK, &json!(2)), "{v}");
    let rev = rev_of(&app, &t).await;
    let (s, v) = call(&app, Method::POST, "/api/items/import", Some(&t), both).await;
    assert_eq!((s, &v["imported"]), (StatusCode::OK, &json!(2)), "{v}");
    assert_eq!(rev_of(&app, &t).await, rev);
    let (z, zbody) = new_item(mine, "z");
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/items/import",
        Some(&t),
        json!({ "items": [zbody, clash] }),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("item_exists"))
    );
    let sync = synced(&app, &t).await;
    assert!(
        item_in(&sync, &z).is_none(),
        "nothing of a refused import is stored"
    );
    assert!(item_in(&sync, &y).is_some());
    assert_eq!(sync["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn stale_item_writes_get_revision_conflict() {
    let app = app().await;
    let c = register(&app, "stale@example.com", "pw-stale-12").await;
    let t = token(&app, "stale@example.com", "pw-stale-12").await;
    let (x, body) = new_item((&c.vault_id, &c.vault_key), "x");
    let (_, created) = call(&app, Method::POST, "/api/items", Some(&t), body.clone()).await;
    let r0 = created["revision"].as_i64().unwrap();
    let path = format!("/api/items/{x}");
    let mut edit = body.clone();
    edit["revision"] = r0.into();
    let (s, _) = call(&app, Method::PUT, &path, Some(&t), edit.clone()).await;
    assert_eq!(s, StatusCode::OK);
    let conflict = |(s, v): (StatusCode, Value)| {
        assert_eq!(s, StatusCode::CONFLICT, "{v}");
        assert_eq!(v["error"], "revision_conflict", "{v}");
        assert_eq!(
            v["message"],
            "item changed on another device; sync and retry"
        );
    };
    conflict(call(&app, Method::PUT, &path, Some(&t), edit).await);
    for (method, p) in [
        (Method::DELETE, format!("{path}?revision={r0}")),
        (Method::POST, format!("{path}/restore?revision={r0}")),
        (Method::DELETE, format!("{path}/permanent?revision={r0}")),
    ] {
        conflict(call(&app, method, &p, Some(&t), json!(null)).await);
    }
}

#[tokio::test]
async fn rate_limited_answers_say_when_to_retry() {
    let app = app().await;
    register(&app, "slow@example.com", "pw-slow-123").await;
    let t = token(&app, "slow@example.com", "pw-slow-123").await;
    let lookup = || {
        Request::get("/api/users/lookup?email=nobody@example.com")
            .header("authorization", format!("Bearer {t}"))
            .body(Body::empty())
            .unwrap()
    };
    for _ in 0..30 {
        let resp = app.clone().oneshot(lookup()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    let resp = app.clone().oneshot(lookup()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = resp.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=600).contains(&retry), "{retry}");
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "rate_limited");
    assert_eq!(body["message"], "too many requests, try again later");
}

#[test]
fn rate_limiter_stays_bounded_and_floods_never_reset_target_counters() {
    use crate::state::{Class, LIMITER_MAX_KEYS, RateLimiter};
    let limiter = RateLimiter::default();
    // A per-target counter at its limit, and a per-email ceiling at its limit.
    for _ in 0..3 {
        limiter.hit(Class::Target, "guard", 3, 3600).unwrap();
    }
    assert!(limiter.hit(Class::Target, "guard", 3, 3600).is_err());
    for _ in 0..crate::auth::LOGIN_PER_EMAIL {
        limiter.login_email.hit("victim@example.com").unwrap();
    }
    assert!(limiter.login_email.hit("victim@example.com").is_err());
    // A flood of address keys stays bounded…
    for i in 0..LIMITER_MAX_KEYS + 10 {
        let _ = limiter.hit(Class::Address, &format!("flood:{i}"), 5, 60);
        let _ = limiter.login_email.hit(&format!("someone-{i}@example.com"));
    }
    assert!(limiter.key_count(Class::Address) <= LIMITER_MAX_KEYS);
    // …and drops none of the others.
    assert_eq!(limiter.key_count(Class::Target), 1);
    let wait = limiter.hit(Class::Target, "guard", 3, 3600).unwrap_err();
    assert!((3000..=3600).contains(&wait), "{wait}");
    assert!(limiter.login_email.hit("victim@example.com").is_err());
    for _ in 0..5 {
        limiter.hit(Class::Address, "busy", 5, 60).unwrap();
    }
    let wait = limiter.hit(Class::Address, "busy", 5, 60).unwrap_err();
    assert!((1..=60).contains(&wait), "{wait}");
}

#[test]
fn slot_counters_count_every_key_alike_and_never_grow() {
    use crate::state::SlotCounter;
    let counter = SlotCounter::new(1 << 4, 3, 60);
    for _ in 0..3 {
        counter.hit("a@example.com").unwrap();
    }
    let wait = counter.hit("a@example.com").unwrap_err();
    assert!((1..=60).contains(&wait), "{wait}");
    // With few slots, keys share them: a shared slot only gets stricter.
    let refused = (0..64)
        .filter(|i| counter.hit(&format!("k{i}@example.com")).is_err())
        .count();
    assert!(refused > 0, "16 slots for 64 keys, 3 each");
    // A slot whose window ended starts again.
    let counter = SlotCounter::new(1 << 4, 1, 0);
    counter.hit("b@example.com").unwrap();
    counter.hit("b@example.com").unwrap();
}

#[tokio::test]
async fn signing_out_other_sessions_keeps_this_one() {
    let app = app().await;
    register(&app, "many@example.com", "pw-many-123").await;
    let mut sessions = Vec::new();
    for d in ["d1", "d2", "d3"] {
        let (s, l) = login(&app, "many@example.com", "pw-many-123", d).await;
        assert_eq!(s, StatusCode::OK, "{l}");
        sessions.push(l);
    }
    let access = |i: usize| sessions[i]["access_token"].as_str().unwrap().to_owned();
    let refresh = |i: usize| {
        let app = app.clone();
        let r = sessions[i]["refresh_token"].clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/auth/refresh",
                None,
                json!({ "refresh_token": r }),
            )
            .await
        }
    };
    // One session signed out from another: its refresh token stops working.
    let (_, third) = call(
        &app,
        Method::GET,
        "/api/account/sessions",
        Some(&access(2)),
        json!(null),
    )
    .await;
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!(
            "/api/account/sessions/{}",
            third["current"].as_str().unwrap()
        ),
        Some(&access(0)),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(refresh(2).await.0, StatusCode::UNAUTHORIZED);

    // Then every other one at once; the caller stays signed in.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/account/sessions/revoke-others",
        Some(&access(0)),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revoked"], 1);
    assert_eq!(refresh(1).await.0, StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/account",
        Some(&access(0)),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, r) = refresh(0).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (_, list) = call(
        &app,
        Method::GET,
        "/api/account/sessions",
        r["access_token"].as_str(),
        json!(null),
    )
    .await;
    let all = list["sessions"].as_array().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["id"], list["current"]);
}

#[tokio::test]
async fn sessions_end_ninety_days_after_sign_in() {
    let (app, state) = app_with_state().await;
    register(&app, "old@example.com", "pw-old-1234").await;
    let (_, l) = login(&app, "old@example.com", "pw-old-1234", "d1").await;
    let day = 24 * 3600;
    let set_created = |at: i64| {
        let db = state.db.clone();
        async move {
            sqlx::query("UPDATE sessions SET created_at = $1")
                .bind(at)
                .execute(&db)
                .await
                .unwrap();
        }
    };
    // Signed in 89 days ago: it still refreshes, but only up to day 90.
    let created = crate::db::now() - 89 * day;
    set_created(created).await;
    let (s, r) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": l["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let ends: i64 = sqlx::query_scalar("SELECT refresh_expires FROM sessions")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(
        ends <= created + 90 * day,
        "refresh never reaches past day 90"
    );
    assert!(r["expires_in"].as_i64().unwrap() <= crate::auth::ACCESS_TTL);

    // Signed in 91 days ago: refused, however fresh the refresh token.
    set_created(crate::db::now() - 91 * day).await;
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": r["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
    assert_eq!(v["error"], "session_expired");
}

#[tokio::test]
async fn the_client_app_is_kept_with_each_session() {
    let app = app().await;
    register(&app, "apps@example.com", "pw-apps-123").await;
    let email = "apps@example.com";
    let (_, l1) = login_with(
        &app,
        email,
        "pw-apps-123",
        "phone",
        &[("x-passauth-client", "ios/0.6.0")],
    )
    .await;
    login_with(
        &app,
        email,
        "pw-apps-123",
        "laptop",
        &[("x-passauth-client", "not a client name")],
    )
    .await;
    let (_, l3) = login(&app, email, "pw-apps-123", "tablet").await;
    let t1 = l1["access_token"].as_str().unwrap().to_owned();
    let client_of = |device: &'static str| {
        let (app, t1) = (app.clone(), t1.clone());
        async move {
            let (_, list) = call(
                &app,
                Method::GET,
                "/api/account/sessions",
                Some(&t1),
                json!(null),
            )
            .await;
            list["sessions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["device_id"] == device)
                .unwrap()["client"]
                .clone()
        }
    };
    assert_eq!(client_of("phone").await, "ios/0.6.0");
    assert_eq!(client_of("laptop").await, Value::Null);
    assert_eq!(client_of("tablet").await, Value::Null);
    // An app says what it is on its next refresh, e.g. after an update.
    let (s, _) = call_with(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        &[("x-passauth-client", "android/0.6.1")],
        json!({ "refresh_token": l3["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(client_of("tablet").await, "android/0.6.1");
}

#[tokio::test]
async fn old_trash_is_deleted_after_the_admins_trash_days() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "trash@example.com", "pw-trash-12").await;
    let t = token(&app, "trash@example.com", "pw-trash-12").await;
    let admin = Some("test-admin");
    let (_, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(v["trash_days"], 0);

    let mut ids = Vec::new();
    for name in ["old", "recent", "kept"] {
        let (id, body) = new_item((&c.vault_id, &c.vault_key), name);
        let (s, _) = call(&app, Method::POST, "/api/items", Some(&t), body).await;
        assert_eq!(s, StatusCode::OK);
        ids.push(id);
    }
    for id in &ids[..2] {
        let (s, _) = call(
            &app,
            Method::DELETE,
            &format!("/api/items/{id}"),
            Some(&t),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }
    let day = 86_400;
    for (id, days_ago) in [(&ids[0], 10), (&ids[1], 1)] {
        sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
            .bind(crate::db::now() - days_ago * day)
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
    }
    assert_eq!(
        crate::vault::purge_trash(&state).await.unwrap(),
        0,
        "0 keeps the trash forever"
    );

    let settings = |days: Option<i64>| {
        let mut b = json!({ "log_level": "info", "icons": true, "signups_verify": false });
        if let Some(d) = days {
            b["trash_days"] = d.into();
        }
        b
    };
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        settings(Some(99_999)),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        settings(Some(7)),
    )
    .await;
    assert_eq!((s, &v["trash_days"]), (StatusCode::OK, &json!(7)), "{v}");

    let before = rev_of(&app, &t).await;
    let cursor = synced(&app, &t).await["cursor"].clone();
    assert_eq!(crate::vault::purge_trash(&state).await.unwrap(), 1);
    assert_eq!(
        delta(&app, &t, &cursor, "").await["deleted"],
        json!([{ "id": ids[0], "vault_id": c.vault_id }]),
        "apps that sync changes only learn it from a tombstone"
    );
    let sync = synced(&app, &t).await;
    assert!(
        item_in(&sync, &ids[0]).is_none(),
        "10 days in the trash: gone"
    );
    assert!(item_in(&sync, &ids[1]).is_some(), "1 day: kept");
    assert!(item_in(&sync, &ids[2]).is_some());
    assert!(
        sync["revision"].as_i64().unwrap() > before,
        "clients re-sync"
    );

    // Older admin pages don't send it: unchanged.
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        settings(None),
    )
    .await;
    assert_eq!((s, &v["trash_days"]), (StatusCode::OK, &json!(7)));
    let (_, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(v["trash_days"], 7);
}

/// A database on disk for tests that reopen it (SQLite), or the test's
/// PostgreSQL database.
fn on_disk(config: &mut Config) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("passauth-test-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_err() {
        config.database_url = format!("sqlite://{}/passauth.db?mode=rwc", dir.display());
    }
    dir
}

#[tokio::test]
async fn a_database_from_a_newer_server_is_refused() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config.clone()).await.unwrap();
    sqlx::query("INSERT INTO schema_version (version) VALUES (99)")
        .execute(&state.db)
        .await
        .unwrap();
    state.db.close().await;
    drop(state);
    let err = match App::new(config).await {
        Ok(_) => panic!("a newer schema must not start"),
        Err(e) => format!("{e:#}"),
    };
    assert!(err.contains("newer PassAuth server"), "{err}");
    assert!(err.contains("schema version 99"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn backup_writes_a_copy_of_the_sqlite_database() {
    let err = crate::db::backup(
        "postgres://db/passauth",
        None,
        std::path::Path::new("/nonexistent/backup.db"),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("pg_dump"), "{err:#}");
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_ok() {
        return;
    }
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let url = config.database_url.clone();
    let app = crate::router(App::new(config).await.unwrap());
    register(&app, "backup@example.com", "pw-backup-12").await;

    let target = dir.join("backup.db");
    let done = crate::db::backup(&url, None, &target).await.unwrap();
    assert!(done.size > 0);
    assert!(done.attachments.is_none(), "no attachments, no folder");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "only the server's user may read it");
    }
    let copy = crate::db::connect(&format!("sqlite://{}", target.display()), 1)
        .await
        .unwrap();
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&copy)
        .await
        .unwrap();
    assert_eq!(users, 1);
    // The copy leaves the sync generation out: restored, it makes a new one and
    // every app's cursor from the newer database is ignored.
    let generation: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM server_secrets WHERE name = 'sync_generation'")
            .fetch_one(&copy)
            .await
            .unwrap();
    assert_eq!(generation, 0);
    copy.close().await;
    assert!(
        crate::db::backup(&url, None, &target).await.is_err(),
        "an existing file is never overwritten"
    );
    let missing = format!("sqlite://{}/missing.db?mode=rwc", dir.display());
    let err = crate::db::backup(&missing, None, &dir.join("other.db"))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("no database"), "{err:#}");
    assert!(
        !dir.join("missing.db").exists() && !dir.join("other.db").exists(),
        "nothing is created"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn import_trash_restore_and_purge() {
    let app = app().await;
    let c = register(&app, "flow@example.com", "pw-flow-123").await;
    register(&app, "flow-b@example.com", "pw-flowb-12").await;
    let t = token(&app, "flow@example.com", "pw-flow-123").await;
    let tb = token(&app, "flow-b@example.com", "pw-flowb-12").await;
    let mine = (c.vault_id.as_str(), &c.vault_key);
    let items: Vec<(String, Value)> = ["a", "b", "c"].iter().map(|n| new_item(mine, n)).collect();
    let bodies: Vec<Value> = items.iter().map(|(_, b)| b.clone()).collect();
    let import = |token: &str, items: Value| {
        let (app, token) = (app.clone(), token.to_owned());
        async move {
            call(
                &app,
                Method::POST,
                "/api/items/import",
                Some(&token),
                json!({ "items": items }),
            )
            .await
        }
    };

    // Refused before anything is written: someone else's vault, too many items, a bad id.
    assert_eq!(import(&tb, json!(bodies)).await.0, StatusCode::NOT_FOUND);
    let too_many: Vec<Value> = (0..=10_000).map(|_| bodies[0].clone()).collect();
    assert_eq!(import(&t, json!(too_many)).await.0, StatusCode::BAD_REQUEST);
    let mut bad = bodies.clone();
    bad[1]["id"] = json!("not-a-uuid");
    assert_eq!(import(&t, json!(bad)).await.0, StatusCode::BAD_REQUEST);
    assert!(
        synced(&app, &t).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let (s, v) = import(&t, json!(bodies)).await;
    assert_eq!((s, &v["imported"]), (StatusCode::OK, &json!(3)), "{v}");
    assert_eq!(synced(&app, &t).await["items"].as_array().unwrap().len(), 3);

    let a = &items[0].0;
    let path = format!("/api/items/{a}");
    let (s, v) = call(&app, Method::DELETE, &path, Some(&t), json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(item_in(&synced(&app, &t).await, a).unwrap()["deleted_at"].is_i64());
    let (s, v) = call(
        &app,
        Method::POST,
        &format!("{path}/restore"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(item_in(&synced(&app, &t).await, a).unwrap()["deleted_at"].is_null());
    // Not a member: the item doesn't exist for them.
    let (s, _) = call(&app, Method::DELETE, &path, Some(&tb), json!(null)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let before = rev_of(&app, &t).await;
    let permanent = format!("{path}/permanent");
    let (s, v) = call(&app, Method::DELETE, &permanent, Some(&t), json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["revision"].as_i64().unwrap() > before);
    let sync = synced(&app, &t).await;
    assert!(item_in(&sync, a).is_none());
    assert_eq!(sync["items"].as_array().unwrap().len(), 2);
    let (s, _) = call(&app, Method::DELETE, &permanent, Some(&t), json!(null)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("{path}/restore"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn items_move_between_vaults_in_both_directions() {
    let app = app().await;
    let c = register(&app, "move@example.com", "pw-move-123").await;
    let bob = register(&app, "move-b@example.com", "pw-moveb-12").await;
    let t = token(&app, "move@example.com", "pw-move-123").await;
    let tb = token(&app, "move-b@example.com", "pw-moveb-12").await;
    let (v2, k2) = new_vault(&app, &c, &t).await;
    let v1 = c.vault_id.as_str();
    let (x, body) = new_item((v1, &c.vault_key), "x");
    let (s, _) = call(&app, Method::POST, "/api/items", Some(&t), body).await;
    assert_eq!(s, StatusCode::OK);
    let path = format!("/api/items/{x}");
    let move_to = |vault: (&str, &SymmetricKey), revision: &Value| {
        let mut b = item_body(&x, vault, "x");
        b["revision"] = revision.clone();
        b
    };

    // Personal vault → second vault → back.
    for vault in [(v2.as_str(), &k2), (v1, &c.vault_key)] {
        let sync = synced(&app, &t).await;
        let rev = &item_in(&sync, &x).unwrap()["revision"];
        let (s, v) = call(&app, Method::PUT, &path, Some(&t), move_to(vault, rev)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(
            item_in(&synced(&app, &t).await, &x).unwrap()["vault_id"],
            vault.0
        );
    }

    // Into, or out of, a vault the user can only read: refused, nothing moves.
    let (s, _) = share(&app, &bob, &tb, "move@example.com", "read").await;
    assert_eq!(s, StatusCode::OK);
    accept(&app, &t, &bob.vault_id).await;
    let sync = synced(&app, &t).await;
    let rev = item_in(&sync, &x).unwrap()["revision"].clone();
    let (s, _) = call(
        &app,
        Method::PUT,
        &path,
        Some(&t),
        move_to((&bob.vault_id, &bob.vault_key), &rev),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        item_in(&synced(&app, &t).await, &x).unwrap()["vault_id"],
        v1
    );
    let (y, ybody) = new_item((&bob.vault_id, &bob.vault_key), "y");
    let (s, _) = call(&app, Method::POST, "/api/items", Some(&tb), ybody).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        Method::PUT,
        &format!("/api/items/{y}"),
        Some(&t),
        item_body(&y, (v1, &c.vault_key), "y"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        item_in(&synced(&app, &tb).await, &y).unwrap()["vault_id"],
        bob.vault_id.as_str()
    );
}

#[tokio::test]
async fn deleting_a_vault_removes_it_for_every_member() {
    let app = app().await;
    let alice = register(&app, "vdel-a@example.com", "pw-alice-1").await;
    register(&app, "vdel-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "vdel-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "vdel-b@example.com", "pw-bobby-1").await;
    let (v2, k2) = new_vault(&app, &alice, &ta).await;
    let (s, _) = share_vault(&app, (&v2, &k2), &ta, "vdel-b@example.com", "admin", None).await;
    assert_eq!(s, StatusCode::OK);
    accept(&app, &tb, &v2).await;
    let (x, body) = new_item((&v2, &k2), "shared");
    let (s, _) = call(&app, Method::POST, "/api/items", Some(&ta), body).await;
    assert_eq!(s, StatusCode::OK);
    let before = rev_of(&app, &tb).await;

    let path = format!("/api/vaults/{v2}");
    let (s, _) = call(&app, Method::DELETE, &path, Some(&tb), json!(null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "only the owner deletes a vault");
    let (s, v) = call(&app, Method::DELETE, &path, Some(&ta), json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let sync = synced(&app, &tb).await;
    assert!(vault_in(&sync, &v2).is_none());
    assert!(item_in(&sync, &x).is_none());
    assert!(
        sync["revision"].as_i64().unwrap() > before,
        "members re-sync"
    );

    let (s, v) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}", alice.vault_id),
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("last_vault"))
    );
    assert_eq!(v["message"], "you can't delete your last vault");
    let ghost = uuid::Uuid::new_v4();
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{ghost}"),
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn changing_the_master_password_signs_out_the_other_sessions() {
    let app = app().await;
    register(&app, "pw@example.com", "old-password-1").await;
    let (_, l1) = login(&app, "pw@example.com", "old-password-1", "d1").await;
    let (_, l2) = login(&app, "pw@example.com", "old-password-1", "d2").await;
    let t1 = l1["access_token"].as_str().unwrap();
    let bundle: AccountBundle = serde_json::from_value(l1["bundle"].clone()).unwrap();

    // A new password: new KDF salt and OPAQUE registration; the keys stay.
    let kdf = KdfParams {
        salt: b64(&[7; 16]),
        ..fast_kdf()
    };
    let master =
        derive_master_keys("new-password-2", None, &bundle.account_id, &kdf, false).unwrap();
    let start = opaque::register_start(&master.login).unwrap();
    let (s, resp) = call(
        &app,
        Method::POST,
        "/api/account/keys/start",
        Some(t1),
        json!({ "message": start.message }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{resp}");
    let upload = opaque::register_finish(
        &start.state,
        &master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let finish = |bundle: &AccountBundle| json!({ "upload": upload, "bundle": bundle });
    let new_bundle = AccountBundle {
        kdf,
        ..bundle.clone()
    };

    let (s, v) = call(
        &app,
        Method::POST,
        "/api/account/keys/finish",
        Some(t1),
        finish(&new_bundle),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    assert_eq!(v["message"], "reauth_required");
    let reauth = reauth_token(&app, "pw@example.com", "old-password-1", t1).await;
    let swapped = AccountBundle {
        public_key: "c3dhcHBlZA".into(),
        ..new_bundle.clone()
    };
    let (s, _) = call_with(
        &app,
        Method::POST,
        "/api/account/keys/finish",
        Some(t1),
        &[("x-reauth-token", &reauth)],
        finish(&swapped),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "only the password wrapping may change"
    );
    let reauth = reauth_token(&app, "pw@example.com", "old-password-1", t1).await;
    let (s, v) = call_with(
        &app,
        Method::POST,
        "/api/account/keys/finish",
        Some(t1),
        &[("x-reauth-token", &reauth)],
        finish(&new_bundle),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // This device stays signed in; the other one is out.
    let (s, _) = call(&app, Method::GET, "/api/account", Some(t1), json!(null)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": l2["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        login(&app, "pw@example.com", "old-password-1", "d3")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (s, l) = login(&app, "pw@example.com", "new-password-2", "d3").await;
    assert_eq!(s, StatusCode::OK, "{l}");
    assert_eq!(l["bundle"]["kdf"]["salt"], b64(&[7; 16]));
}

#[tokio::test]
async fn errors_carry_a_code_and_the_request_id() {
    let (app, state) = app_with_state().await;
    register(&app, "codes@example.com", "pw-codes-12").await;
    let t = token(&app, "codes@example.com", "pw-codes-12").await;

    let (s, v) = call(&app, Method::DELETE, "/api/account", Some(&t), json!(null)).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("reauth_required"))
    );
    assert_eq!(
        v["message"], "reauth_required",
        "older clients compare the message"
    );

    sqlx::query("UPDATE users SET email_verified = 0")
        .execute(&state.db)
        .await
        .unwrap();
    state
        .signups_verify
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let (s, v) = login(&app, "codes@example.com", "pw-codes-12", "d2").await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("email_not_verified"))
    );
    assert_eq!(v["message"], "email_not_verified");

    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/verify-email",
        None,
        json!({ "token": "nope" }),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("expired"))
    );
    assert_eq!(v["message"], "invalid or expired link");

    // Request ids: made by the server, or kept from a proxy when well-formed.
    let get = |id: Option<&str>| {
        let mut req = Request::get("/api/nope");
        if let Some(id) = id {
            req = req.header("x-request-id", id);
        }
        let app = app.clone();
        let req = req.body(Body::empty()).unwrap();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let header = resp.headers()["x-request-id"].to_str().unwrap().to_owned();
            let body: Value =
                serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            (header, body)
        }
    };
    let (id, body) = get(None).await;
    assert_eq!(id.len(), 32);
    assert_eq!(body["request_id"], id.as_str());
    assert_eq!(body["error"], "not_found");
    let (id, body) = get(Some("edge-7f3a.1")).await;
    assert_eq!(
        (id.as_str(), &body["request_id"]),
        ("edge-7f3a.1", &json!("edge-7f3a.1"))
    );
    let long = "x".repeat(65);
    let (id, _) = get(Some(&long)).await;
    assert_ne!(id, long, "an unusable id is replaced");
    // Axum's own rejections (bad JSON) carry it too.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/auth/prelogin")
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = resp.headers()["x-request-id"].to_str().unwrap().to_owned();
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        (&body["error"], &body["request_id"]),
        (&json!("bad_request"), &json!(id))
    );
}

#[test]
fn a_panicking_handler_answers_500_json() {
    let resp = crate::panic_response(Box::new("boom"));
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(resp.headers()["content-type"], "application/json");
}

#[test]
fn new_device_alert_links_to_the_session_list() {
    let device = crate::state::DeviceInfo {
        id: "d".into(),
        name: "Phone".into(),
        kind: "ios".into(),
    };
    let mail = crate::auth::new_device_alert("https://vault.example.com", &device);
    assert_eq!(
        mail.action.unwrap(),
        (
            "Review sessions".to_owned(),
            "https://vault.example.com/settings/sessions".to_owned()
        )
    );
}

#[tokio::test]
async fn avatar_is_stored_sealed_and_versioned_in_sync() {
    let app = app().await;
    register(&app, "me@example.com", "pw-me-12345").await;
    let t = token(&app, "me@example.com", "pw-me-12345").await;
    assert_eq!(synced(&app, &t).await["user"]["avatar_seq"], 0);
    let (s, v) = call(
        &app,
        Method::GET,
        "/api/account/avatar",
        Some(&t),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["avatar"].is_null());
    let r0 = rev_of(&app, &t).await;
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/account/avatar",
        Some(&t),
        json!({ "avatar": "c2VhbGVk" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["avatar_seq"], 1);
    let sync = synced(&app, &t).await;
    assert!(sync["revision"].as_i64().unwrap() > r0);
    assert_eq!(sync["user"]["avatar_seq"], 1);
    let (_, v) = call(
        &app,
        Method::GET,
        "/api/account/avatar",
        Some(&t),
        json!({}),
    )
    .await;
    assert_eq!(v["avatar"], "c2VhbGVk");
    // Only base64url, not empty, not too large.
    for bad in [
        "",
        "not base64!",
        &"A".repeat(400_000),
        &"A".repeat(350_001),
    ] {
        let (s, _) = call(
            &app,
            Method::PUT,
            "/api/account/avatar",
            Some(&t),
            json!({ "avatar": bad }),
        )
        .await;
        assert!(
            matches!(s, StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE),
            "{}",
            bad.len()
        );
    }
    // Review fix: a sealed picture is larger than the general body limit (64 KiB); the
    // route takes one up to its own limit, the largest an app seals (256 KiB of image
    // is 349,580 characters) included.
    let mut seq = 1;
    for size in [70_000, 300_000, 349_580, 350_000] {
        let big = "A".repeat(size);
        let (s, v) = call(
            &app,
            Method::PUT,
            "/api/account/avatar",
            Some(&t),
            json!({ "avatar": big }),
        )
        .await;
        seq += 1;
        assert_eq!(
            (s, &v["avatar_seq"]),
            (StatusCode::OK, &json!(seq)),
            "{size}"
        );
        let (_, v) = call(
            &app,
            Method::GET,
            "/api/account/avatar",
            Some(&t),
            json!(null),
        )
        .await;
        assert_eq!(v["avatar"].as_str().map(str::len), Some(size));
    }
    let (s, v) = call(
        &app,
        Method::DELETE,
        "/api/account/avatar",
        Some(&t),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["avatar_seq"], seq + 1);
    let (_, v) = call(
        &app,
        Method::GET,
        "/api/account/avatar",
        Some(&t),
        json!({}),
    )
    .await;
    assert!(v["avatar"].is_null());
    assert_eq!(v["avatar_seq"], seq + 1);
    let (s, _) = call(&app, Method::GET, "/api/account/avatar", None, json!({})).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn profile_and_email_changes_reach_other_devices() {
    let (app, state) = app_with_state().await;
    register(&app, "me@example.com", "pw-me-12345").await;
    let t = token(&app, "me@example.com", "pw-me-12345").await;
    let r0 = rev_of(&app, &t).await;
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/account/profile",
        Some(&t),
        json!({ "name": "New name" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let sync = synced(&app, &t).await;
    assert!(sync["revision"].as_i64().unwrap() > r0);
    assert_eq!(sync["user"]["name"], "New name");

    // Confirming the email from the verification link.
    let r1 = sync["revision"].as_i64().unwrap();
    let me = user_id(&app, &t).await;
    sqlx::query("UPDATE users SET email_verified = 0")
        .execute(&state.db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO email_tokens (id, user_id, purpose, token_hash, attempts, expires_at) VALUES ($1, $2, 'verify', $3, 0, $4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&me)
        .bind(crate::state::hash_token("link-token"))
        .bind(crate::db::now() + 3600)
        .execute(&state.db)
        .await
        .unwrap();
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/verify-email",
        None,
        json!({ "token": "link-token" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let sync = synced(&app, &t).await;
    assert!(sync["revision"].as_i64().unwrap() > r1);
    assert_eq!(sync["user"]["email_verified"], true);
}

#[tokio::test]
async fn sync_is_compressed_when_the_client_asks() {
    use std::io::Read;
    let app = app().await;
    let c = register(&app, "zip@example.com", "pw-zip-1234").await;
    let t = token(&app, "zip@example.com", "pw-zip-1234").await;
    let (_, body) = new_item((&c.vault_id, &c.vault_key), "zip");
    call(&app, Method::POST, "/api/items", Some(&t), body).await;
    let send = |method: Method, path: &str, token: Option<&str>, encoding: &str, body: Value| {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("accept-encoding", encoding)
            .header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = req.body(Body::from(body.to_string())).unwrap();
        app.clone().oneshot(req)
    };

    let resp = send(Method::GET, "/api/sync", Some(&t), "gzip", json!(null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-encoding"], "gzip");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .unwrap();
    let sync: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(sync["vaults"][0]["key_epoch"], 0);
    assert_eq!(sync["items"].as_array().unwrap().len(), 1);
    let resp = send(Method::GET, "/api/sync", Some(&t), "br", json!(null))
        .await
        .unwrap();
    assert_eq!(resp.headers()["content-encoding"], "br");

    // Never on the sign-in routes, never for errors.
    let resp = send(
        Method::POST,
        "/api/auth/prelogin",
        None,
        "gzip, br",
        json!({ "email": "zip@example.com" }),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("content-encoding").is_none());
    let resp = send(Method::GET, "/api/sync", None, "gzip, br", json!(null))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(resp.headers().get("content-encoding").is_none());
}

// --------------------------------------------------------------- WebSocket

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The router on a real port, for WebSocket clients.
async fn serve(state: AppState) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service =
        crate::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
    addr
}

async fn socket(addr: std::net::SocketAddr, token: &str) -> Socket {
    socket_with_origin(addr, token).await.0
}

/// A live-sync socket after its `{"type":"hello"}`, and the origin the hello gave.
async fn socket_with_origin(addr: std::net::SocketAddr, token: &str) -> (Socket, String) {
    let url = format!("ws://{addr}/api/ws?access_token={token}");
    let mut ws = tokio_tungstenite::connect_async(url).await.unwrap().0;
    let hello = next_message(&mut ws).await.expect("a hello first");
    assert_eq!(hello["type"], "hello", "{hello}");
    let origin = hello["origin"].as_str().unwrap().to_owned();
    assert_eq!(hello, json!({ "type": "hello", "origin": origin }));
    (ws, origin)
}

/// The next message as JSON, or `None` once the server closed the socket.
async fn next_message(ws: &mut Socket) -> Option<Value> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    loop {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("the server answers in time");
        match frame {
            Some(Ok(Message::Text(text))) => {
                return Some(serde_json::from_str(text.as_str()).unwrap());
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_)) | Err(_)) | None => return None,
            Some(Ok(other)) => panic!("unexpected frame {other:?}"),
        }
    }
}

#[tokio::test]
async fn live_sync_reaches_members_and_signed_out_sockets_close() {
    let (app, state) = app_with_state().await;
    let addr = serve(state).await;
    let alice = register(&app, "ws-a@example.com", "pw-alice-1").await;
    register(&app, "ws-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "ws-a@example.com", "pw-alice-1").await;
    assert_eq!(
        share(&app, &alice, &ta, "ws-b@example.com", "read").await.0,
        StatusCode::OK
    );
    let mut bob = Vec::new();
    for device in ["b1", "b2", "b3"] {
        let (_, l) = login(&app, "ws-b@example.com", "pw-bobby-1", device).await;
        bob.push(l["access_token"].as_str().unwrap().to_owned());
    }
    accept(&app, &bob[0], &alice.vault_id).await;
    let mut ws1 = socket(addr, &bob[0]).await;
    let mut ws2 = socket(addr, &bob[1]).await;
    let save = || {
        let app = app.clone();
        let body = new_item((&alice.vault_id, &alice.vault_key), "shared").1;
        let ta = ta.clone();
        async move {
            let (s, v) = call(&app, Method::POST, "/api/items", Some(&ta), body).await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };

    // Alice saves into the shared vault: both of Bob's sockets hear about it,
    // with the vault's new sequence number and the origin of Alice's session.
    save().await;
    let (_, now) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&bob[0]),
        json!(null),
    )
    .await;
    let shared = json!({ &alice.vault_id: now["vaults"][&alice.vault_id] });
    for ws in [&mut ws1, &mut ws2] {
        let msg = next_message(ws).await.unwrap();
        assert_eq!(
            (&msg["type"], &msg["revision"], &msg["vaults"]),
            (&json!("sync"), &now["revision"], &shared),
            "{msg}"
        );
        assert!(msg["origin"].is_string(), "{msg}");
    }

    // Session 1 signed out from session 2: only socket 1 hears it, at once, and closes.
    let (_, first) = call(
        &app,
        Method::GET,
        "/api/account/sessions",
        Some(&bob[0]),
        json!(null),
    )
    .await;
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!(
            "/api/account/sessions/{}",
            first["current"].as_str().unwrap()
        ),
        Some(&bob[1]),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        next_message(&mut ws1).await.unwrap(),
        json!({ "type": "logout" })
    );
    assert!(
        next_message(&mut ws1).await.is_none(),
        "and the socket closes"
    );
    save().await;
    assert_eq!(next_message(&mut ws2).await.unwrap()["type"], "sync");

    // "Sign out other sessions" from session 3 reaches socket 2, not socket 3.
    let mut ws3 = socket(addr, &bob[2]).await;
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/account/sessions/revoke-others",
        Some(&bob[2]),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        next_message(&mut ws2).await.unwrap(),
        json!({ "type": "logout" })
    );
    assert!(next_message(&mut ws2).await.is_none());

    // Signing out closes the session's own socket too.
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/logout",
        Some(&bob[2]),
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        next_message(&mut ws3).await.unwrap(),
        json!({ "type": "logout" })
    );
}

#[tokio::test]
async fn oversized_websocket_messages_close_the_socket() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let (app, state) = app_with_state().await;
    let addr = serve(state).await;
    register(&app, "big@example.com", "pw-big-1234").await;
    let t = token(&app, "big@example.com", "pw-big-1234").await;
    let mut ws = socket(addr, &t).await;
    // Small messages are fine: the socket keeps delivering.
    ws.send(Message::text("hello")).await.unwrap();
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/account/profile",
        Some(&t),
        json!({ "name": "Big" }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(next_message(&mut ws).await.unwrap()["type"], "sync");
    ws.send(Message::text("x".repeat(crate::ws::MAX_INCOMING + 1)))
        .await
        .unwrap();
    assert!(
        next_message(&mut ws).await.is_none(),
        "the server closes the socket"
    );
}

/// Moves in both directions between two shared vaults at once: every write
/// locks its vaults (and then the members' rows) in the same order, so none of
/// them can deadlock. Needs a pool with several connections (file SQLite here,
/// a real database in the PostgreSQL CI job).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_moves_between_two_vaults_never_fail() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let app = crate::router(App::new(config).await.unwrap());
    let alice = register(&app, "busy-a@example.com", "pw-alice-1").await;
    register(&app, "busy-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "busy-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "busy-b@example.com", "pw-bobby-1").await;
    let (v2, k2) = new_vault(&app, &alice, &ta).await;
    let vaults = [(alice.vault_id.clone(), alice.vault_key.clone()), (v2, k2)];
    for (id, key) in &vaults {
        let (s, v) = share_vault(&app, (id, key), &ta, "busy-b@example.com", "write", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        accept(&app, &tb, id).await;
    }
    let tasks: Vec<_> = (0..8)
        .map(|n| {
            let (app, ta, vaults) = (app.clone(), ta.clone(), vaults.clone());
            tokio::spawn(async move {
                let (from, to) = (&vaults[n % 2], &vaults[(n + 1) % 2]);
                let (id, body) = new_item((&from.0, &from.1), "busy");
                let (s, v) = call(&app, Method::POST, "/api/items", Some(&ta), body).await;
                assert_eq!(s, StatusCode::OK, "{v}");
                let mut revision = v["revision"].clone();
                for round in 0..6 {
                    let target = if round % 2 == 0 { to } else { from };
                    let mut b = item_body(&id, (&target.0, &target.1), "busy");
                    b["revision"] = revision.clone();
                    let (s, v) =
                        call(&app, Method::PUT, &format!("/api/items/{id}"), Some(&ta), b).await;
                    assert_eq!(s, StatusCode::OK, "round {round}: {v}");
                    revision = v["revision"].clone();
                }
            })
        })
        .collect();
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(
        synced(&app, &ta).await["items"].as_array().unwrap().len(),
        8
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// -------------------------------------------------------------- delta sync

/// `/api/sync?since=<cursor><extra>` (e.g. `extra` = `&trash=summary`).
async fn delta(app: &Router, token: &str, cursor: &Value, extra: &str) -> Value {
    let path = format!("/api/sync?since={}{extra}", cursor.as_str().unwrap());
    let (s, v) = call(app, Method::GET, &path, Some(token), json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// The ids in a sync response's `items`, sorted.
fn ids(sync: &Value) -> Vec<String> {
    sorted(
        sync["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_owned())
            .collect(),
    )
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn seq_of(sync: &Value, vault: &str) -> i64 {
    vault_in(sync, vault).unwrap()["seq"].as_i64().unwrap()
}

/// `call` that must succeed; returns the body.
async fn ok(app: &Router, method: Method, path: &str, token: &str, body: Value) -> Value {
    let (s, v) = call(app, method, path, Some(token), body).await;
    assert_eq!(s, StatusCode::OK, "{path}: {v}");
    v
}

#[tokio::test]
async fn delta_sync_sends_only_what_changed() {
    let app = app().await;
    let c = register(&app, "delta@example.com", "pw-delta-123").await;
    let t = token(&app, "delta@example.com", "pw-delta-123").await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let (b_id, b_key) = new_vault(&app, &c, &t).await;
    let b = (b_id.as_str(), &b_key);

    // Every write answers with the vault's new sequence number.
    let (x, body) = new_item(a, "x");
    let r = ok(&app, Method::POST, "/api/items", &t, body).await;
    assert_eq!(r["vault_seq"], 1, "the vault's first write: {r}");
    let (y, body) = new_item(a, "y");
    assert_eq!(
        ok(&app, Method::POST, "/api/items", &t, body).await["vault_seq"],
        2
    );

    // A full sync is today's response plus a cursor and each vault's number.
    let full = synced(&app, &t).await;
    for key in ["delta", "deleted", "reset"] {
        assert!(full.get(key).is_none(), "{key} is only in a delta");
    }
    assert_eq!((seq_of(&full, a.0), seq_of(&full, b.0)), (2, 0));
    let c0 = full["cursor"].clone();

    // Nothing changed since: an empty delta, with every vault's header.
    let d = delta(&app, &t, &c0, "").await;
    assert_eq!(d["delta"], true);
    assert_eq!(
        (&d["items"], &d["deleted"], &d["reset"]),
        (&json!([]), &json!([]), &json!([]))
    );
    assert_eq!(d["vaults"], full["vaults"]);
    assert_eq!(
        (&d["user"], &d["bundle"], &d["revision"]),
        (&full["user"], &full["bundle"], &full["revision"])
    );
    assert_eq!(d["cursor"], c0, "nothing changed: the same cursor");

    // An edit, a trash and a new item in the other vault: exactly those three.
    let mut edit = item_body(&x, a, "x2");
    edit["revision"] = item_in(&full, &x).unwrap()["revision"].clone();
    let r = ok(&app, Method::PUT, &format!("/api/items/{x}"), &t, edit).await;
    assert_eq!(r["vault_seq"], 3);
    let r = ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{y}"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(r["vault_seq"], 4);
    let (z, body) = new_item(b, "z");
    assert_eq!(
        ok(&app, Method::POST, "/api/items", &t, body).await["vault_seq"],
        1
    );
    let d1 = delta(&app, &t, &c0, "").await;
    assert_eq!(ids(&d1), sorted(vec![x.clone(), y.clone(), z.clone()]));
    assert_eq!((&d1["deleted"], &d1["reset"]), (&json!([]), &json!([])));
    assert!(item_in(&d1, &y).unwrap()["deleted_at"].is_i64());
    assert_eq!((seq_of(&d1, a.0), seq_of(&d1, b.0)), (4, 1));
    let now = synced(&app, &t).await;
    assert_eq!(item_in(&d1, &x), item_in(&now, &x), "as a full sync has it");

    // trash=summary: the item in the trash comes without its key and data.
    let d = delta(&app, &t, &c0, "&trash=summary").await;
    let trashed = item_in(&d, &y).unwrap();
    assert!(
        trashed.get("item_key").is_none() && trashed.get("data").is_none(),
        "{trashed}"
    );
    assert_eq!(
        (&trashed["revision"], &trashed["deleted_at"]),
        (
            &item_in(&d1, &y).unwrap()["revision"],
            &item_in(&d1, &y).unwrap()["deleted_at"]
        )
    );
    assert!(item_in(&d, &x).unwrap()["data"].is_string());
    let (_, s) = call(
        &app,
        Method::GET,
        "/api/sync?trash=summary",
        Some(&t),
        json!(null),
    )
    .await;
    assert!(item_in(&s, &y).unwrap().get("data").is_none());
    assert!(item_in(&s, &z).unwrap()["item_key"].is_string());

    // y back from the trash, x deleted for good: y, and a tombstone for x.
    let c1 = d1["cursor"].clone();
    let r = ok(
        &app,
        Method::POST,
        &format!("/api/items/{y}/restore"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(r["vault_seq"], 5);
    let r = ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{x}/permanent"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(r["vault_seq"], 6);
    let d2 = delta(&app, &t, &c1, "").await;
    assert_eq!(ids(&d2), vec![y.clone()]);
    assert!(item_in(&d2, &y).unwrap()["deleted_at"].is_null());
    assert_eq!(d2["deleted"], json!([{ "id": x, "vault_id": a.0 }]));

    // y moves A → B: in B, gone from A; a move takes a number in both vaults.
    let c2 = d2["cursor"].clone();
    let r = ok(
        &app,
        Method::PUT,
        &format!("/api/items/{y}"),
        &t,
        item_body(&y, b, "y"),
    )
    .await;
    assert_eq!(r["vault_seq"], 2, "the target vault's number");
    let d3 = delta(&app, &t, &c2, "").await;
    assert_eq!(ids(&d3), vec![y.clone()]);
    assert_eq!(item_in(&d3, &y).unwrap()["vault_id"], b.0);
    assert_eq!(d3["deleted"], json!([{ "id": y, "vault_id": a.0 }]));
    assert_eq!((seq_of(&d3, a.0), seq_of(&d3, b.0)), (7, 2));
    // ...and back B → A: in A again, gone from B (from either cursor).
    let c3 = d3["cursor"].clone();
    let r = ok(
        &app,
        Method::PUT,
        &format!("/api/items/{y}"),
        &t,
        item_body(&y, a, "y"),
    )
    .await;
    assert_eq!(r["vault_seq"], 8);
    for since in [&c2, &c3] {
        let d = delta(&app, &t, since, "").await;
        assert_eq!(ids(&d), vec![y.clone()]);
        assert_eq!(item_in(&d, &y).unwrap()["vault_id"], a.0);
        assert_eq!(d["deleted"], json!([{ "id": y, "vault_id": b.0 }]));
        assert_eq!(d["reset"], json!([]));
    }

    // Imports answer with the vault's number too; a retried one changes nothing.
    let c4 = synced(&app, &t).await["cursor"].clone();
    let batch: Vec<Value> = ["i1", "i2"].iter().map(|n| new_item(b, n).1).collect();
    let r = ok(
        &app,
        Method::POST,
        "/api/items/import",
        &t,
        json!({ "items": batch }),
    )
    .await;
    assert_eq!(
        (&r["imported"], &r["vault_seq"], &r["vault_seqs"]),
        (&json!(2), &json!(4), &json!({ b.0: 4 }))
    );
    let again = ok(
        &app,
        Method::POST,
        "/api/items/import",
        &t,
        json!({ "items": batch }),
    )
    .await;
    assert_eq!(again["vault_seq"], 4, "nothing written: the current number");
    assert_eq!(
        delta(&app, &t, &c4, "").await["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // The cheap poll names every vault's number.
    let (_, r) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&t),
        json!(null),
    )
    .await;
    let last = synced(&app, &t).await;
    assert_eq!(r["revision"], last["revision"]);
    assert_eq!(r["vaults"], json!({ a.0: 8, b.0: 4 }));
}

#[tokio::test]
async fn a_full_sync_keeps_its_shape_for_older_apps() {
    let app = app().await;
    let c = register(&app, "shape@example.com", "pw-shape-123").await;
    let t = token(&app, "shape@example.com", "pw-shape-123").await;
    let (id, body) = new_item((&c.vault_id, &c.vault_key), "shape");
    let created = ok(&app, Method::POST, "/api/items", &t, body).await;
    let keys =
        |v: &Value| -> Vec<String> { sorted(v.as_object().unwrap().keys().cloned().collect()) };
    assert_eq!(
        keys(&created),
        [
            "id",
            "manifest_link",
            "manifest_seq",
            "revision",
            "vault_seq"
        ]
    );
    let full = synced(&app, &t).await;
    assert_eq!(
        keys(&full),
        [
            "bundle",
            "cursor",
            "invitations",
            "items",
            "revision",
            "server_time",
            "trash_days",
            "user",
            "vaults"
        ]
    );
    assert_eq!(
        keys(&full["vaults"][0]),
        [
            "id",
            "key_epoch",
            "key_kind",
            "manifest",
            "manifest_ok",
            "manifest_prev",
            "manifest_seq",
            "member_roster",
            "member_roster_seq",
            "meta",
            "role",
            "rotation_pending",
            "seq",
            "share",
            "wrapped_key"
        ]
    );
    assert_eq!(
        keys(item_in(&full, &id).unwrap()),
        [
            "created_at",
            "data",
            "deleted_at",
            "id",
            "item_key",
            "revision",
            "updated_at",
            "vault_id"
        ]
    );
    assert_eq!(
        keys(&full["user"]),
        [
            "account_wraps_v2",
            "avatar_seq",
            "email",
            "email_verified",
            "id",
            "identity",
            "key_pins_seq",
            "name"
        ]
    );
}

#[tokio::test]
async fn delta_sync_resets_what_a_cursor_cannot_vouch_for() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "reset@example.com", "pw-reset-123").await;
    let t = token(&app, "reset@example.com", "pw-reset-123").await;
    let me = user_id(&app, &t).await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let (b_id, b_key) = new_vault(&app, &c, &t).await;
    let b = (b_id.as_str(), &b_key);
    let mut in_a = Vec::new();
    for name in ["one", "two"] {
        let (id, body) = new_item(a, name);
        ok(&app, Method::POST, "/api/items", &t, body).await;
        in_a.push(id);
    }
    let (in_b, body) = new_item(b, "three");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let full = synced(&app, &t).await;
    let c0 = full["cursor"].clone();

    // Anything that isn't a cursor of this database: the full response, never an error.
    let generation = state.sync_generation.clone();
    let cursor = |vaults: &[(&str, i64, i64)]| {
        json!(crate::vault::Cursor::new(&generation, vaults.iter().copied()).encode())
    };
    let other_db = crate::vault::Cursor::new("another-database", [(a.0, 0, 0)]).encode();
    let mut newer_format = unb64(cursor(&[(a.0, 0, 0)]).as_str().unwrap()).unwrap();
    newer_format[0] = 2;
    for since in [
        String::new(),
        "not-a-cursor".into(),
        b64(&[1, 200]),
        other_db,
        b64(&newer_format),
    ] {
        let (s, v) = call(
            &app,
            Method::GET,
            &format!("/api/sync?since={since}"),
            Some(&t),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert!(v.get("delta").is_none(), "a full response");
        assert_eq!(ids(&v), ids(&full));
        assert_eq!(v["vaults"], full["vaults"]);
    }

    // A replaced vault key: that vault comes back whole, the other doesn't.
    let rotated: Vec<Value> = in_a.iter().map(|id| item_body(id, a, "rotated")).collect();
    let r = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/rotate", a.0),
        &t,
        json!({ "keys": [{ "user_id": me, "wrapped_key": "a2V5", "key_kind": "account" }], "items": rotated, "key_epoch": 0 }),
    )
    .await;
    assert_eq!((&r["key_epoch"], &r["vault_seq"]), (&json!(1), &json!(3)));
    let d = delta(&app, &t, &c0, "").await;
    assert_eq!(d["reset"], json!([a.0]));
    assert_eq!(ids(&d), sorted(in_a.clone()));
    assert_eq!(d["deleted"], json!([]));

    // A cursor older than the vault's horizon (forgotten tombstones): whole again.
    let c1 = d["cursor"].clone();
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{in_b}/permanent"),
        &t,
        json!(null),
    )
    .await;
    sqlx::query("UPDATE vaults SET horizon = seq WHERE id = $1")
        .bind(b.0)
        .execute(&state.db)
        .await
        .unwrap();
    let d = delta(&app, &t, &c1, "").await;
    assert_eq!(d["reset"], json!([b.0]));
    assert_eq!((&d["items"], &d["deleted"]), (&json!([]), &json!([])));

    // Numbers from a newer database (a restored backup): whole; vaults the
    // account doesn't read are ignored, and one the cursor doesn't know is whole.
    let (_, rev) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&t),
        json!(null),
    )
    .await;
    let seq_a = rev["vaults"][a.0].as_i64().unwrap();
    let seq_b = rev["vaults"][b.0].as_i64().unwrap();
    let stranger = "00000000-0000-4000-8000-000000000000";
    let d = delta(
        &app,
        &t,
        &cursor(&[(a.0, seq_a, 1), (b.0, seq_b + 5, 0), (stranger, 1, 0)]),
        "",
    )
    .await;
    assert_eq!(d["reset"], json!([b.0]));
    assert!(vault_in(&d, stranger).is_none());
    let d = delta(&app, &t, &cursor(&[(a.0, seq_a, 1)]), "").await;
    assert_eq!(d["reset"], json!([b.0]));
    let d = delta(&app, &t, &cursor(&[(a.0, seq_a, 1), (b.0, seq_b, 0)]), "").await;
    assert_eq!(
        d["reset"],
        json!([]),
        "a cursor that matches: nothing to send"
    );
    assert_eq!(d["items"], json!([]));
}

#[tokio::test]
async fn delta_sync_follows_membership() {
    let app = app().await;
    let alice = register(&app, "dm-a@example.com", "pw-alice-1").await;
    register(&app, "dm-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "dm-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "dm-b@example.com", "pw-bobby-1").await;
    let shared = (alice.vault_id.as_str(), &alice.vault_key);
    let (x, body) = new_item(shared, "x");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    let c0 = synced(&app, &tb).await["cursor"].clone();

    // Invited: only the invitation, nothing of the vault.
    assert_eq!(
        share(&app, &alice, &ta, "dm-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    let d = delta(&app, &tb, &c0, "").await;
    assert!(vault_in(&d, shared.0).is_none());
    assert_eq!(
        (&d["items"], &d["reset"], &d["invitations"][0]["vault_id"]),
        (&json!([]), &json!([]), &json!(shared.0))
    );

    // Gained on accepting: the vault arrives whole, the invitation is gone.
    accept(&app, &tb, shared.0).await;
    let d = delta(&app, &tb, &c0, "").await;
    assert_eq!(d["reset"], json!([shared.0]));
    assert_eq!(ids(&d), vec![x.clone()]);
    assert_eq!(d["invitations"], json!([]));
    let c1 = d["cursor"].clone();

    // Then its changes come as deltas like any other.
    let (y, body) = new_item(shared, "y");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    let d = delta(&app, &tb, &c1, "").await;
    assert_eq!((ids(&d), &d["reset"]), (vec![y.clone()], &json!([])));
    let c2 = d["cursor"].clone();

    // Lost: missing from `vaults` (the app drops it with its items), nothing else.
    let bob = user_id(&app, &tb).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}/members/{bob}", shared.0),
        &ta,
        json!(null),
    )
    .await;
    let d = delta(&app, &tb, &c2, "").await;
    assert!(vault_in(&d, shared.0).is_none());
    assert_eq!(
        (&d["items"], &d["deleted"], &d["reset"]),
        (&json!([]), &json!([]), &json!([]))
    );
    let c3 = d["cursor"].clone();

    // Added again after a deletion: whole from a cursor that had dropped it, a
    // delta (with the tombstone) from one that still had it.
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{y}/permanent"),
        &ta,
        json!(null),
    )
    .await;
    assert_eq!(
        share(&app, &alice, &ta, "dm-b@example.com", "read").await.0,
        StatusCode::OK
    );
    accept(&app, &tb, shared.0).await;
    let d = delta(&app, &tb, &c3, "").await;
    assert_eq!(
        (ids(&d), &d["reset"]),
        (vec![x.clone()], &json!([shared.0]))
    );
    let d = delta(&app, &tb, &c2, "").await;
    assert_eq!(d["reset"], json!([]));
    assert_eq!(d["deleted"], json!([{ "id": y, "vault_id": shared.0 }]));
}

/// Writers race into one vault while a reader follows with deltas: the numbers
/// are unique and gap-free, and the reader misses nothing (which it would if a
/// write could commit with a lower number than one already seen). Needs a pool
/// with several connections (file SQLite here, a real server with
/// `PASSAUTH_TEST_DATABASE_URL`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_get_increasing_numbers_and_deltas_miss_nothing() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let app = crate::router(App::new(config).await.unwrap());
    let c = register(&app, "race@example.com", "pw-race-1234").await;
    let t = token(&app, "race@example.com", "pw-race-1234").await;
    let vault = (c.vault_id.clone(), c.vault_key.clone());
    let writers: Vec<_> = (0..6)
        .map(|_| {
            let (app, t, vault) = (app.clone(), t.clone(), vault.clone());
            tokio::spawn(async move {
                let mut seqs = Vec::new();
                for _ in 0..8 {
                    let (_, body) = new_item((&vault.0, &vault.1), "race");
                    let r = ok(&app, Method::POST, "/api/items", &t, body).await;
                    seqs.push(r["vault_seq"].as_i64().unwrap());
                }
                seqs
            })
        })
        .collect();
    let reader = {
        let (app, t) = (app.clone(), t.clone());
        tokio::spawn(async move {
            let full = synced(&app, &t).await;
            let mut seen: std::collections::BTreeSet<String> = ids(&full).into_iter().collect();
            let mut cursor = full["cursor"].clone();
            for _ in 0..40 {
                let d = delta(&app, &t, &cursor, "").await;
                seen.extend(ids(&d));
                cursor = d["cursor"].clone();
                tokio::task::yield_now().await;
            }
            (seen, cursor)
        })
    };
    let mut numbers = Vec::new();
    for w in writers {
        numbers.extend(w.await.unwrap());
    }
    let (mut seen, cursor) = reader.await.unwrap();
    seen.extend(ids(&delta(&app, &t, &cursor, "").await));
    numbers.sort_unstable();
    assert_eq!(
        numbers,
        (1..=48).collect::<Vec<i64>>(),
        "one number per write, none shared"
    );
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        ids(&synced(&app, &t).await),
        "following the deltas gave every item"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn old_tombstones_are_forgotten_and_older_cursors_reset() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "tomb@example.com", "pw-tomb-1234").await;
    let t = token(&app, "tomb@example.com", "pw-tomb-1234").await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let mut items = Vec::new();
    for name in ["old", "newer", "kept"] {
        let (id, body) = new_item(a, name);
        ok(&app, Method::POST, "/api/items", &t, body).await;
        items.push(id);
    }
    let purge = |id: &String| {
        let (app, t, path) = (app.clone(), t.clone(), format!("/api/items/{id}/permanent"));
        async move { ok(&app, Method::DELETE, &path, &t, json!(null)).await }
    };
    let c0 = synced(&app, &t).await["cursor"].clone();
    purge(&items[0]).await;
    let c1 = synced(&app, &t).await["cursor"].clone();
    purge(&items[1]).await;
    let day = 86_400;
    for (id, days_ago) in [(&items[0], 100), (&items[1], 10)] {
        sqlx::query("UPDATE item_tombstones SET deleted_at = $1 WHERE item_id = $2")
            .bind(crate::db::now() - days_ago * day)
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
    }
    let horizon = || {
        let db = state.db.clone();
        let vault = a.0.to_owned();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT horizon FROM vaults WHERE id = $1")
                .bind(vault)
                .fetch_one(&db)
                .await
                .unwrap()
        }
    };

    // 90 days by default: the 100-day-old one goes, the horizon moves to it.
    assert_eq!(crate::vault::purge_tombstones(&state).await.unwrap(), 1);
    assert_eq!(horizon().await, 4);
    let d = delta(&app, &t, &c0, "").await;
    assert_eq!(d["reset"], json!([a.0]), "older than the horizon: whole");
    assert_eq!(ids(&d), vec![items[2].clone()]);
    let d = delta(&app, &t, &c1, "").await;
    assert_eq!(d["reset"], json!([]));
    assert_eq!(d["deleted"], json!([{ "id": items[1], "vault_id": a.0 }]));

    // The admin may keep them 7 days at the least.
    let admin = Some("test-admin");
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        json!({ "tombstone_days": 6 }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        admin,
        json!({ "tombstone_days": 7 }),
    )
    .await;
    assert_eq!((s, &v["tombstone_days"]), (StatusCode::OK, &json!(7)));
    assert_eq!(crate::vault::purge_tombstones(&state).await.unwrap(), 1);
    assert_eq!(horizon().await, 5);
    assert_eq!(delta(&app, &t, &c1, "").await["reset"], json!([a.0]));
    assert_eq!(crate::vault::purge_tombstones(&state).await.unwrap(), 0);
}

#[tokio::test]
async fn sync_notices_for_one_account_are_collapsed() {
    use crate::state::{Notice, SyncNotice};
    let (_, state) = app_with_state().await;
    let mut rx = state.subscribe("u1").unwrap();
    let notice = |revision: i64, vault: &str, seq: i64, origin: Option<&str>| {
        let mut n = SyncNotice::new(revision, origin.map(str::to_owned));
        n.vaults.insert(vault.to_owned(), seq);
        n
    };
    let next = |rx: &mut tokio::sync::broadcast::Receiver<Notice>| {
        let got = rx.try_recv();
        match got {
            Ok(Notice::Sync(n)) => n,
            other => panic!("expected a sync notice, got {other:?}"),
        }
    };

    // A burst from one session: one notice, the newest values, its origin.
    state.notify_sync(vec![("u1".into(), notice(10, "va", 1, Some("o1")))]);
    state.notify_sync(vec![
        ("u1".into(), notice(12, "va", 3, Some("o1"))),
        ("nobody".into(), notice(1, "vz", 1, None)),
    ]);
    state.notify_sync(vec![("u1".into(), notice(11, "vb", 2, Some("o1")))]);
    assert!(rx.try_recv().is_err(), "held for the collapse window");
    tokio::time::sleep(crate::state::SYNC_COLLAPSE * 2).await;
    let mut want = notice(12, "va", 3, Some("o1"));
    want.vaults.insert("vb".into(), 2);
    assert_eq!(next(&mut rx), want);
    assert!(rx.try_recv().is_err(), "one message for the burst");

    // Writes from two sessions in one window: no origin, so neither app skips it.
    state.notify_sync(vec![("u1".into(), notice(13, "va", 4, Some("o1")))]);
    state.notify_sync(vec![("u1".into(), notice(14, "va", 5, Some("o2")))]);
    tokio::time::sleep(crate::state::SYNC_COLLAPSE * 2).await;
    assert_eq!(next(&mut rx), notice(14, "va", 5, None));
    assert!(
        state.pending_sync.is_empty(),
        "accounts without sockets aren't collected"
    );
}

/// No text message on `ws` for `ms` milliseconds.
async fn quiet(ws: &mut Socket, ms: u64) -> Vec<Value> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let mut got = Vec::new();
    let until = tokio::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        match tokio::time::timeout_at(until, ws.next()).await {
            Err(_) => return got,
            Ok(Some(Ok(Message::Text(text)))) => {
                got.push(serde_json::from_str(text.as_str()).unwrap());
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(other) => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn live_sync_names_the_writer_and_collapses_bursts() {
    let (app, state) = app_with_state().await;
    let addr = serve(state).await;
    let c = register(&app, "burst@example.com", "pw-burst-123").await;
    let session = |device: &'static str| {
        let app = app.clone();
        async move {
            let (_, l) = login(&app, "burst@example.com", "pw-burst-123", device).await;
            l["access_token"].as_str().unwrap().to_owned()
        }
    };
    let (laptop, phone) = (session("laptop").await, session("phone").await);
    let (mut ws_laptop, o_laptop) = socket_with_origin(addr, &laptop).await;
    let (mut ws_phone, o_phone) = socket_with_origin(addr, &phone).await;
    let (mut ws_laptop2, o_laptop2) = socket_with_origin(addr, &laptop).await;
    assert_ne!(o_laptop, o_phone, "each session has its own origin");
    assert_eq!(
        o_laptop, o_laptop2,
        "the same on each of a session's sockets"
    );

    // A burst of saves on the laptop: fewer messages than saves, the last with
    // the newest values and the laptop's origin, on every socket.
    let mut last = Value::Null;
    for n in 0..5 {
        let (_, body) = new_item((&c.vault_id, &c.vault_key), &format!("burst {n}"));
        last = ok(&app, Method::POST, "/api/items", &laptop, body).await;
    }
    let want = json!({
        "type": "sync",
        "revision": rev_of(&app, &laptop).await,
        "vaults": { &c.vault_id: last["vault_seq"] },
        "origin": o_laptop,
    });
    for ws in [&mut ws_laptop, &mut ws_phone, &mut ws_laptop2] {
        let got = quiet(ws, 900).await;
        assert!(!got.is_empty() && got.len() < 5, "{got:?}");
        assert_eq!(got.last().unwrap(), &want);
    }

    // The phone renames the account: no vault changed, the phone's origin.
    ok(
        &app,
        Method::PUT,
        "/api/account/profile",
        &phone,
        json!({ "name": "Burst" }),
    )
    .await;
    let msg = next_message(&mut ws_laptop).await.unwrap();
    assert_eq!(
        msg,
        json!({ "type": "sync", "revision": rev_of(&app, &phone).await, "vaults": {}, "origin": o_phone })
    );
}

#[test]
fn the_two_step_lockout_alert_links_to_the_session_list() {
    let mail = crate::auth::two_factor_lockout_alert("https://vault.example.com");
    assert_eq!(
        mail.action.unwrap(),
        (
            "Review sessions".to_owned(),
            "https://vault.example.com/settings/sessions".to_owned()
        )
    );
}

// ---------------------------------------------------- quotas and settings

/// Turn on TOTP for the account behind `token`; returns its recovery codes.
/// Turn on an authenticator app for the account of `token` (`email`, `pw`: turning
/// it on needs a reauth token); its recovery codes.
async fn enable_totp(app: &Router, email: &str, pw: &str, token: &str) -> Vec<String> {
    let setup = ok(
        app,
        Method::POST,
        "/api/account/2fa/totp/setup",
        token,
        json!({}),
    )
    .await;
    let totp = Totp::parse(setup["uri"].as_str().unwrap()).unwrap();
    let code = totp.generate(crate::db::now() as u64);
    let reauth = reauth_token(app, email, pw, token).await;
    let (s, en) = call_with(
        app,
        Method::POST,
        "/api/account/2fa/totp/enable",
        Some(token),
        &[("x-reauth-token", &reauth)],
        json!({ "code": code }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{en}");
    serde_json::from_value(en["recovery_codes"].clone()).unwrap()
}

/// `PUT /api/admin/settings`.
async fn admin_set(app: &Router, body: Value) -> (StatusCode, Value) {
    call(
        app,
        Method::PUT,
        "/api/admin/settings",
        Some("test-admin"),
        body,
    )
    .await
}

#[tokio::test]
async fn quotas_stop_growth_of_an_owners_vaults() {
    let app = app().await;
    let alice = register(&app, "q-a@example.com", "pw-alice-1").await;
    let bob = register(&app, "q-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "q-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "q-b@example.com", "pw-bobby-1").await;
    let a = (alice.vault_id.as_str(), &alice.vault_key);
    let set = |b: Value| {
        let app = app.clone();
        async move {
            let (s, v) = admin_set(&app, b).await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };
    let refused = |(s, v): (StatusCode, Value)| {
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(
            (&v["error"], &v["message"]),
            (&json!("quota_exceeded"), &json!("storage limit reached"))
        );
    };
    let post = |token: &str, body: Value| {
        let (app, token) = (app.clone(), token.to_owned());
        async move { call(&app, Method::POST, "/api/items", Some(&token), body).await }
    };

    // Item history has its own test (its versions count too).
    set(json!({ "item_versions_kept": 0 })).await;

    // No limits by default (but for attachments); the account and the admin see
    // the usage.
    let (x, body) = new_item(a, "x");
    let x_bytes =
        (body["key"].as_str().unwrap().len() + body["data"].as_str().unwrap().len()) as i64;
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    let me = ok(&app, Method::GET, "/api/account", &ta, json!(null)).await;
    assert_eq!(
        (&me["usage"], &me["limits"]),
        (
            &json!({ "item_count": 1, "storage_bytes": x_bytes, "attachment_bytes": 0 }),
            &json!({ "max_items": 0, "max_storage_bytes": 0, "max_attachment_bytes": 1024 * 1024 * 1024 })
        )
    );
    let (_, users) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    let row = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "q-a@example.com")
        .unwrap();
    assert_eq!(
        (&row["item_count"], &row["storage_bytes"], &row["items"]),
        (&json!(1), &json!(x_bytes), &json!(1))
    );

    // Two items per user.
    set(json!({ "max_items_per_user": 2 })).await;
    assert_eq!(
        ok(&app, Method::GET, "/api/account", &ta, json!(null)).await["limits"]["max_items"],
        2
    );
    let (y, body) = new_item(a, "y");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    refused(post(&ta, new_item(a, "z").1).await);
    refused(
        call(
            &app,
            Method::POST,
            "/api/items/import",
            Some(&ta),
            json!({ "items": [new_item(a, "z").1] }),
        )
        .await,
    );

    // Bob writing into Alice's vault counts against her; his own vault, him.
    assert_eq!(
        share(&app, &alice, &ta, "q-b@example.com", "write").await.0,
        StatusCode::OK
    );
    accept(&app, &tb, a.0).await;
    refused(post(&tb, new_item(a, "bob's").1).await);
    let (w, body) = new_item((&bob.vault_id, &bob.vault_key), "w");
    ok(&app, Method::POST, "/api/items", &tb, body).await;
    // Moving his item into her vault would grow hers.
    refused(
        call(
            &app,
            Method::PUT,
            &format!("/api/items/{w}"),
            Some(&tb),
            item_body(&w, a, "w"),
        )
        .await,
    );
    // Edits and the trash still work at the limit; the trash still counts.
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        &ta,
        item_body(&x, a, "x2"),
    )
    .await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{y}"),
        &ta,
        json!(null),
    )
    .await;
    refused(post(&ta, new_item(a, "z").1).await);
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{y}/permanent"),
        &ta,
        json!(null),
    )
    .await;
    let (s, v) = post(&ta, new_item(a, "z").1).await;
    assert_eq!(s, StatusCode::OK, "room again after deleting for good: {v}");

    // Storage: 1 MB. Growth past it is refused; shrinking passes even above it.
    set(json!({ "max_items_per_user": 0 })).await;
    let big = |chars: usize| item_body(&x, a, &"x".repeat(chars));
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        &ta,
        big(1_100_000),
    )
    .await;
    set(json!({ "max_storage_mb_per_user": 1 })).await;
    let me = ok(&app, Method::GET, "/api/account", &ta, json!(null)).await;
    assert_eq!(me["limits"]["max_storage_bytes"], 1024 * 1024);
    assert!(me["usage"]["storage_bytes"].as_i64().unwrap() > 1024 * 1024);
    refused(post(&ta, new_item(a, "small").1).await);
    refused(
        call(
            &app,
            Method::PUT,
            &format!("/api/items/{x}"),
            Some(&ta),
            big(1_200_000),
        )
        .await,
    );
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        &ta,
        big(1_000_000),
    )
    .await;
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        &ta,
        item_body(&x, a, "x3"),
    )
    .await;
    let (s, v) = post(&ta, new_item(a, "small").1).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn admin_limits_are_listed_and_range_checked() {
    let app = app().await;
    let admin = Some("test-admin");
    let (s, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for (name, default) in [
        ("trash_days", 0),
        ("tombstone_days", 90),
        ("session_days", 90),
        ("refresh_days", 30),
        ("remember_device_days", 30),
        ("signin_attempts_per_minute", 30),
        ("two_step_attempts_per_hour", 10),
        ("max_import_items", 10_000),
        ("max_item_kib", 2048),
        ("websocket_ping_seconds", 30),
        ("max_items_per_user", 0),
        ("max_storage_mb_per_user", 0),
    ] {
        assert_eq!(v[name], default, "{name}");
        assert_eq!(v["ranges"][name]["default"], default, "{name}");
    }
    assert_eq!(
        v["ranges"]["session_days"],
        json!({ "min": 1, "max": 365, "default": 90 })
    );
    assert_eq!(v["breach_check"], true);

    // Out of range, not a whole number, an unknown name: 400, and nothing changes.
    for bad in [
        json!({ "session_days": 0 }),
        json!({ "session_days": 366 }),
        json!({ "max_item_kib": "64" }),
        json!({ "max_import_items": 1000.5 }),
        json!({ "sessions_days": 30 }),
        json!({ "session_days": 30, "max_import_items": 100 }),
        json!({ "breach_check": "no" }),
    ] {
        let (s, e) = admin_set(&app, bad.clone()).await;
        assert!(s.is_client_error(), "{bad}: {s} {e}");
    }
    let (_, e) = admin_set(&app, json!({ "max_import_items": 100 })).await;
    assert!(
        e["message"].as_str().unwrap().contains("from 500 to 50000"),
        "{e}"
    );
    let (_, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(
        (&v["session_days"], &v["max_import_items"]),
        (&json!(90), &json!(10_000))
    );
    // The whole object from `GET` can go back with a change.
    let (_, mut all) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    all["max_items_per_user"] = json!(100);
    let (s, v) = admin_set(&app, all).await;
    assert_eq!(
        (s, &v["max_items_per_user"]),
        (StatusCode::OK, &json!(100)),
        "{v}"
    );
    // `null` leaves a value as it is; only what was sent changes.
    let (s, v) = admin_set(
        &app,
        json!({ "websocket_ping_seconds": 15, "session_days": null }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            &v["websocket_ping_seconds"],
            &v["session_days"],
            &v["log_level"]
        ),
        (&json!(15), &json!(90), &json!("info"))
    );
}

#[tokio::test]
async fn import_and_item_size_limits_apply_at_once() {
    let app = app().await;
    let c = register(&app, "limits@example.com", "pw-limits-12").await;
    let t = token(&app, "limits@example.com", "pw-limits-12").await;
    let mine = (c.vault_id.as_str(), &c.vault_key);

    assert_eq!(
        admin_set(&app, json!({ "max_import_items": 500 })).await.0,
        StatusCode::OK
    );
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(config["limits"]["max_import_items"], 500);
    let batch: Vec<Value> = (0..501).map(|_| new_item(mine, "i").1).collect();
    let (s, e) = call(
        &app,
        Method::POST,
        "/api/items/import",
        Some(&t),
        json!({ "items": batch }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(e["message"], "import at most 500 items at a time");
    let r = ok(
        &app,
        Method::POST,
        "/api/items/import",
        &t,
        json!({ "items": batch[..500] }),
    )
    .await;
    assert_eq!(r["imported"], 500);

    // 64 KiB items at most: a 70 KiB one is refused until the limit goes up.
    assert_eq!(
        admin_set(&app, json!({ "max_item_kib": 64 })).await.0,
        StatusCode::OK
    );
    let (id, big) = new_item(mine, &"x".repeat(70 * 1024));
    let (s, e) = call(&app, Method::POST, "/api/items", Some(&t), big.clone()).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{e}");
    assert_eq!(
        admin_set(&app, json!({ "max_item_kib": 128 })).await.0,
        StatusCode::OK
    );
    ok(&app, Method::POST, "/api/items", &t, big).await;
    // A key rotation re-encrypts what is stored, whatever the limit is now.
    assert_eq!(
        admin_set(&app, json!({ "max_item_kib": 64 })).await.0,
        StatusCode::OK
    );
    let me = user_id(&app, &t).await;
    let all: Vec<Value> = synced(&app, &t).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| json!({ "id": i["id"], "vault_id": i["vault_id"], "key": i["item_key"], "data": i["data"] }))
        .collect();
    assert!(all.iter().any(|i| i["id"] == id));
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/rotate", mine.0),
        &t,
        json!({ "keys": [{ "user_id": me, "wrapped_key": "a2V5", "key_kind": "account" }], "items": all }),
    )
    .await;
}

#[tokio::test]
async fn sign_in_limits_apply_at_once() {
    let (app, state) = app_with_state().await;
    register(&app, "signin@example.com", "pw-signin-12").await;
    register(&app, "remember@example.com", "pw-remember-1").await;

    // Sign-in attempts per address per minute.
    assert_eq!(
        admin_set(&app, json!({ "signin_attempts_per_minute": 5 }))
            .await
            .0,
        StatusCode::OK
    );
    state.limiter.clear();
    for n in 1..=6 {
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/auth/login/start",
            None,
            json!({ "email": "nobody@example.com", "message": "AAAA" }),
        )
        .await;
        assert_eq!(
            s == StatusCode::TOO_MANY_REQUESTS,
            n == 6,
            "attempt {n}: {s}"
        );
    }
    state.limiter.clear();
    assert_eq!(
        admin_set(&app, json!({ "signin_attempts_per_minute": 30 }))
            .await
            .0,
        StatusCode::OK
    );

    // Two-step attempts per hour: the third wrong code pauses sign-in.
    let t = token(&app, "signin@example.com", "pw-signin-12").await;
    enable_totp(&app, "signin@example.com", "pw-signin-12", &t).await;
    assert_eq!(
        admin_set(&app, json!({ "two_step_attempts_per_hour": 3 }))
            .await
            .0,
        StatusCode::OK
    );
    let (_, l) = login(&app, "signin@example.com", "pw-signin-12", "d-2").await;
    let wrong = |n: u32| {
        let (app, tf) = (app.clone(), l["two_factor_token"].clone());
        async move {
            call(&app, Method::POST, "/api/auth/2fa/verify", None,
                json!({ "two_factor_token": tf, "provider": "recovery", "code": format!("WRONG{n}") })).await.0
        }
    };
    assert_eq!(wrong(1).await, StatusCode::BAD_REQUEST);
    assert_eq!(wrong(2).await, StatusCode::BAD_REQUEST);
    assert_eq!(wrong(3).await, StatusCode::TOO_MANY_REQUESTS);

    // "Remember this device" for remember_device_days.
    assert_eq!(
        admin_set(&app, json!({ "remember_device_days": 2 }))
            .await
            .0,
        StatusCode::OK
    );
    let t = token(&app, "remember@example.com", "pw-remember-1").await;
    let codes = enable_totp(&app, "remember@example.com", "pw-remember-1", &t).await;
    let (_, l) = login(&app, "remember@example.com", "pw-remember-1", "d-r").await;
    let (s, v) = call(&app, Method::POST, "/api/auth/2fa/verify", None,
        json!({ "two_factor_token": l["two_factor_token"], "provider": "recovery", "code": codes[0], "remember": true })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["remember_token"].is_string());
    let expires: i64 = sqlx::query_scalar("SELECT remember_expires FROM devices WHERE id = 'd-r'")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(
        (expires - (crate::db::now() + 2 * 86_400)).abs() < 60,
        "{expires}"
    );
}

#[tokio::test]
async fn session_lifetimes_apply_at_once() {
    let (app, state) = app_with_state().await;
    register(&app, "life@example.com", "pw-life-1234").await;
    let day = 86_400;
    let (_, l) = login(&app, "life@example.com", "pw-life-1234", "d-old").await;
    sqlx::query("UPDATE sessions SET created_at = $1")
        .bind(crate::db::now() - 2 * day)
        .execute(&state.db)
        .await
        .unwrap();
    let refresh = |token: Value| {
        let app = app.clone();
        async move {
            call(
                &app,
                Method::POST,
                "/api/auth/refresh",
                None,
                json!({ "refresh_token": token }),
            )
            .await
        }
    };

    // Signed in two days ago: over a one-day lifetime, fine again at 90 days.
    assert_eq!(
        admin_set(&app, json!({ "session_days": 1 })).await.0,
        StatusCode::OK
    );
    let (s, v) = refresh(l["refresh_token"].clone()).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::UNAUTHORIZED, &json!("session_expired"))
    );
    assert_eq!(
        admin_set(&app, json!({ "session_days": 90 })).await.0,
        StatusCode::OK
    );
    let (s, v) = refresh(l["refresh_token"].clone()).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // A new session's refresh token lasts refresh_days, never past session_days.
    let refresh_expiry = |device: &'static str| {
        let db = state.db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT refresh_expires FROM sessions WHERE device_id = $1",
            )
            .bind(device)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };
    assert_eq!(
        admin_set(&app, json!({ "refresh_days": 3 })).await.0,
        StatusCode::OK
    );
    login(&app, "life@example.com", "pw-life-1234", "d-new").await;
    let expires = refresh_expiry("d-new").await;
    assert!(
        (expires - (crate::db::now() + 3 * day)).abs() < 60,
        "{expires}"
    );
    assert_eq!(
        admin_set(&app, json!({ "refresh_days": 30, "session_days": 2 }))
            .await
            .0,
        StatusCode::OK
    );
    login(&app, "life@example.com", "pw-life-1234", "d-newer").await;
    let expires = refresh_expiry("d-newer").await;
    assert!(
        (expires - (crate::db::now() + 2 * day)).abs() < 60,
        "{expires}"
    );
}

#[tokio::test]
async fn breach_check_opens_the_web_vaults_csp_and_is_a_feature() {
    let dir = std::env::temp_dir().join(format!("passauth-web-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>PassAuth</title>",
    )
    .unwrap();
    let mut config = test_config().await;
    config.web_vault_dir = Some(dir.to_str().unwrap().to_owned());
    let app = crate::router(App::new(config).await.unwrap());
    let closed = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";
    let open = closed.replace(
        "connect-src 'self';",
        "connect-src 'self' https://api.pwnedpasswords.com;",
    );
    let check = |policy: String, listed: bool| {
        let app = app.clone();
        async move {
            // The document, and the page every app route falls back to.
            for path in ["/", "/index.html", "/settings/security"] {
                let resp = get_raw(&app, path).await;
                assert_eq!(resp.status(), StatusCode::OK, "{path}");
                assert_eq!(
                    resp.headers()["content-security-policy"],
                    policy.as_str(),
                    "{path}"
                );
            }
            let (_, v) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
            let features: Vec<String> = serde_json::from_value(v["features"].clone()).unwrap();
            assert_eq!(features.iter().any(|f| f == "breach_check"), listed, "{v}");
        }
    };
    check(open.clone(), true).await;
    assert_eq!(
        admin_set(&app, json!({ "breach_check": false })).await.0,
        StatusCode::OK
    );
    check(closed.to_owned(), false).await;
    assert_eq!(
        admin_set(&app, json!({ "breach_check": true })).await.0,
        StatusCode::OK
    );
    check(open, true).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `reset-sync` (and a restored `backup` copy) drop the sync generation: the
/// server makes a new one when it starts, and every older cursor gets the full
/// response.
#[tokio::test]
async fn a_new_sync_generation_makes_every_cursor_get_everything() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config.clone()).await.unwrap();
    let app = crate::router(state.clone());
    let c = register(&app, "gen@example.com", "pw-gen-12345").await;
    let t = token(&app, "gen@example.com", "pw-gen-12345").await;
    ok(
        &app,
        Method::POST,
        "/api/items",
        &t,
        new_item((&c.vault_id, &c.vault_key), "kept").1,
    )
    .await;
    let cursor = synced(&app, &t).await["cursor"].clone();
    assert_eq!(delta(&app, &t, &cursor, "").await["delta"], true);
    let old = state.sync_generation.clone();
    crate::db::delete_secret(&state.db, crate::state::SYNC_GENERATION)
        .await
        .unwrap();
    drop(app);
    state.db.close().await;
    drop(state);

    let state = App::new(config).await.unwrap();
    assert_ne!(state.sync_generation, old);
    let app = crate::router(state);
    let (s, v) = call(
        &app,
        Method::GET,
        &format!("/api/sync?since={}", cursor.as_str().unwrap()),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v.get("delta").is_none(), "the full response");
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(delta(&app, &t, &v["cursor"], "").await["delta"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------- invitations

/// The pending invitations of a `/sync` answer.
fn invitations(sync: &Value) -> &Vec<Value> {
    sync["invitations"].as_array().unwrap()
}

/// The members of a vault as its member `token` sees them.
async fn members(app: &Router, token: &str, vault: &str) -> Vec<Value> {
    ok(
        app,
        Method::GET,
        &format!("/api/vaults/{vault}/members"),
        token,
        json!(null),
    )
    .await["members"]
        .as_array()
        .unwrap()
        .clone()
}

fn member<'a>(members: &'a [Value], user: &str) -> Option<&'a Value> {
    members.iter().find(|m| m["user_id"] == user)
}

#[tokio::test]
async fn an_invited_vault_stays_out_of_sync_until_accepted() {
    let app = app().await;
    let alice = register(&app, "inv-a@example.com", "pw-alice-1").await;
    let bob = register(&app, "inv-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "inv-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "inv-b@example.com", "pw-bobby-1").await;
    let (a, b) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let v = alice.vault_id.as_str();
    let mine = (v, &alice.vault_key);
    let (x, body) = new_item(mine, "x");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    let before = synced(&app, &tb).await;

    // Shared: Bob gets an invitation, and nothing of the vault.
    let (s, r) = share(&app, &alice, &ta, "inv-b@example.com", "write").await;
    assert_eq!(
        (s, &r["status"]),
        (StatusCode::OK, &json!("invited")),
        "{r}"
    );
    let sync = synced(&app, &tb).await;
    assert!(vault_in(&sync, v).is_none());
    assert!(item_in(&sync, &x).is_none());
    assert!(
        sync["revision"].as_i64() > before["revision"].as_i64(),
        "Bob is told"
    );
    assert_eq!(invitations(&sync).len(), 1);
    let inv = &invitations(&sync)[0];
    assert_eq!(
        (&inv["vault_id"], &inv["role"]),
        (&json!(v), &json!("write"))
    );
    // His app can open the key to show the vault's name and Alice's fingerprint.
    let key = bob
        .unlocked
        .open_shared_vault_key(v, inv["wrapped_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(key.as_bytes(), alice.vault_key.as_bytes());
    assert_eq!(
        inv["meta"],
        vault_in(&synced(&app, &ta).await, v).unwrap()["meta"]
    );
    let found = ok(
        &app,
        Method::GET,
        "/api/users/lookup?email=inv-a@example.com",
        &tb,
        json!(null),
    )
    .await;
    assert_eq!(
        inv["invited_by"],
        json!({
            "id": a, "email": "inv-a@example.com", "name": "Test",
            "public_key": found["public_key"], "signing_key": null, "identity_signature": null,
            "x25519_signature": null,
        })
    );
    assert!(inv["invited_at"].is_i64());
    let poll = ok(&app, Method::GET, "/api/sync/revision", &tb, json!(null)).await;
    assert!(poll["vaults"].get(v).is_none(), "{poll}");
    let cursor = sync["cursor"].clone();

    // He can't use it yet, or leave it.
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&tb),
        new_item(mine, "bob's").1,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    for path in [
        format!("/api/vaults/{v}/members"),
        format!("/api/vaults/{v}/events"),
        format!("/api/items/{x}/versions"),
    ] {
        let (s, _) = call(&app, Method::GET, &path, Some(&tb), json!(null)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let leave = format!("/api/vaults/{v}/members/{b}");
    let (s, _) = call(&app, Method::DELETE, &leave, Some(&tb), json!(null)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Alice sees him as invited.
    let list = members(&app, &ta, v).await;
    let m = member(&list, &b).unwrap();
    assert_eq!(
        (&m["status"], &m["role"], &m["invited_by"]),
        (&json!("invited"), &json!("write"), &json!(a))
    );
    assert_eq!(member(&list, &a).unwrap()["status"], "active");

    // Item writes don't concern him; a new name does (his invitation shows it).
    let r0 = rev_of(&app, &tb).await;
    let (y, body) = new_item(mine, "y");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    assert_eq!(rev_of(&app, &tb).await, r0);
    ok(
        &app,
        Method::PUT,
        &format!("/api/vaults/{v}"),
        &ta,
        json!({ "meta": "bmV3" }),
    )
    .await;
    assert!(rev_of(&app, &tb).await > r0);
    assert_eq!(invitations(&synced(&app, &tb).await)[0]["meta"], "bmV3");

    // Sharing again changes the invitation's role; it stays an invitation.
    let (s, r) = share(&app, &alice, &ta, "inv-b@example.com", "read").await;
    assert_eq!((s, &r["status"]), (StatusCode::OK, &json!("invited")));
    assert_eq!(invitations(&synced(&app, &tb).await)[0]["role"], "read");

    // Accepted: the vault arrives whole, the invitation goes, he is a member.
    let r = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{v}/invitation/accept"),
        &tb,
        json!(null),
    )
    .await;
    assert_eq!(r["status"], "active");
    assert_eq!(r["vault_seq"], seq_of(&synced(&app, &ta).await, v));
    let d = delta(&app, &tb, &cursor, "").await;
    assert_eq!(d["reset"], json!([v]));
    assert_eq!(ids(&d), sorted(vec![x.clone(), y.clone()]));
    assert!(invitations(&d).is_empty());
    assert_eq!(vault_in(&d, v).unwrap()["role"], "read");
    let poll = ok(&app, Method::GET, "/api/sync/revision", &tb, json!(null)).await;
    assert!(poll["vaults"].get(v).is_some(), "{poll}");
    assert_eq!(
        member(&members(&app, &ta, v).await, &b).unwrap()["status"],
        "active"
    );

    // Accepting again is harmless; there is nothing left to decline.
    let again = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{v}/invitation/accept"),
        &tb,
        json!(null),
    )
    .await;
    assert_eq!(again["status"], "active");
    assert_eq!(again["vault_seq"], r["vault_seq"], "nothing was written");
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v}/invitation"),
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // A role change of a member keeps them a member.
    let (s, r) = share(&app, &alice, &ta, "inv-b@example.com", "write").await;
    assert_eq!((s, &r["status"]), (StatusCode::OK, &json!("active")));
    assert_eq!(
        vault_in(&synced(&app, &tb).await, v).unwrap()["role"],
        "write"
    );
}

#[tokio::test]
async fn declined_and_cancelled_invitations_leave_nothing_behind() {
    let app = app().await;
    let alice = register(&app, "dec-a@example.com", "pw-alice-1").await;
    for who in ["b", "c", "d"] {
        register(&app, &format!("dec-{who}@example.com"), "pw-other-12").await;
    }
    let ta = token(&app, "dec-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "dec-b@example.com", "pw-other-12").await;
    let tc = token(&app, "dec-c@example.com", "pw-other-12").await;
    let td = token(&app, "dec-d@example.com", "pw-other-12").await;
    let (b, c) = (user_id(&app, &tb).await, user_id(&app, &tc).await);
    let v = alice.vault_id.as_str();
    for (who, role) in [("b", "write"), ("c", "read"), ("d", "write")] {
        let email = format!("dec-{who}@example.com");
        assert_eq!(
            share(&app, &alice, &ta, &email, role).await.0,
            StatusCode::OK
        );
    }
    accept(&app, &td, v).await;
    let pending = |sync: Value| vault_in(&sync, v).unwrap()["rotation_pending"].clone();
    assert_eq!(pending(synced(&app, &ta).await), 0);

    // Bob declines: the invitation is gone. His app opened the vault key to show
    // the name, so the vault asks for a new key, as when someone leaves.
    let before = rev_of(&app, &tb).await;
    let (_, a_before) = call(
        &app,
        Method::GET,
        "/api/sync/revision",
        Some(&ta),
        json!(null),
    )
    .await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v}/invitation"),
        &tb,
        json!(null),
    )
    .await;
    assert!(invitations(&synced(&app, &tb).await).is_empty());
    assert!(rev_of(&app, &tb).await > before);
    assert!(rev_of(&app, &ta).await > a_before["revision"].as_i64().unwrap());
    assert_eq!(pending(synced(&app, &ta).await), 1);
    assert!(member(&members(&app, &ta, v).await, &b).is_none());
    for (method, path) in [
        (Method::DELETE, format!("/api/vaults/{v}/invitation")),
        (Method::POST, format!("/api/vaults/{v}/invitation/accept")),
    ] {
        let (s, _) = call(&app, method, &path, Some(&tb), json!(null)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }

    // A writer can't cancel Carol's invitation; the owner can.
    let cancel = format!("/api/vaults/{v}/members/{c}");
    let (s, _) = call(&app, Method::DELETE, &cancel, Some(&td), json!(null)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let before = rev_of(&app, &tc).await;
    let r = ok(&app, Method::DELETE, &cancel, &ta, json!(null)).await;
    assert_eq!(r["rotation_required"], true);
    assert!(invitations(&synced(&app, &tc).await).is_empty());
    assert!(rev_of(&app, &tc).await > before);
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("/api/vaults/{v}/invitation/accept"),
        Some(&tc),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // No vault, no invitation: 404.
    let ghost = uuid::Uuid::new_v4();
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("/api/vaults/{ghost}/invitation/accept"),
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn key_replacements_seal_the_new_key_to_invitees() {
    let app = app().await;
    let alice = register(&app, "kr-a@example.com", "pw-alice-1").await;
    register(&app, "kr-b@example.com", "pw-bobby-1").await;
    register(&app, "kr-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "kr-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "kr-b@example.com", "pw-bobby-1").await;
    let tc = token(&app, "kr-c@example.com", "pw-carol-1").await;
    let (a, b, c) = (
        user_id(&app, &ta).await,
        user_id(&app, &tb).await,
        user_id(&app, &tc).await,
    );
    let v = alice.vault_id.as_str();
    assert_eq!(
        share(&app, &alice, &ta, "kr-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        share(&app, &alice, &ta, "kr-c@example.com", "read").await.0,
        StatusCode::OK
    );
    accept(&app, &tc, v).await;
    let key = |u: &str, k: &str| json!({ "user_id": u, "wrapped_key": k, "key_kind": if u == a { "account" } else { "sealed" } });

    // The invitee counts: without a key for Bob the rotation is refused.
    let rotate = format!("/api/vaults/{v}/rotate");
    let (s, _) = call(
        &app,
        Method::POST,
        &rotate,
        Some(&ta),
        json!({ "keys": [key(&a, "a2V5"), key(&c, "a2V5")], "items": [] }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // With it, his invitation carries the new key and name, and he is told.
    let before = rev_of(&app, &tb).await;
    ok(
        &app,
        Method::POST,
        &rotate,
        &ta,
        json!({ "keys": [key(&a, "a2V5"), key(&b, "a2V5"), key(&c, "a2V5")], "items": [], "meta": "bmV3" }),
    )
    .await;
    let inv = invitations(&synced(&app, &tb).await)[0].clone();
    assert_eq!(
        (&inv["wrapped_key"], &inv["meta"]),
        (&json!("a2V5"), &json!("bmV3"))
    );
    assert!(rev_of(&app, &tb).await > before);

    // Removing Carol with a new key in one step reaches him too.
    let before = rev_of(&app, &tb).await;
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{v}/members/{c}/remove"),
        &ta,
        json!({ "keys": [key(&a, "a2V5"), key(&b, "bmV3S2V5")], "items": [], "key_epoch": 1 }),
    )
    .await;
    assert!(rev_of(&app, &tb).await > before);
    assert_eq!(
        invitations(&synced(&app, &tb).await)[0]["wrapped_key"],
        "bmV3S2V5"
    );
    accept(&app, &tb, v).await;
    assert_eq!(
        vault_in(&synced(&app, &tb).await, v).unwrap()["wrapped_key"],
        "bmV3S2V5"
    );
}

#[tokio::test]
async fn live_sync_tells_invitees_only_that_their_invitations_changed() {
    let (app, state) = app_with_state().await;
    let addr = serve(state).await;
    let alice = register(&app, "wsi-a@example.com", "pw-alice-1").await;
    register(&app, "wsi-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "wsi-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "wsi-b@example.com", "pw-bobby-1").await;
    let v = alice.vault_id.as_str();
    let mut ws = socket(addr, &tb).await;

    assert_eq!(
        share(&app, &alice, &ta, "wsi-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    let msg = next_message(&mut ws).await.unwrap();
    assert_eq!(
        (&msg["type"], &msg["vaults"]),
        (&json!("sync"), &json!({})),
        "{msg}"
    );
    // Alice's items are none of his business yet.
    let save = || {
        let (app, ta) = (app.clone(), ta.clone());
        let body = new_item((v, &alice.vault_key), "x").1;
        async move { ok(&app, Method::POST, "/api/items", &ta, body).await }
    };
    save().await;
    assert!(quiet(&mut ws, 600).await.is_empty());

    // Accepted: from now on his messages carry the vault's numbers.
    accept(&app, &tb, v).await;
    let msg = next_message(&mut ws).await.unwrap();
    assert!(msg["vaults"].get(v).is_some(), "{msg}");
    quiet(&mut ws, 400).await;
    let r = save().await;
    let msg = next_message(&mut ws).await.unwrap();
    assert_eq!(msg["vaults"][v], r["vault_seq"], "{msg}");
}

#[test]
fn the_invitation_email_names_the_sharer_and_opens_the_vaults_page() {
    let e = crate::vault::invitation_email("https://vault.example.com", "Alice", "a@example.com");
    assert_eq!(e.subject, "You've been invited to a shared vault");
    assert!(
        e.body.starts_with("Alice (a@example.com) invited you"),
        "{}",
        e.body
    );
    assert_eq!(
        e.action.unwrap().1,
        "https://vault.example.com/settings/vaults"
    );
    // The sharer's name can't add lines of its own.
    let e = crate::vault::invitation_email(
        "https://v.example",
        "Eve\n\nYour account is locked",
        "e@example.com",
    );
    assert!(
        e.body
            .starts_with("EveYour account is locked (e@example.com)"),
        "{}",
        e.body
    );
    let e = crate::vault::invitation_email("https://v.example", "  ", "e@example.com");
    assert!(
        e.body.starts_with("e@example.com invited you"),
        "{}",
        e.body
    );
}

// ------------------------------------------------------------ activity log

/// `call` from TCP peer `ip` (the visitor's address without a proxy), as the
/// web app (`X-PassAuth-Client: web/9.9.9`).
async fn call_from(
    app: &Router,
    ip: &str,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("x-passauth-client", "web/9.9.9");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    let peer: std::net::SocketAddr = format!("{ip}:40000").parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every stored event, oldest first, as JSON with every column (failed sign-ins
/// counted in the background included).
async fn stored_events(state: &AppState) -> Vec<Value> {
    state.failures.flush().await;
    type Row = (
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, at, type, actor_id, session_id, client, ip, vault_id, item_id, target_user_id, data
         FROM events ORDER BY at, id",
    )
    .fetch_all(&state.db)
    .await
    .unwrap();
    rows.into_iter()
        .map(
            |(id, at, kind, actor, session, client, ip, vault, item, target, data)| {
                json!({
                    "id": id, "at": at, "type": kind, "actor_id": actor, "session_id": session,
                    "client": client, "ip": ip, "vault_id": vault, "item_id": item,
                    "target_user_id": target,
                    "data": data.map(|d| serde_json::from_str::<Value>(&d).unwrap()),
                })
            },
        )
        .collect()
}

fn of_type<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["type"] == kind).collect()
}

/// Every event of `path` (an events endpoint), following `next` page by page.
async fn all_pages(app: &Router, token: &str, path: &str, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let mut before: Option<String> = None;
    loop {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut url = format!("{path}{sep}limit={limit}");
        if let Some(b) = &before {
            url.push_str(&format!("&before={b}"));
        }
        let page = ok(app, Method::GET, &url, token, json!(null)).await;
        let events = page["events"].as_array().unwrap();
        assert!(events.len() <= limit);
        out.extend(events.iter().cloned());
        match page["next"].as_str() {
            Some(next) => before = Some(next.to_owned()),
            None => return out,
        }
    }
}

#[tokio::test]
async fn vault_writes_are_logged_in_their_own_transaction() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "log@example.com", "pw-log-12345").await;
    let t = token(&app, "log@example.com", "pw-log-12345").await;
    let me = user_id(&app, &t).await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let from = |method: Method, path: String, body: Value| {
        let (app, t) = (app.clone(), t.clone());
        async move {
            let (s, v) = call_from(&app, "203.0.113.7", method, &path, Some(&t), body).await;
            assert_eq!(s, StatusCode::OK, "{path}: {v}");
            v
        }
    };

    let (x, body) = new_item(a, "Bank login");
    let created = from(Method::POST, "/api/items".into(), body.clone()).await;
    let mut edit = item_body(&x, a, "Bank login (old)");
    edit["revision"] = created["revision"].clone();
    from(Method::PUT, format!("/api/items/{x}"), edit.clone()).await;
    from(Method::DELETE, format!("/api/items/{x}"), json!(null)).await;
    from(Method::POST, format!("/api/items/{x}/restore"), json!(null)).await;
    from(
        Method::DELETE,
        format!("/api/items/{x}/permanent"),
        json!(null),
    )
    .await;
    let (y, ybody) = new_item(a, "y");
    let (z, zbody) = new_item(a, "z");
    from(
        Method::POST,
        "/api/items/import".into(),
        json!({ "items": [ybody, zbody] }),
    )
    .await;
    let (v2, k2) = new_vault(&app, &c, &t).await;
    from(
        Method::PUT,
        format!("/api/items/{y}"),
        item_body(&y, (&v2, &k2), "y"),
    )
    .await;
    from(
        Method::PUT,
        format!("/api/vaults/{v2}"),
        json!({ "meta": "bmV3" }),
    )
    .await;

    let events = stored_events(&state).await;
    let kinds: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        kinds,
        [
            "account.created",
            "vault.created",
            "auth.signed_in",
            "item.created",
            "item.updated",
            "item.trashed",
            "item.restored",
            "item.deleted",
            "item.imported",
            "vault.created",
            "item.moved",
            "item.moved",
            "vault.renamed",
        ]
    );
    let first = of_type(&events, "item.created")[0];
    assert_eq!(
        (&first["actor_id"], &first["vault_id"], &first["item_id"]),
        (&json!(me), &json!(a.0), &json!(x))
    );
    assert_eq!(
        (&first["client"], &first["ip"]),
        (&json!("web/9.9.9"), &json!("203.0.113.7"))
    );
    assert!(first["session_id"].is_string());
    assert_eq!(
        of_type(&events, "item.imported")[0]["data"],
        json!({ "count": 2 })
    );
    let moved = of_type(&events, "item.moved");
    assert_eq!(
        (&moved[0]["vault_id"], &moved[0]["data"]),
        (&json!(a.0), &json!({ "to": v2 }))
    );
    assert_eq!(
        (&moved[1]["vault_id"], &moved[1]["data"]),
        (&json!(v2), &json!({ "from": a.0 }))
    );

    // A refused write leaves no event: a stale revision, a replaced key, a quota.
    let count = stored_events(&state).await.len();
    let mut stale = item_body(&z, a, "z2");
    stale["revision"] = json!(1);
    let (s, _) = call(
        &app,
        Method::PUT,
        &format!("/api/items/{z}"),
        Some(&t),
        stale,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let mut old_key = new_item(a, "w").1;
    old_key["key_epoch"] = json!(7);
    let (s, _) = call(&app, Method::POST, "/api/items", Some(&t), old_key).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(stored_events(&state).await.len(), count);
    assert_eq!(
        admin_set(&app, json!({ "max_items_per_user": 1 })).await.0,
        StatusCode::OK
    );
    let count = stored_events(&state).await.len();
    // The quota is checked after the event was written: both roll back.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/items",
        Some(&t),
        new_item(a, "w").1,
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("quota_exceeded"))
    );
    assert_eq!(stored_events(&state).await.len(), count);

    // Nothing of the vaults' content is in the log, only ids.
    let dump = serde_json::to_string(&stored_events(&state).await).unwrap();
    let full = synced(&app, &t).await;
    let mut secrets = vec![
        body["key"].as_str().unwrap().to_owned(),
        body["data"].as_str().unwrap().to_owned(),
        edit["data"].as_str().unwrap().to_owned(),
        "Bank login".to_owned(),
    ];
    for v in full["vaults"].as_array().unwrap() {
        secrets.push(v["meta"].as_str().unwrap().to_owned());
        secrets.push(v["wrapped_key"].as_str().unwrap().to_owned());
    }
    for i in full["items"].as_array().unwrap() {
        secrets.push(i["item_key"].as_str().unwrap().to_owned());
        secrets.push(i["data"].as_str().unwrap().to_owned());
    }
    for secret in secrets.iter().filter(|s| s.len() > 4) {
        assert!(!dump.contains(secret.as_str()), "{secret} is in the log");
    }
}

#[tokio::test]
async fn event_pages_go_back_in_time_and_show_only_ones_own_addresses() {
    let app = app().await;
    let alice = register(&app, "ev-a@example.com", "pw-alice-1").await;
    register(&app, "ev-b@example.com", "pw-bobby-1").await;
    register(&app, "ev-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "ev-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "ev-b@example.com", "pw-bobby-1").await;
    let tc = token(&app, "ev-c@example.com", "pw-carol-1").await;
    let (a, b) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let v = alice.vault_id.as_str();
    let (alice_ip, bob_ip) = ("203.0.113.7", "198.51.100.9");
    let (s, _) = share(&app, &alice, &ta, "ev-b@example.com", "write").await;
    assert_eq!(s, StatusCode::OK);
    let accept = format!("/api/vaults/{v}/invitation/accept");
    let (s, _) = call_from(&app, bob_ip, Method::POST, &accept, Some(&tb), json!(null)).await;
    assert_eq!(s, StatusCode::OK);
    for (ip, token, n) in [(bob_ip, &tb, 5), (alice_ip, &ta, 2)] {
        for _ in 0..n {
            let body = new_item((v, &alice.vault_key), "x").1;
            let (s, _) = call_from(&app, ip, Method::POST, "/api/items", Some(token), body).await;
            assert_eq!(s, StatusCode::OK);
        }
    }

    // Alice (the owner) reads the vault's log page by page, newest first.
    let events = all_pages(&app, &ta, &format!("/api/vaults/{v}/events"), 3).await;
    let kinds: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    let mut expected = vec!["item.created"; 7];
    expected.extend(["member.accepted", "member.invited", "vault.created"]);
    assert_eq!(kinds, expected);
    let mut seen: Vec<&str> = events.iter().map(|e| e["id"].as_str().unwrap()).collect();
    seen.dedup();
    assert_eq!(seen.len(), events.len(), "no event twice");
    assert!(
        events
            .windows(2)
            .all(|w| w[0]["at"].as_i64() >= w[1]["at"].as_i64())
    );
    // Her own addresses, never Bob's.
    for e in &events {
        let by = e["actor"]["id"].as_str();
        assert_eq!(
            e.get("ip").is_some(),
            by == Some(&a) && e["type"] == "item.created",
            "{e}"
        );
    }
    assert_eq!(events[0]["ip"], alice_ip);
    let invited = &events[8];
    assert_eq!(
        (&invited["actor"], &invited["target_user"], &invited["data"]),
        (
            &json!({ "id": a, "email": "ev-a@example.com", "name": "Test" }),
            &json!({ "id": b, "email": "ev-b@example.com" }),
            &json!({ "role": "write", "signed": false })
        )
    );
    assert_eq!(
        (&invited["vault_id"], &invited["item_id"]),
        (&json!(v), &json!(null))
    );

    // Bob (a writer) can't read it; someone outside the vault gets 404.
    for (t, status) in [(&tb, StatusCode::FORBIDDEN), (&tc, StatusCode::NOT_FOUND)] {
        let (s, _) = call(
            &app,
            Method::GET,
            &format!("/api/vaults/{v}/events"),
            Some(t),
            json!(null),
        )
        .await;
        assert_eq!(s, status);
    }

    // Bob's own log: what he did (with his address) and Alice's invitation of him (without hers).
    let mine = all_pages(&app, &tb, "/api/account/events", 200).await;
    let accepted = mine
        .iter()
        .find(|e| e["type"] == "member.accepted")
        .unwrap();
    assert_eq!(accepted["ip"], bob_ip);
    assert_eq!(accepted["client"], "web/9.9.9");
    let invited = mine.iter().find(|e| e["type"] == "member.invited").unwrap();
    assert_eq!(invited["actor"]["id"], a);
    assert!(invited.get("ip").is_none());
    assert!(
        mine.iter()
            .all(|e| e["type"] != "vault.created" || e["actor"]["id"] == b)
    );

    // The admin page sees every address, and filters.
    let admin = |query: &str| {
        let app = app.clone();
        let path = format!("/api/admin/events?{query}");
        async move {
            let (s, v) = call(&app, Method::GET, &path, Some("test-admin"), json!(null)).await;
            (s, v)
        }
    };
    let (s, page) = admin(&format!("vault={v}&user={b}&type=item&limit=200")).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let bobs = page["events"].as_array().unwrap();
    assert_eq!(bobs.len(), 5);
    assert!(
        bobs.iter()
            .all(|e| e["ip"] == bob_ip && e["type"] == "item.created")
    );
    let (_, page) = admin("type=member.accepted").await;
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    for bad in ["type=Item", "type=item.%25", "type=it_m", "before=***"] {
        assert_eq!(admin(bad).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/admin/events",
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "users can't read the admin log"
    );

    // Limits are clamped; a bad cursor is refused.
    let page = ok(
        &app,
        Method::GET,
        "/api/account/events?limit=0",
        &ta,
        json!(null),
    )
    .await;
    assert_eq!(page["events"].as_array().unwrap().len(), 1);
    assert!(page["next"].is_string());
    let (s, _) = call(
        &app,
        Method::GET,
        "/api/account/events?before=bm9wZQ",
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_ins_and_failed_attempts_are_logged_and_counted() {
    let (app, state) = app_with_state().await;
    register(&app, "in@example.com", "pw-in-123456").await;
    for _ in 0..3 {
        let (s, _) = login(&app, "in@example.com", "wrong password", "d1").await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
    let (s, _) = login(&app, "ghost@example.com", "whatever", "d1").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let t = token(&app, "in@example.com", "pw-in-123456").await;
    let me = user_id(&app, &t).await;
    let second = token(&app, "in@example.com", "pw-in-123456").await;

    let events = stored_events(&state).await;
    let failed = of_type(&events, "auth.signin_failed");
    assert_eq!(failed.len(), 1, "counted in one entry: {failed:?}");
    assert_eq!(
        (
            &failed[0]["target_user_id"],
            &failed[0]["actor_id"],
            &failed[0]["data"]
        ),
        (
            &json!(me),
            &json!(null),
            &json!({ "reason": "password", "count": 3 })
        )
    );
    let signed_in = of_type(&events, "auth.signed_in");
    assert_eq!(signed_in.len(), 2);
    assert_eq!(signed_in[0]["actor_id"], me);
    assert_eq!(
        (&signed_in[0]["data"], &signed_in[1]["data"]["new_device"]),
        (
            &json!({ "two_step": null, "device_kind": "cli", "new_device": true }),
            &json!(false)
        )
    );

    // With two-step login on, wrong codes count under their own reason.
    enable_totp(&app, "in@example.com", "pw-in-123456", &t).await;
    for _ in 0..2 {
        let (_, l) = login(&app, "in@example.com", "pw-in-123456", "d1").await;
        let (s, _) = call(
            &app,
            Method::POST,
            "/api/auth/2fa/verify",
            None,
            json!({ "two_factor_token": l["two_factor_token"], "provider": "totp", "code": "000000" }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }
    let events = stored_events(&state).await;
    let two_step: Vec<_> = of_type(&events, "auth.signin_failed")
        .into_iter()
        .filter(|e| e["data"]["reason"] == "two_step")
        .collect();
    assert_eq!(two_step[0]["data"]["count"], 2);
    let enabled = of_type(&events, "account.two_step_enabled");
    assert_eq!(
        enabled[0]["data"],
        json!({ "method": "totp", "recovery_codes": true })
    );

    // Signing out is logged too, and the account sees all of it.
    ok(&app, Method::POST, "/api/auth/logout", &second, json!({})).await;
    let mine = all_pages(&app, &t, "/api/account/events", 50).await;
    for kind in [
        "auth.signin_failed",
        "auth.signed_in",
        "session.signed_out",
        "account.two_step_enabled",
        "account.created",
    ] {
        assert!(mine.iter().any(|e| e["type"] == kind), "{kind}");
    }
}

#[tokio::test]
async fn old_events_are_deleted_and_addresses_can_be_turned_off() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "ret@example.com", "pw-ret-12345").await;
    let t = token(&app, "ret@example.com", "pw-ret-12345").await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let save = || {
        let (app, t) = (app.clone(), t.clone());
        let body = new_item(a, "x").1;
        async move {
            let (s, v) = call_from(
                &app,
                "203.0.113.7",
                Method::POST,
                "/api/items",
                Some(&t),
                body,
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };
    save().await;
    let ips = |events: Vec<Value>| -> Vec<Value> {
        events.into_iter().map(|e| e["ip"].clone()).collect()
    };
    assert!(ips(stored_events(&state).await).contains(&json!("203.0.113.7")));

    // Kept `event_days` (365 by default), then the sweeper deletes them.
    let old = crate::db::now() - 400 * 86_400;
    sqlx::query("INSERT INTO events (id, at, type) VALUES ('old-one', $1, 'item.created')")
        .bind(old)
        .execute(&state.db)
        .await
        .unwrap();
    let before = stored_events(&state).await.len();
    assert_eq!(crate::events::purge(&state).await.unwrap(), 1);
    assert_eq!(stored_events(&state).await.len(), before - 1);
    for (days, status) in [
        (29, StatusCode::BAD_REQUEST),
        (3651, StatusCode::BAD_REQUEST),
        (30, StatusCode::OK),
    ] {
        assert_eq!(
            admin_set(&app, json!({ "event_days": days })).await.0,
            status,
            "{days}"
        );
    }

    // Addresses off: none kept from now on, and the kept ones are erased.
    let (s, v) = admin_set(&app, json!({ "event_ip": false })).await;
    assert_eq!((s, &v["event_ip"]), (StatusCode::OK, &json!(false)));
    save().await;
    assert!(ips(stored_events(&state).await).iter().all(Value::is_null));
    let (_, v) = admin_set(&app, json!({ "event_ip": true })).await;
    assert_eq!(v["event_ip"], true);
    save().await;
    assert!(ips(stored_events(&state).await).contains(&json!("203.0.113.7")));

    // Admin changes are logged by name, never with their values.
    admin_set(
        &app,
        json!({ "session_days": 45, "icons": true, "event_days": 30 }),
    )
    .await;
    let events = stored_events(&state).await;
    let changes = of_type(&events, "admin.settings_changed");
    assert_eq!(
        changes
            .iter()
            .map(|e| e["data"].clone())
            .collect::<Vec<_>>(),
        [
            json!({ "changed": ["event_days"] }),
            json!({ "changed": ["event_ip"] }),
            json!({ "changed": ["event_ip"] }),
            json!({ "changed": ["session_days"] }),
        ]
    );
    assert!(changes.iter().all(|e| e["actor_id"].is_null()));
}

#[tokio::test]
async fn turning_addresses_off_keeps_none_not_even_in_its_own_event() {
    let (app, state) = app_with_state().await;
    let admin = |body: Value| {
        let app = app.clone();
        async move {
            let path = "/api/admin/settings";
            let (s, v) = call_from(
                &app,
                "198.51.100.9",
                Method::PUT,
                path,
                Some("test-admin"),
                body,
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v
        }
    };
    admin(json!({ "session_days": 45 })).await;
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "admin.settings_changed")[0]["ip"],
        "198.51.100.9"
    );

    // Off: every kept address is erased, and the change's own event keeps none either.
    assert_eq!(admin(json!({ "event_ip": false })).await["event_ip"], false);
    let events = stored_events(&state).await;
    let changes = of_type(&events, "admin.settings_changed");
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[1]["data"], json!({ "changed": ["event_ip"] }));
    assert!(events.iter().all(|e| e["ip"].is_null()), "{events:?}");
    admin(json!({ "session_days": 40 })).await;
    assert!(
        stored_events(&state)
            .await
            .iter()
            .all(|e| e["ip"].is_null())
    );

    // On again: kept from that change on, its own event included.
    admin(json!({ "event_ip": true })).await;
    let events = stored_events(&state).await;
    let changes = of_type(&events, "admin.settings_changed");
    assert_eq!(changes.len(), 4);
    assert_eq!(changes[3]["ip"], "198.51.100.9");
}

#[tokio::test]
async fn admin_actions_on_an_account_are_in_its_log() {
    let app = app().await;
    register(&app, "adm@example.com", "pw-adm-12345").await;
    let t = token(&app, "adm@example.com", "pw-adm-12345").await;
    let id = user_id(&app, &t).await;
    let admin = Some("test-admin");
    for path in ["disable", "enable", "sessions/revoke", "two-factor/reset"] {
        let (s, v) = call(
            &app,
            Method::POST,
            &format!("/api/admin/users/{id}/{path}"),
            admin,
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
    }
    let t = token(&app, "adm@example.com", "pw-adm-12345").await;
    let mine = all_pages(&app, &t, "/api/account/events", 50).await;
    let kinds: Vec<&str> = mine
        .iter()
        .map(|e| e["type"].as_str().unwrap())
        .take(5)
        .collect();
    assert_eq!(
        kinds,
        [
            "auth.signed_in",
            "admin.two_step_reset",
            "admin.sessions_revoked",
            "admin.user_enabled",
            "admin.user_disabled"
        ]
    );
    let disabled = &mine[4];
    assert_eq!(
        (&disabled["actor"], &disabled["target_user"]),
        (
            &json!(null),
            &json!({ "id": id, "email": "adm@example.com" })
        )
    );
    let (s, _) = call(
        &app,
        Method::DELETE,
        &format!("/api/admin/users/{id}"),
        admin,
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, page) = call(
        &app,
        Method::GET,
        &format!("/api/admin/events?user={id}&type=admin.user_deleted"),
        admin,
        json!(null),
    )
    .await;
    let deleted = &page["events"][0];
    assert_eq!(
        deleted["target_user"],
        json!({ "id": id, "email": null }),
        "the deleted account is only an id now"
    );
    let (_, page) = call(
        &app,
        Method::GET,
        "/api/admin/events?type=admin",
        admin,
        json!(null),
    )
    .await;
    assert!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["type"].as_str().unwrap().starts_with("admin."))
    );
}

// ------------------------------------------------------------ item history

async fn versions(app: &Router, token: &str, item: &str) -> Vec<Value> {
    ok(
        app,
        Method::GET,
        &format!("/api/items/{item}/versions"),
        token,
        json!(null),
    )
    .await["versions"]
        .as_array()
        .unwrap()
        .clone()
}

/// Versions stored for an item (also beyond what the API lists).
async fn stored_versions(state: &AppState, item: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM item_versions WHERE item_id = $1")
        .bind(item)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

/// Save `name` as the new content of item `id` in `vault`; returns the request body.
async fn edit_item(
    app: &Router,
    token: &str,
    id: &str,
    vault: (&str, &SymmetricKey),
    name: &str,
) -> Value {
    let body = item_body(id, vault, name);
    ok(
        app,
        Method::PUT,
        &format!("/api/items/{id}"),
        token,
        body.clone(),
    )
    .await;
    body
}

#[tokio::test]
async fn edits_and_the_trash_keep_earlier_versions() {
    let app = app().await;
    let alice = register(&app, "hist-a@example.com", "pw-alice-1").await;
    register(&app, "hist-b@example.com", "pw-bobby-1").await;
    register(&app, "hist-c@example.com", "pw-carol-1").await;
    let ta = token(&app, "hist-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "hist-b@example.com", "pw-bobby-1").await;
    let tc = token(&app, "hist-c@example.com", "pw-carol-1").await;
    let a = user_id(&app, &ta).await;
    let v = (alice.vault_id.as_str(), &alice.vault_key);
    assert_eq!(
        share(&app, &alice, &ta, "hist-b@example.com", "read")
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &tb, v.0).await;

    let (x, v0) = new_item(v, "v0");
    ok(&app, Method::POST, "/api/items", &ta, v0.clone()).await;
    assert!(
        versions(&app, &ta, &x).await.is_empty(),
        "a new item has no history"
    );
    let v1 = edit_item(&app, &ta, &x, v, "v1").await;
    let v2 = edit_item(&app, &ta, &x, v, "v2").await;
    let list = versions(&app, &ta, &x).await;
    assert_eq!(list.len(), 2);
    assert!(
        list[0]["seq"].as_i64() > list[1]["seq"].as_i64(),
        "newest first"
    );
    assert_eq!(
        list[0]["saved_by"],
        json!({ "id": a, "email": "hist-a@example.com", "name": "Test" })
    );
    let get = |seq: &Value| {
        let (app, ta, x) = (app.clone(), ta.clone(), x.clone());
        let seq = seq.as_i64().unwrap();
        async move {
            ok(
                &app,
                Method::GET,
                &format!("/api/items/{x}/versions/{seq}"),
                &ta,
                json!(null),
            )
            .await
        }
    };
    let newest = get(&list[0]["seq"]).await;
    assert_eq!(
        (&newest["item_key"], &newest["data"]),
        (&v1["key"], &v1["data"])
    );
    assert_eq!(
        (&newest["vault_id"], &newest["seq"]),
        (&json!(v.0), &list[0]["seq"])
    );
    let oldest = get(&list[1]["seq"]).await;
    assert_eq!(oldest["data"], v0["data"]);

    // Trashing keeps the last content; restoring and editing don't copy it twice.
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{x}"),
        &ta,
        json!(null),
    )
    .await;
    assert_eq!(versions(&app, &ta, &x).await.len(), 3);
    assert_eq!(
        get(&versions(&app, &ta, &x).await[0]["seq"]).await["data"],
        v2["data"]
    );
    ok(
        &app,
        Method::POST,
        &format!("/api/items/{x}/restore"),
        &ta,
        json!(null),
    )
    .await;
    edit_item(&app, &ta, &x, v, "v3").await;
    assert_eq!(versions(&app, &ta, &x).await.len(), 3);
    edit_item(&app, &ta, &x, v, "v4").await;
    assert_eq!(versions(&app, &ta, &x).await.len(), 4);

    // Every member may read them; nobody else, and unknown numbers are 404.
    assert_eq!(versions(&app, &tb, &x).await.len(), 4);
    for path in [
        format!("/api/items/{x}/versions"),
        format!("/api/items/{x}/versions/999999"),
    ] {
        let (s, _) = call(&app, Method::GET, &path, Some(&tc), json!(null)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/items/{x}/versions/999999"),
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Restoring is an ordinary edit with a version's key and data.
    let back = get(&oldest["seq"]).await;
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        &ta,
        json!({ "id": x, "vault_id": v.0, "key": back["item_key"], "data": back["data"] }),
    )
    .await;
    assert_eq!(
        item_in(&synced(&app, &ta).await, &x).unwrap()["data"],
        v0["data"]
    );
}

#[tokio::test]
async fn the_admin_sets_how_many_versions_are_kept() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "kept@example.com", "pw-kept-1234").await;
    let t = token(&app, "kept@example.com", "pw-kept-1234").await;
    let v = (c.vault_id.as_str(), &c.vault_key);
    let (x, body) = new_item(v, "v0");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    for n in 1..=4 {
        edit_item(&app, &t, &x, v, &format!("v{n}")).await;
    }
    assert_eq!(versions(&app, &t, &x).await.len(), 4);
    let all = versions(&app, &t, &x).await;

    // Fewer: the oldest go at once.
    assert_eq!(
        admin_set(&app, json!({ "item_versions_kept": 2 })).await.0,
        StatusCode::OK
    );
    let list = versions(&app, &t, &x).await;
    assert_eq!(list, all[..2].to_vec());
    assert_eq!(stored_versions(&state, &x).await, 2);
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/items/{x}/versions/{}", all[3]["seq"]),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    edit_item(&app, &t, &x, v, "v5").await;
    assert_eq!(stored_versions(&state, &x).await, 2);
    let config = |app: Router| async move {
        call(&app, Method::GET, "/api/config", None, json!(null))
            .await
            .1
    };
    let cfg = config(app.clone()).await;
    assert_eq!(cfg["limits"]["item_versions_kept"], 2);
    assert!(
        cfg["features"]
            .as_array()
            .unwrap()
            .contains(&json!("item_history"))
    );

    // Off: nothing listed or kept, and clients don't offer it.
    assert_eq!(
        admin_set(&app, json!({ "item_versions_kept": 0 })).await.0,
        StatusCode::OK
    );
    assert!(versions(&app, &t, &x).await.is_empty());
    assert_eq!(stored_versions(&state, &x).await, 0);
    edit_item(&app, &t, &x, v, "v6").await;
    assert_eq!(stored_versions(&state, &x).await, 0);
    assert!(
        !config(app.clone()).await["features"]
            .as_array()
            .unwrap()
            .contains(&json!("item_history"))
    );
    assert_eq!(
        admin_set(&app, json!({ "item_versions_kept": 101 }))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn versions_go_with_key_replacements_moves_and_deletions() {
    let (app, state) = app_with_state().await;
    let c = register(&app, "vgone@example.com", "pw-vgone-123").await;
    let t = token(&app, "vgone@example.com", "pw-vgone-123").await;
    let me = user_id(&app, &t).await;
    let v = (c.vault_id.as_str(), &c.vault_key);
    let (v2, k2) = new_vault(&app, &c, &t).await;
    let w = (v2.as_str(), &k2);
    let (x, body) = new_item(v, "x");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let x1 = edit_item(&app, &t, &x, v, "x1").await;
    assert_eq!(stored_versions(&state, &x).await, 1);

    // A key replacement re-encrypts only current items: the vault's versions go.
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/rotate", v.0),
        &t,
        json!({ "keys": [{ "user_id": me, "wrapped_key": "a2V5", "key_kind": "account" }], "items": [x1] }),
    )
    .await;
    assert_eq!(stored_versions(&state, &x).await, 0);
    edit_item(&app, &t, &x, v, "x2").await;
    assert_eq!(stored_versions(&state, &x).await, 1);

    // A move to another vault starts afresh; deleting for good leaves nothing.
    edit_item(&app, &t, &x, w, "x3").await;
    assert_eq!(stored_versions(&state, &x).await, 0);
    edit_item(&app, &t, &x, w, "x4").await;
    assert_eq!(versions(&app, &t, &x).await.len(), 1);
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{x}/permanent"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(stored_versions(&state, &x).await, 0);

    // Deleting the vault, or the trash sweeper, takes them too.
    let (y, body) = new_item(w, "y");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    edit_item(&app, &t, &y, w, "y1").await;
    let (z, body) = new_item(v, "z");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    edit_item(&app, &t, &z, v, "z1").await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{z}"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(stored_versions(&state, &z).await, 2);
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v2}"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(stored_versions(&state, &y).await, 0);
    assert_eq!(
        admin_set(&app, json!({ "trash_days": 1 })).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
        .bind(crate::db::now() - 2 * 86_400)
        .bind(&z)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(crate::vault::purge_trash(&state).await.unwrap(), 1);
    assert_eq!(stored_versions(&state, &z).await, 0);
    let emptied = of_type(&stored_events(&state).await, "trash.emptied")
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        (&emptied[0]["actor_id"], &emptied[0]["data"]),
        (&json!(null), &json!({ "count": 1, "days": 1 }))
    );
}

#[tokio::test]
async fn versions_count_toward_the_owners_storage() {
    let app = app().await;
    let c = register(&app, "vq@example.com", "pw-vq-123456").await;
    let t = token(&app, "vq@example.com", "pw-vq-123456").await;
    let v = (c.vault_id.as_str(), &c.vault_key);
    let size =
        |b: &Value| (b["key"].as_str().unwrap().len() + b["data"].as_str().unwrap().len()) as i64;
    let (x, b0) = new_item(v, "x");
    ok(&app, Method::POST, "/api/items", &t, b0.clone()).await;
    let b1 = edit_item(&app, &t, &x, v, &"y".repeat(600_000)).await;
    let usage = ok(&app, Method::GET, "/api/account", &t, json!(null)).await["usage"].clone();
    assert_eq!(
        usage,
        json!({ "item_count": 1, "storage_bytes": size(&b0) + size(&b1), "attachment_bytes": 0 })
    );
    let (_, users) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    let row = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "vq@example.com")
        .unwrap()
        .clone();
    assert_eq!(row["storage_bytes"], size(&b0) + size(&b1));

    // At the limit, growing is refused (history included), editing still works.
    assert_eq!(
        admin_set(&app, json!({ "max_storage_mb_per_user": 1 }))
            .await
            .0,
        StatusCode::OK
    );
    let (s, r) = call(
        &app,
        Method::PUT,
        &format!("/api/items/{x}"),
        Some(&t),
        item_body(&x, v, &"z".repeat(700_000)),
    )
    .await;
    assert_eq!(
        (s, &r["error"]),
        (StatusCode::FORBIDDEN, &json!("quota_exceeded"))
    );
    edit_item(&app, &t, &x, v, &"z".repeat(500_000)).await;
}

#[tokio::test]
async fn deleting_a_vault_or_its_owner_withdraws_invitations() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "wd-a@example.com", "pw-alice-1").await;
    register(&app, "wd-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "wd-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "wd-b@example.com", "pw-bobby-1").await;
    let a = user_id(&app, &ta).await;
    let (v2, k2) = new_vault(&app, &alice, &ta).await;
    let (x, body) = new_item((&v2, &k2), "x");
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    edit_item(&app, &ta, &x, (&v2, &k2), "x1").await;
    assert_eq!(
        share(&app, &alice, &ta, "wd-b@example.com", "read").await.0,
        StatusCode::OK
    );
    let (s, _) = share_vault(&app, (&v2, &k2), &ta, "wd-b@example.com", "write", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(invitations(&synced(&app, &tb).await).len(), 2);

    // The vault goes: so does its invitation, and Bob is told.
    let before = rev_of(&app, &tb).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{v2}"),
        &ta,
        json!(null),
    )
    .await;
    assert!(rev_of(&app, &tb).await > before);
    let left = synced(&app, &tb).await;
    assert_eq!(invitations(&left).len(), 1);
    assert_eq!(invitations(&left)[0]["vault_id"], alice.vault_id.as_str());
    assert_eq!(stored_versions(&state, &x).await, 0);

    // Alice deletes her account: her last vault and its invitation go too.
    let before = rev_of(&app, &tb).await;
    let reauth = reauth_token(&app, "wd-a@example.com", "pw-alice-1", &ta).await;
    let (s, v) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&ta),
        &[("x-reauth-token", reauth.as_str())],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(rev_of(&app, &tb).await > before);
    assert!(invitations(&synced(&app, &tb).await).is_empty());
    let events = stored_events(&state).await;
    let deleted = of_type(&events, "account.deleted");
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["actor_id"], a);
}

/// A sign-in to `email` that fails at the last step, sent from `ip`.
async fn failed_login_from(app: &Router, ip: &str, email: &str) {
    let (_, pre) = call(
        app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": email }),
    )
    .await;
    let kdf: KdfParams = serde_json::from_value(pre["kdf"].clone()).unwrap();
    let master = derive_master_keys(
        "not the password",
        None,
        pre["account_id"].as_str().unwrap(),
        &kdf,
        false,
    )
    .unwrap();
    let start = opaque::login_start(&master.login).unwrap();
    let (_, resp) = call(
        app,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": start.message }),
    )
    .await;
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
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn owners_see_where_attempts_on_their_account_came_from() {
    let (app, state) = app_with_state().await;
    register(&app, "where@example.com", "pw-where-123").await;
    failed_login_from(&app, "192.0.2.44", "where@example.com").await;
    state.failures.flush().await;
    let t = token(&app, "where@example.com", "pw-where-123").await;
    let id = user_id(&app, &t).await;
    let (s, _) = call_from(
        &app,
        "10.9.8.7",
        Method::POST,
        &format!("/api/admin/users/{id}/two-factor/reset"),
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let mine = all_pages(&app, &t, "/api/account/events", 50).await;
    let failed = mine
        .iter()
        .find(|e| e["type"] == "auth.signin_failed")
        .unwrap();
    assert_eq!(
        (&failed["ip"], &failed["data"], &failed["actor"]),
        (
            &json!("192.0.2.44"),
            &json!({ "reason": "password", "count": 1 }),
            &json!(null)
        )
    );
    let reset = mine
        .iter()
        .find(|e| e["type"] == "admin.two_step_reset")
        .unwrap();
    assert!(
        reset.get("ip").is_none(),
        "the admin page's address stays hidden: {reset}"
    );
    let (_, page) = call(
        &app,
        Method::GET,
        "/api/admin/events?type=admin.two_step_reset",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(page["events"][0]["ip"], "10.9.8.7");
}

// ------------------------------------------------------------------- sends

/// A Send body with stand-in ciphertext (the server never reads it), deleted
/// after `days`.
fn send_body(days: i64) -> Value {
    json!({
        "name": b64(b"encrypted name"),
        "data": b64(b"encrypted text"),
        "owner_key": b64(b"wrapped send key"),
        "delete_at": crate::db::now() + days * 86_400,
    })
}

/// `send_body(7)` with the fields of `extra` set (or replaced).
fn send_with(extra: Value) -> Value {
    let mut body = send_body(7);
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// Create a Send (must succeed); returns its owner view.
async fn new_send(app: &Router, token: &str, extra: Value) -> Value {
    ok(app, Method::POST, "/api/sends", token, send_with(extra)).await
}

/// The public page info of a Send, asked from `ip`.
async fn send_info(app: &Router, ip: &str, id: &str) -> (StatusCode, Value) {
    call_from(
        app,
        ip,
        Method::GET,
        &format!("/api/public/sends/{id}"),
        None,
        json!(null),
    )
    .await
}

/// Open a Send from `ip`, with the password's verifier if given.
async fn open_send(
    app: &Router,
    ip: &str,
    id: &str,
    verifier: Option<&str>,
) -> (StatusCode, Value) {
    let body = match verifier {
        Some(v) => json!({ "verifier": v }),
        None => json!({}),
    };
    call_from(
        app,
        ip,
        Method::POST,
        &format!("/api/public/sends/{id}/access"),
        None,
        body,
    )
    .await
}

async fn my_send(app: &Router, token: &str, id: &str) -> Value {
    ok(
        app,
        Method::GET,
        &format!("/api/sends/{id}"),
        token,
        json!(null),
    )
    .await
}

async fn change_send(app: &Router, token: &str, id: &str, body: Value) -> (StatusCode, Value) {
    call(
        app,
        Method::PUT,
        &format!("/api/sends/{id}"),
        Some(token),
        body,
    )
    .await
}

#[tokio::test]
async fn a_send_opens_through_its_link_and_counts_each_view() {
    let (app, state) = app_with_state().await;
    register(&app, "send-a@example.com", "pw-send-a-1").await;
    let t = token(&app, "send-a@example.com", "pw-send-a-1").await;
    let created = new_send(&app, &t, json!({})).await;
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 22, "128 random bits, base64url");
    assert_eq!(created["path"], format!("/send/{id}"));
    assert_eq!(
        (
            &created["kind"],
            &created["views"],
            &created["available"],
            &created["has_password"],
            &created["max_views"],
            &created["expires_at"],
            &created["data"],
        ),
        (
            &json!("text"),
            &json!(0),
            &json!(true),
            &json!(false),
            &json!(null),
            &json!(null),
            &json!(b64(b"encrypted text")),
        )
    );
    let size = b64(b"encrypted name").len()
        + b64(b"encrypted text").len()
        + b64(b"wrapped send key").len();
    assert_eq!(created["size"], size);
    assert!(created.get("access_verifier").is_none());

    // The owner's list has it, without the text.
    let list = ok(&app, Method::GET, "/api/sends", &t, json!(null)).await;
    let sends = list["sends"].as_array().unwrap();
    assert_eq!(sends.len(), 1);
    assert_eq!(sends[0]["id"], id.as_str());
    assert!(sends[0].get("data").is_none(), "{list}");

    // Anyone with the link: first what the page shows (never the text), then the text.
    let ip = "203.0.113.5";
    let (s, info) = send_info(&app, ip, &id).await;
    assert_eq!(s, StatusCode::OK, "{info}");
    assert_eq!(
        info,
        json!({
            "id": id, "kind": "text", "name": b64(b"encrypted name"), "needs_password": false,
            "access_salt": null, "expires_at": null, "delete_at": created["delete_at"],
            "sender": "send-a@example.com",
        })
    );
    for n in 1..=2 {
        let (s, v) = open_send(&app, ip, &id, None).await;
        assert_eq!(
            (s, v),
            (
                StatusCode::OK,
                json!({ "kind": "text", "name": b64(b"encrypted name"), "data": b64(b"encrypted text") })
            )
        );
        assert_eq!(my_send(&app, &t, &id).await["views"], n);
    }
    assert_eq!(
        send_info(&app, ip, &id).await.1["needs_password"],
        false,
        "the page info counts no view"
    );
    assert_eq!(my_send(&app, &t, &id).await["views"], 2);

    // The sender can hide their email; a disabled Send answers like an unknown one.
    let (s, v) = change_send(&app, &t, &id, json!({ "hide_email": true })).await;
    assert_eq!((s, &v["hide_email"]), (StatusCode::OK, &json!(true)), "{v}");
    assert_eq!(send_info(&app, ip, &id).await.1["sender"], json!(null));
    let (_, v) = change_send(&app, &t, &id, json!({ "disabled": true })).await;
    assert_eq!(
        (&v["disabled"], &v["available"]),
        (&json!(true), &json!(false))
    );
    for other in [id.as_str(), "AAAAAAAAAAAAAAAAAAAAAA", "not-a-send"] {
        for (s, v) in [
            send_info(&app, ip, other).await,
            open_send(&app, ip, other, None).await,
        ] {
            assert_eq!(
                (s, &v["error"], &v["message"]),
                (
                    StatusCode::NOT_FOUND,
                    &json!("not_found"),
                    &json!("not found")
                ),
                "{other}"
            );
        }
    }
    // The owner view may go back whole with one change: read-only fields are ignored.
    let mut whole = my_send(&app, &t, &id).await;
    whole["disabled"] = json!(false);
    whole["views"] = json!(0);
    let (s, v) = change_send(&app, &t, &id, whole).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["available"], &v["views"], &v["data"]),
        (&json!(true), &json!(2), &json!(b64(b"encrypted text")))
    );

    // Nobody else can read, change or delete it.
    register(&app, "send-b@example.com", "pw-send-b-1").await;
    let tb = token(&app, "send-b@example.com", "pw-send-b-1").await;
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (s, _) = call(
            &app,
            method.clone(),
            &format!("/api/sends/{id}"),
            Some(&tb),
            json!({ "disabled": true }),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method}");
    }
    let theirs = ok(&app, Method::GET, "/api/sends", &tb, json!(null)).await;
    assert_eq!(theirs["sends"], json!([]));
    assert_eq!(my_send(&app, &t, &id).await["available"], true);

    // Deleted: gone for everyone.
    ok(
        &app,
        Method::DELETE,
        &format!("/api/sends/{id}"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(send_info(&app, ip, &id).await.0, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/sends/{id}"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The owner's log: created, updated (field names only), opened (a count: no
    // address, no app), deleted.
    let mine = all_pages(&app, &t, "/api/account/events", 50).await;
    let opened: Vec<&Value> = mine
        .iter()
        .filter(|e| e["type"] == "send.accessed")
        .collect();
    assert_eq!(opened.len(), 1, "one row per Send and hour");
    assert_eq!(opened[0]["data"], json!({ "send": id, "count": 2 }));
    assert!(
        opened[0].get("ip").is_none()
            && opened[0]["actor"].is_null()
            && opened[0]["client"].is_null(),
        "{}",
        opened[0]
    );
    let stored = stored_events(&state).await;
    assert!(
        of_type(&stored, "send.accessed")
            .iter()
            .all(|e| e["ip"].is_null())
    );
    let updates: Vec<&Value> = of_type(&stored, "send.updated")
        .into_iter()
        .map(|e| &e["data"])
        .collect();
    assert_eq!(
        updates,
        [
            &json!({ "send": id, "changed": ["hide_email"] }),
            &json!({ "send": id, "changed": ["disabled"] }),
            &json!({ "send": id, "changed": ["disabled"] }),
        ]
    );
    for kind in ["send.created", "send.deleted"] {
        let e = of_type(&stored, kind);
        assert_eq!(e.len(), 1, "{kind}");
        assert_eq!(e[0]["data"], json!({ "send": id }), "{kind}");
        assert!(e[0]["actor_id"].is_string(), "{kind}");
    }
}

#[tokio::test]
async fn send_passwords_and_view_limits() {
    let app = app().await;
    register(&app, "send-pw@example.com", "pw-send-pw-1").await;
    let t = token(&app, "send-pw@example.com", "pw-send-pw-1").await;
    let s = new_send(
        &app,
        &t,
        json!({ "access_salt": "c2FsdHNhbHRzYWx0", "access_verifier": "verifier-one-1", "max_views": 2 }),
    )
    .await;
    let id = s["id"].as_str().unwrap().to_owned();
    assert_eq!(
        (&s["has_password"], &s["access_salt"], &s["max_views"]),
        (&json!(true), &json!("c2FsdHNhbHRzYWx0"), &json!(2))
    );
    assert!(s.get("access_verifier").is_none(), "{s}");
    let ip = "198.51.100.20";
    // Before the password, the page learns that one is needed, and its salt; not
    // even the (encrypted) name.
    let (_, info) = send_info(&app, ip, &id).await;
    assert_eq!(
        (&info["needs_password"], &info["access_salt"], &info["name"]),
        (&json!(true), &json!("c2FsdHNhbHRzYWx0"), &json!(null))
    );
    assert!(info.as_object().unwrap().contains_key("name"), "{info}");
    // A missing or wrong verifier: 401 without the name, and no view counted.
    for wrong in [None, Some("verifier-two-2")] {
        let (s, v) = open_send(&app, ip, &id, wrong).await;
        assert_eq!(
            (s, &v["error"], &v["message"]),
            (
                StatusCode::UNAUTHORIZED,
                &json!("wrong_password"),
                &json!("wrong password")
            )
        );
        assert!(v.get("name").is_none() && v.get("data").is_none(), "{v}");
    }
    assert_eq!(my_send(&app, &t, &id).await["views"], 0);
    // The right password opens it, name included. Two views, then used up: the
    // same 404 as an unknown Send.
    for _ in 0..2 {
        let (s, v) = open_send(&app, ip, &id, Some("verifier-one-1")).await;
        assert_eq!(
            (s, v),
            (
                StatusCode::OK,
                json!({ "kind": "text", "name": b64(b"encrypted name"), "data": b64(b"encrypted text") })
            )
        );
    }
    assert_eq!(
        open_send(&app, ip, &id, Some("verifier-one-1")).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(send_info(&app, ip, &id).await.0, StatusCode::NOT_FOUND);
    let mine = my_send(&app, &t, &id).await;
    assert_eq!(
        (&mine["views"], &mine["available"]),
        (&json!(2), &json!(false))
    );

    // One more view allowed; then no limit and no password.
    let ip = "198.51.100.21";
    let (_, v) = change_send(&app, &t, &id, json!({ "max_views": 3 })).await;
    assert_eq!(v["available"], true, "{v}");
    assert_eq!(
        open_send(&app, ip, &id, Some("verifier-one-1")).await.0,
        StatusCode::OK
    );
    assert_eq!(
        open_send(&app, ip, &id, Some("verifier-one-1")).await.0,
        StatusCode::NOT_FOUND
    );
    let (s, v) = change_send(
        &app,
        &t,
        &id,
        json!({ "max_views": null, "access_verifier": null }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            &v["has_password"],
            &v["access_salt"],
            &v["max_views"],
            &v["available"]
        ),
        (&json!(false), &json!(null), &json!(null), &json!(true))
    );
    assert_eq!(open_send(&app, ip, &id, None).await.0, StatusCode::OK);
    let (_, info) = send_info(&app, ip, &id).await;
    assert_eq!(
        (&info["needs_password"], &info["access_salt"], &info["name"]),
        (&json!(false), &json!(null), &json!(b64(b"encrypted name"))),
        "without a password the page shows the name at once"
    );
    let bare = app
        .clone()
        .oneshot(
            Request::post(format!("/api/public/sends/{id}/access"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bare.status(),
        StatusCode::OK,
        "no body needed without a password"
    );

    // A new password replaces the old one; half a password changes nothing.
    let ip = "198.51.100.22";
    let (s, v) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_salt": "bmV3c2FsdG5ld3NhbHQ", "access_verifier": "verifier-three-3" }),
    )
    .await;
    assert_eq!(
        (s, &v["has_password"]),
        (StatusCode::OK, &json!(true)),
        "{v}"
    );
    assert_eq!(send_info(&app, ip, &id).await.1["name"], json!(null));
    assert_eq!(
        open_send(&app, ip, &id, Some("verifier-one-1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = open_send(&app, ip, &id, Some("verifier-three-3")).await;
    assert_eq!(
        (s, &v["name"]),
        (StatusCode::OK, &json!(b64(b"encrypted name")))
    );
    let (s, _) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_verifier": "verifier-four-4" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a verifier needs its salt");
    let (s, _) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_salt": "b3RoZXJzYWx0b3RoZXI" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "and a new salt its verifier");
    let mine = my_send(&app, &t, &id).await;
    let (s, same) = change_send(&app, &t, &id, mine.clone()).await;
    assert_eq!(
        (s, &same),
        (StatusCode::OK, &mine),
        "sending it back unchanged changes nothing"
    );
    let (s, _) = change_send(
        &app,
        &t,
        &id,
        json!({ "access_verifier": "x", "access_salt": "bmV3c2FsdG5ld3NhbHQ" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "too short");
    assert_eq!(
        open_send(&app, ip, &id, Some("verifier-three-3")).await.0,
        StatusCode::OK
    );
    // Only a hash of the verifier is kept.
    let mine = my_send(&app, &t, &id).await;
    assert!(!mine.to_string().contains("verifier-three-3"), "{mine}");
}

#[tokio::test]
async fn sends_follow_their_dates_the_admin_switch_and_their_owner() {
    let (app, state) = app_with_state().await;
    register(&app, "send-d@example.com", "pw-send-d-1").await;
    let t = token(&app, "send-d@example.com", "pw-send-d-1").await;
    let now = crate::db::now();
    for (bad, why) in [
        (json!({ "delete_at": now - 10 }), "deletion in the past"),
        (
            json!({ "delete_at": now + 31 * 86_400 + 7200 }),
            "past send_max_days",
        ),
        (json!({ "expires_at": now - 1 }), "expiry in the past"),
        (json!({ "max_views": 0 }), "no views"),
        (json!({ "kind": "file" }), "files come later"),
        (json!({ "data": "" }), "no text"),
        (
            json!({ "access_salt": "salt-salt-salt" }),
            "half a password",
        ),
        (
            json!({ "data": "A".repeat(1024 * 1024 + 1) }),
            "text over 1 MiB",
        ),
    ] {
        let (s, v) = call(&app, Method::POST, "/api/sends", Some(&t), send_with(bad)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}: {v}");
    }
    new_send(&app, &t, json!({ "data": "A".repeat(1024 * 1024) })).await;
    // The admin's longest time applies at once.
    assert_eq!(
        admin_set(&app, json!({ "send_max_days": 1 })).await.0,
        StatusCode::OK
    );
    let (s, _) = call(&app, Method::POST, "/api/sends", Some(&t), send_body(2)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let s1 = new_send(
        &app,
        &t,
        json!({ "delete_at": now + 86_400, "expires_at": now + 3600 }),
    )
    .await;
    let id1 = s1["id"].as_str().unwrap().to_owned();
    let (s, _) = change_send(&app, &t, &id1, json!({ "delete_at": now + 2 * 86_400 })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // Expired: it no longer opens, but its owner sees it until it's deleted.
    let ip = "192.0.2.80";
    assert_eq!(send_info(&app, ip, &id1).await.0, StatusCode::OK);
    sqlx::query("UPDATE sends SET expires_at = $1 WHERE id = $2")
        .bind(now - 1)
        .bind(&id1)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(send_info(&app, ip, &id1).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        open_send(&app, ip, &id1, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(my_send(&app, &t, &id1).await["available"], false);
    // Past its deletion date the sweeper deletes it, and the owner's log says so.
    sqlx::query("UPDATE sends SET delete_at = $1 WHERE id = $2")
        .bind(now - 1)
        .bind(&id1)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(crate::sends::purge(&state).await.unwrap(), 1);
    let (s, _) = call(
        &app,
        Method::GET,
        &format!("/api/sends/{id1}"),
        Some(&t),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let events = stored_events(&state).await;
    let swept = of_type(&events, "send.deleted");
    assert_eq!(swept.len(), 1);
    assert_eq!(
        (
            &swept[0]["data"],
            &swept[0]["actor_id"],
            &swept[0]["target_user_id"]
        ),
        (
            &json!({ "send": id1, "reason": "deletion_date" }),
            &json!(null),
            &json!(user_id(&app, &t).await)
        )
    );
    assert_eq!(crate::sends::purge(&state).await.unwrap(), 0);

    // The admin turns Send off: links stop working and new Sends are refused;
    // existing ones can still be listed and deleted.
    assert_eq!(
        admin_set(&app, json!({ "send_max_days": 30 })).await.0,
        StatusCode::OK
    );
    let s2 = new_send(&app, &t, json!({})).await;
    let id2 = s2["id"].as_str().unwrap().to_owned();
    assert_eq!(
        admin_set(&app, json!({ "sends": false })).await.0,
        StatusCode::OK
    );
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        !config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("sends"))
    );
    assert_eq!(send_info(&app, ip, &id2).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        open_send(&app, ip, &id2, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (s, v) = call(&app, Method::POST, "/api/sends", Some(&t), send_body(1)).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("sends_disabled"))
    );
    let list = ok(&app, Method::GET, "/api/sends", &t, json!(null)).await;
    assert!(
        list["sends"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["available"] == false)
    );
    assert_eq!(
        admin_set(&app, json!({ "sends": true })).await.0,
        StatusCode::OK
    );
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("sends"))
    );
    assert_eq!(send_info(&app, ip, &id2).await.0, StatusCode::OK);

    // A disabled owner's Sends stop opening; a deleted account takes its Sends along.
    let uid = user_id(&app, &t).await;
    let admin = Some("test-admin");
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("/api/admin/users/{uid}/disable"),
        admin,
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(send_info(&app, ip, &id2).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        open_send(&app, ip, &id2, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("/api/admin/users/{uid}/enable"),
        admin,
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(send_info(&app, ip, &id2).await.0, StatusCode::OK);
    let (_, overview) = call(&app, Method::GET, "/api/admin/overview", admin, json!(null)).await;
    assert_eq!(overview["sends"], 2);
    let t = token(&app, "send-d@example.com", "pw-send-d-1").await;
    let reauth = reauth_token(&app, "send-d@example.com", "pw-send-d-1", &t).await;
    let (s, _) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(send_info(&app, ip, &id2).await.0, StatusCode::NOT_FOUND);
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sends")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn visitors_at_once_never_get_more_views_than_allowed() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let state = App::new(config).await.unwrap();
    let app = crate::router(state.clone());
    register(&app, "send-c@example.com", "pw-send-c-1").await;
    let t = token(&app, "send-c@example.com", "pw-send-c-1").await;
    let s = new_send(
        &app,
        &t,
        json!({ "max_views": 3, "access_salt": "c2FsdHNhbHRzYWx0", "access_verifier": "verifier-one-1" }),
    )
    .await;
    let id = s["id"].as_str().unwrap().to_owned();
    let tasks: Vec<_> = (0..16)
        .map(|n| {
            let (app, id) = (app.clone(), id.clone());
            tokio::spawn(async move {
                open_send(
                    &app,
                    &format!("192.0.2.{}", n + 1),
                    &id,
                    Some("verifier-one-1"),
                )
                .await
                .0
            })
        })
        .collect();
    let mut answers = Vec::new();
    for task in tasks {
        answers.push(task.await.unwrap());
    }
    let opened = answers.iter().filter(|s| **s == StatusCode::OK).count();
    assert_eq!(opened, 3, "{answers:?}");
    assert!(
        answers
            .iter()
            .all(|s| *s == StatusCode::OK || *s == StatusCode::NOT_FOUND),
        "{answers:?}"
    );
    assert_eq!(my_send(&app, &t, &id).await["views"], 3);
    let counted: i64 = stored_events(&state)
        .await
        .iter()
        .filter(|e| e["type"] == "send.accessed")
        .map(|e| e["data"]["count"].as_i64().unwrap())
        .sum();
    assert_eq!(counted, 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn opening_sends_is_rate_limited() {
    let app = app().await;
    register(&app, "send-r@example.com", "pw-send-r-1").await;
    let t = token(&app, "send-r@example.com", "pw-send-r-1").await;
    let open = new_send(&app, &t, json!({})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Ten tries a minute per address and Send…
    for _ in 0..10 {
        assert_eq!(
            open_send(&app, "192.0.2.50", &open, None).await.0,
            StatusCode::OK
        );
    }
    let (s, v) = open_send(&app, "192.0.2.50", &open, None).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited"))
    );
    assert_eq!(
        open_send(&app, "192.0.2.51", &open, None).await.0,
        StatusCode::OK
    );
    // …and 60 public requests a minute per address, whatever they ask for.
    for n in 0..59 {
        let (s, _) = send_info(&app, "192.0.2.52", &open).await;
        assert_eq!(s, StatusCode::OK, "{n}");
    }
    assert_eq!(
        send_info(&app, "192.0.2.52", "AAAAAAAAAAAAAAAAAAAAAA")
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send_info(&app, "192.0.2.52", &open).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        open_send(&app, "192.0.2.52", &open, None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Wrong passwords from many addresses together: after 100 in an hour the Send
    // answers 429 to everyone, the right password too.
    let locked = new_send(
        &app,
        &t,
        json!({ "access_salt": "c2FsdHNhbHRzYWx0", "access_verifier": "verifier-one-1" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for n in 0..100 {
        let ip = format!("198.18.{}.{}", n / 10, n % 10 + 1);
        let (s, _) = open_send(&app, &ip, &locked, Some("a-wrong-guess")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{n}");
    }
    let (s, v) = open_send(&app, "198.18.99.1", &locked, Some("verifier-one-1")).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited"))
    );
    assert_eq!(my_send(&app, &t, &locked).await["views"], 0);
    // Other Sends are not affected.
    assert_eq!(
        open_send(&app, "198.18.99.1", &open, None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_send_page_is_the_web_vault_without_a_referrer() {
    let dir = std::env::temp_dir().join(format!("passauth-web-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>PassAuth</title>",
    )
    .unwrap();
    let mut config = test_config().await;
    config.web_vault_dir = Some(dir.to_str().unwrap().to_owned());
    let app = crate::router(App::new(config).await.unwrap());
    let home = get_raw(&app, "/").await;
    assert_eq!(home.headers()["referrer-policy"], "same-origin");
    let csp = home.headers()["content-security-policy"].clone();
    for path in [
        "/send/AAAAAAAAAAAAAAAAAAAAAA",
        "/send/AAAAAAAAAAAAAAAAAAAAAA/",
    ] {
        // No sign-in: the page is the web vault's own document.
        let resp = get_raw(&app, path).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let h = resp.headers();
        assert_eq!(h["referrer-policy"], "no-referrer", "{path}");
        assert_eq!(h["x-robots-tag"], "noindex, nofollow", "{path}");
        assert_eq!(h["content-security-policy"], csp, "{path}");
        assert_eq!(h["x-frame-options"], "DENY", "{path}");
        assert_eq!(h["cache-control"], "no-cache", "{path}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"<!doctype html>"), "{path}");
    }
    // Its API needs no account either (an unknown Send is a JSON 404).
    let resp = get_raw(&app, "/api/public/sends/AAAAAAAAAAAAAAAAAAAAAA").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sends_count_toward_the_storage_quota() {
    let app = app().await;
    register(&app, "send-q@example.com", "pw-send-q-1").await;
    let t = token(&app, "send-q@example.com", "pw-send-q-1").await;
    assert_eq!(
        admin_set(&app, json!({ "max_storage_mb_per_user": 1 }))
            .await
            .0,
        StatusCode::OK
    );
    let big = new_send(&app, &t, json!({ "data": "A".repeat(600 * 1024) })).await;
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/sends",
        Some(&t),
        send_with(json!({ "data": "A".repeat(600 * 1024) })),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("quota_exceeded"))
    );
    let small = new_send(&app, &t, json!({})).await;
    let account = ok(&app, Method::GET, "/api/account", &t, json!(null)).await;
    let used = big["size"].as_i64().unwrap() + small["size"].as_i64().unwrap();
    assert_eq!(account["usage"]["storage_bytes"], used, "{account}");
    let (_, users) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(users["users"][0]["storage_bytes"], used);
    // Growing a Send past the limit is refused; shrinking always passes.
    let small_id = small["id"].as_str().unwrap();
    let big_id = big["id"].as_str().unwrap();
    let (s, v) = change_send(
        &app,
        &t,
        small_id,
        json!({ "data": "B".repeat(500 * 1024) }),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("quota_exceeded"))
    );
    assert_eq!(
        my_send(&app, &t, small_id).await["data"],
        b64(b"encrypted text")
    );
    let (s, _) = change_send(&app, &t, big_id, json!({ "data": "A".repeat(100 * 1024) })).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = change_send(
        &app,
        &t,
        small_id,
        json!({ "data": "B".repeat(500 * 1024) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

// ---------------------------------------------------------------- policies

/// Register with the bundle changed by `tweak` (e.g. its KDF), with or without a
/// Secret Key; returns the `register/finish` answer.
async fn try_register(
    app: &Router,
    email: &str,
    pw: &str,
    secret_key: bool,
    tweak: impl FnOnce(&mut AccountBundle),
) -> (StatusCode, Value) {
    let (s, init) = call(
        app,
        Method::POST,
        "/api/auth/register/init",
        None,
        json!({ "email": email }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{init}");
    let account_id = init["account_id"].as_str().unwrap();
    let mut acct = AccountBundle::create_with_kdf(account_id, pw, secret_key, fast_kdf()).unwrap();
    tweak(&mut acct.bundle);
    let start = opaque::register_start(&acct.master.login).unwrap();
    let (_, resp) = call(
        app,
        Method::POST,
        "/api/auth/register/start",
        None,
        json!({ "registration_id": init["registration_id"], "message": start.message }),
    )
    .await;
    let upload = opaque::register_finish(
        &start.state,
        &acct.master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let vault_id = uuid::Uuid::new_v4().to_string();
    let (vault_key, wrapped) = acct.unlocked.new_vault_key(&vault_id).unwrap();
    let meta = b64(&vault_key
        .encrypt(br#"{"name":"Personal"}"#, b"meta")
        .unwrap());
    call(
        app,
        Method::POST,
        "/api/auth/register/finish",
        None,
        json!({
            "registration_id": init["registration_id"], "upload": upload, "bundle": acct.bundle,
            "vault": { "id": vault_id, "meta": meta, "wrapped_key": wrapped },
        }),
    )
    .await
}

/// `/account/keys/start` + `/finish` with a fresh reauth token: the account's
/// bundle with a new KDF salt, changed by `tweak`.
async fn change_keys(
    app: &Router,
    email: &str,
    pw: &str,
    token: &str,
    tweak: impl FnOnce(&mut AccountBundle),
) -> (StatusCode, Value) {
    let account = ok(app, Method::GET, "/api/account", token, json!(null)).await;
    let (_, l) = login(app, email, pw, "dev-keys").await;
    let mut bundle: AccountBundle = serde_json::from_value(l["bundle"].clone()).unwrap();
    assert_eq!(bundle.account_id, account["user_id"].as_str().unwrap());
    bundle.kdf.salt = b64(&random_salt());
    let master = derive_master_keys(pw, None, &bundle.account_id, &bundle.kdf, false).unwrap();
    tweak(&mut bundle);
    let start = opaque::register_start(&master.login).unwrap();
    let resp = ok(
        app,
        Method::POST,
        "/api/account/keys/start",
        token,
        json!({ "message": start.message }),
    )
    .await;
    let upload = opaque::register_finish(
        &start.state,
        &master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let reauth = reauth_token(app, email, pw, token).await;
    call_with(
        app,
        Method::POST,
        "/api/account/keys/finish",
        Some(token),
        &[("x-reauth-token", &reauth)],
        json!({ "upload": upload, "bundle": bundle }),
    )
    .await
}

fn random_salt() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

async fn violations(app: &Router, token: &str) -> Value {
    ok(app, Method::GET, "/api/account", token, json!(null)).await["policy_violations"].clone()
}

#[tokio::test]
async fn policies_are_admin_settings_and_reach_the_apps() {
    let (app, state) = app_with_state().await;
    let admin = Some("test-admin");
    let (s, v) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["switches"],
        json!({
            "sends": { "default": true }, "require_two_step": { "default": false },
            "require_secret_key": { "default": false }, "disable_export": { "default": false },
            "attachments": { "default": true }, "emergency_access": { "default": true },
            "login_with_device": { "default": true },
        })
    );
    for (name, on) in [
        ("sends", true),
        ("require_two_step", false),
        ("require_secret_key", false),
        ("disable_export", false),
    ] {
        assert_eq!(v[name], on, "{name}");
    }
    for (name, range) in [
        (
            "send_max_days",
            json!({ "min": 1, "max": 365, "default": 30 }),
        ),
        (
            "min_kdf_memory_mib",
            json!({ "min": 64, "max": 1024, "default": 64 }),
        ),
        (
            "min_kdf_iterations",
            json!({ "min": 3, "max": 20, "default": 3 }),
        ),
        (
            "master_password_min_length",
            json!({ "min": 10, "max": 128, "default": 10 }),
        ),
        (
            "max_vault_timeout_minutes",
            json!({ "min": 0, "max": 43200, "default": 0 }),
        ),
    ] {
        assert_eq!(v["ranges"][name], range, "{name}");
        assert_eq!(v[name], range["default"], "{name}");
    }
    for bad in [
        json!({ "require_two_step": "yes" }),
        json!({ "disable_export": 1 }),
        json!({ "master_password_min_length": 8 }),
        json!({ "min_kdf_memory_mib": 32 }),
        json!({ "send_max_days": 0 }),
    ] {
        let (s, e) = admin_set(&app, bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {e}");
    }
    let (s, v) = admin_set(
        &app,
        json!({ "master_password_min_length": 14, "max_vault_timeout_minutes": 60, "disable_export": true, "require_two_step": null }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(
        config["policies"],
        json!({
            "require_two_step": false, "require_secret_key": false,
            "min_kdf_memory_mib": 64, "min_kdf_iterations": 3,
            "master_password_min_length": 14, "max_vault_timeout_minutes": 60,
            "disable_export": true,
        })
    );
    // The whole object from `GET` goes back as it was (`switches` is read-only).
    let (_, all) = call(&app, Method::GET, "/api/admin/settings", admin, json!(null)).await;
    assert_eq!(admin_set(&app, all).await.0, StatusCode::OK);
    let changed: Vec<Value> = of_type(&stored_events(&state).await, "admin.settings_changed")
        .iter()
        .map(|e| e["data"]["changed"].clone())
        .collect();
    assert_eq!(
        changed,
        [json!([
            "master_password_min_length",
            "max_vault_timeout_minutes",
            "disable_export"
        ])],
        "names only, and only what changed"
    );
}

#[tokio::test]
async fn policies_are_kept_across_a_restart() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let app = crate::router(App::new(config.clone()).await.unwrap());
    let (s, v) = admin_set(
        &app,
        json!({ "sends": false, "require_secret_key": true, "min_kdf_iterations": 5, "send_max_days": 7 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    drop(app);
    let app = crate::router(App::new(config).await.unwrap());
    let (_, v) = call(
        &app,
        Method::GET,
        "/api/admin/settings",
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(
        (
            &v["sends"],
            &v["require_secret_key"],
            &v["min_kdf_iterations"],
            &v["send_max_days"],
            &v["require_two_step"]
        ),
        (
            &json!(false),
            &json!(true),
            &json!(5),
            &json!(7),
            &json!(false)
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn required_two_step_login_leaves_only_its_setup() {
    let app = app().await;
    register(&app, "2s-a@example.com", "pw-two-step-1").await;
    register(&app, "2s-b@example.com", "pw-two-step-2").await;
    register(&app, "2s-c@example.com", "pw-two-step-3").await;
    let ta = token(&app, "2s-a@example.com", "pw-two-step-1").await;
    let tb = token(&app, "2s-b@example.com", "pw-two-step-2").await;
    let tc = token(&app, "2s-c@example.com", "pw-two-step-3").await;
    enable_totp(&app, "2s-b@example.com", "pw-two-step-2", &tb).await;
    assert_eq!(violations(&app, &ta).await, json!([]));
    assert_eq!(
        admin_set(&app, json!({ "require_two_step": true })).await.0,
        StatusCode::OK
    );
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(config["policies"]["require_two_step"], true);

    // Without a method everything but its setup answers 403 two_step_required…
    let refused = |token: String| {
        let app = app.clone();
        async move {
            for (method, path, body) in [
                (Method::GET, "/api/sync", json!(null)),
                (Method::GET, "/api/sync/revision", json!(null)),
                (Method::GET, "/api/ws", json!(null)),
                (Method::GET, "/api/sends", json!(null)),
                (Method::POST, "/api/sends", send_body(1)),
                (Method::PUT, "/api/account/profile", json!({ "name": "x" })),
                (Method::GET, "/api/account/sessions", json!(null)),
                (Method::GET, "/api/account/events", json!(null)),
                (Method::POST, "/api/account/2fa/recovery", json!(null)),
                (
                    Method::POST,
                    "/api/account/devices/dev-1/forget",
                    json!(null),
                ),
            ] {
                let (s, v) = call(&app, method.clone(), path, Some(&token), body).await;
                assert_eq!(
                    (s, &v["error"]),
                    (StatusCode::FORBIDDEN, &json!("two_step_required")),
                    "{method} {path}: {v}"
                );
            }
        }
    };
    refused(ta.clone()).await;
    // …while the account (saying what it lacks) and the config still answer.
    assert_eq!(violations(&app, &ta).await, json!(["two_step"]));
    let (s, _) = call(&app, Method::GET, "/api/config", Some(&ta), json!(null)).await;
    assert_eq!(s, StatusCode::OK);
    // Accounts with a method are not affected.
    assert_eq!(
        call(&app, Method::GET, "/api/sync", Some(&tb), json!(null))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(violations(&app, &tb).await, json!([]));
    // Signing in still works, and the new session is held to the same rule.
    let (s, l) = login(&app, "2s-a@example.com", "pw-two-step-1", "dev-2").await;
    assert_eq!(s, StatusCode::OK, "{l}");
    refused(l["access_token"].as_str().unwrap().to_owned()).await;
    // Signing out works without a method.
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/logout",
        Some(&tc),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Setting up an authenticator (after confirming the master password, which
    // works while the policy holds the account back) lifts it at once…
    enable_totp(&app, "2s-a@example.com", "pw-two-step-1", &ta).await;
    assert_eq!(
        call(&app, Method::GET, "/api/sync", Some(&ta), json!(null))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(violations(&app, &ta).await, json!([]));
    // …and the last method can't be turned off while the server requires one.
    let reauth = reauth_token(&app, "2s-a@example.com", "pw-two-step-1", &ta).await;
    let (s, v) = call_with(
        &app,
        Method::DELETE,
        "/api/account/2fa/totp",
        Some(&ta),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::FORBIDDEN, &json!("two_step_required")),
        "{v}"
    );
    let account = ok(&app, Method::GET, "/api/account", &ta, json!(null)).await;
    assert_eq!(
        (&account["two_factor"], &account["recovery_codes_left"]),
        (&json!(["totp"]), &json!(10))
    );
    // With the policy off it can.
    assert_eq!(
        admin_set(&app, json!({ "require_two_step": false }))
            .await
            .0,
        StatusCode::OK
    );
    let reauth = reauth_token(&app, "2s-a@example.com", "pw-two-step-1", &ta).await;
    let (s, _) = call_with(
        &app,
        Method::DELETE,
        "/api/account/2fa/totp",
        Some(&ta),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        call(&app, Method::GET, "/api/sync", Some(&ta), json!(null))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn secret_key_and_kdf_policies_apply_to_new_account_keys() {
    let app = app().await;
    // An account from before the policies: no Secret Key, the tests' quick KDF.
    register(&app, "pol-old@example.com", "pw-policy-1").await;
    let t = token(&app, "pol-old@example.com", "pw-policy-1").await;
    let (s, v) = admin_set(
        &app,
        json!({ "require_secret_key": true, "min_kdf_iterations": 4 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Registration: without a Secret Key, or with weaker key derivation, refused.
    let (s, v) = try_register(&app, "pol-1@example.com", "pw-policy-2", false, |b| {
        b.kdf.iterations = 4
    })
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("secret_key_required")),
        "{v}"
    );
    let (s, v) = try_register(&app, "pol-2@example.com", "pw-policy-2", true, |_| {}).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("kdf_too_weak")),
        "{v}"
    );
    let (s, v) = try_register(&app, "pol-3@example.com", "pw-policy-2", true, |b| {
        b.kdf.iterations = 4
    })
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // The older account still signs in, and learns what to change.
    let (s, l) = login(&app, "pol-old@example.com", "pw-policy-1", "dev-2").await;
    assert_eq!(s, StatusCode::OK, "{l}");
    assert_eq!(violations(&app, &t).await, json!(["secret_key", "kdf"]));
    // A master password change has to meet them too.
    let (s, v) = change_keys(&app, "pol-old@example.com", "pw-policy-1", &t, |b| {
        b.kdf.iterations = 4
    })
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("secret_key_required")),
        "{v}"
    );
    let (s, v) = change_keys(&app, "pol-old@example.com", "pw-policy-1", &t, |b| {
        b.secret_key_enabled = true
    })
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("kdf_too_weak")),
        "{v}"
    );
    assert_eq!(
        violations(&app, &t).await,
        json!(["secret_key", "kdf"]),
        "nothing changed"
    );
    let (s, v) = change_keys(&app, "pol-old@example.com", "pw-policy-1", &t, |b| {
        b.secret_key_enabled = true;
        b.kdf.iterations = 4;
    })
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(violations(&app, &t).await, json!([]));

    // Memory above the core's 64 MiB floor counts too; the floors themselves add nothing.
    assert_eq!(
        admin_set(&app, json!({ "min_kdf_memory_mib": 128 }))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(violations(&app, &t).await, json!(["kdf"]));
    let (s, v) = try_register(&app, "pol-4@example.com", "pw-policy-2", true, |b| {
        b.kdf.iterations = 4
    })
    .await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::BAD_REQUEST, &json!("kdf_too_weak")),
        "{v}"
    );
    let (s, v) = try_register(&app, "pol-5@example.com", "pw-policy-2", true, |b| {
        b.kdf.iterations = 4;
        b.kdf.memory_kib = 128 * 1024;
    })
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // Unknown emails get a made-up prelogin shaped like a new account's.
    let fake = || async {
        let (_, v) = call(
            &app,
            Method::POST,
            "/api/auth/prelogin",
            None,
            json!({ "email": "nobody@example.com" }),
        )
        .await;
        (
            v["kdf"]["memory_kib"].clone(),
            v["kdf"]["iterations"].clone(),
            v["secret_key_required"].clone(),
        )
    };
    let (s, _) = admin_set(
        &app,
        json!({ "min_kdf_memory_mib": 256, "min_kdf_iterations": 5 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(fake().await, (json!(256 * 1024), json!(5), json!(true)));
    let (s, _) = admin_set(
        &app,
        json!({ "require_secret_key": false, "min_kdf_iterations": 3, "min_kdf_memory_mib": 64 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(violations(&app, &t).await, json!([]));
    let (s, v) = try_register(&app, "pol-6@example.com", "pw-policy-2", false, |_| {}).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(fake().await, (json!(128 * 1024), json!(3), json!(false)));
}

// ----------------------------------------------------------------- devices

/// [`login`] sending a remember-this-device token.
async fn login_remembered(
    app: &Router,
    email: &str,
    pw: &str,
    device: &str,
    remember: &str,
) -> Value {
    let (_, pre) = call(
        app,
        Method::POST,
        "/api/auth/prelogin",
        None,
        json!({ "email": email }),
    )
    .await;
    let kdf: KdfParams = serde_json::from_value(pre["kdf"].clone()).unwrap();
    let master =
        derive_master_keys(pw, None, pre["account_id"].as_str().unwrap(), &kdf, false).unwrap();
    let start = opaque::login_start(&master.login).unwrap();
    let (_, resp) = call(
        app,
        Method::POST,
        "/api/auth/login/start",
        None,
        json!({ "email": email, "message": start.message }),
    )
    .await;
    let fin = opaque::login_finish(
        &start.state,
        &master.login,
        resp["message"].as_str().unwrap(),
    )
    .unwrap();
    let (s, v) = call(
        app,
        Method::POST,
        "/api/auth/login/finish",
        None,
        json!({
            "login_id": resp["login_id"], "message": fin, "remember_token": remember,
            "device": { "id": device, "name": "Test device", "kind": "cli" },
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

#[tokio::test]
async fn forgetting_a_device_signs_it_out_and_drops_its_remember_token() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("forget@example.com", "pw-forget-1");
    register(&app, email, pw).await;
    let t1 = token(&app, email, pw).await;
    let codes = enable_totp(&app, email, pw, &t1).await;
    // dev-2 signs in with a recovery code and "remember this device".
    let (s, l) = login(&app, email, pw, "dev-2").await;
    assert_eq!(
        (s, &l["two_factor_required"]),
        (StatusCode::OK, &json!(true)),
        "{l}"
    );
    let v = ok(&app, Method::POST, "/api/auth/2fa/verify", "", json!({
        "two_factor_token": l["two_factor_token"], "provider": "recovery", "code": codes[0], "remember": true,
    }))
    .await;
    let (t2, remember) = (
        v["access_token"].as_str().unwrap().to_owned(),
        v["remember_token"].as_str().unwrap().to_owned(),
    );
    let refresh2 = v["refresh_token"].clone();
    let l = login_remembered(&app, email, pw, "dev-2", &remember).await;
    assert!(l["access_token"].is_string(), "remembered: {l}");

    // Forget dev-2: its sessions end, and its token no longer skips two-step login.
    let v = ok(
        &app,
        Method::POST,
        "/api/account/devices/dev-2/forget",
        &t1,
        json!(null),
    )
    .await;
    assert_eq!(v, json!({ "ok": true, "signed_out": 2, "current": false }));
    assert_eq!(
        call(&app, Method::GET, "/api/account", Some(&t2), json!(null))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": refresh2 }),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&app, Method::GET, "/api/account", Some(&t1), json!(null))
            .await
            .0,
        StatusCode::OK
    );
    let l = login_remembered(&app, email, pw, "dev-2", &remember).await;
    assert_eq!(l["two_factor_required"], true, "{l}");
    let events = stored_events(&state).await;
    let forgot = of_type(&events, "session.device_forgotten");
    assert_eq!(forgot.len(), 1);
    assert_eq!(forgot[0]["data"], json!({ "device": "dev-2", "count": 2 }));

    // Unknown devices, and other people's: 404.
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/account/devices/nope/forget",
        Some(&t1),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    register(&app, "forget-b@example.com", "pw-forget-2").await;
    let tb = token(&app, "forget-b@example.com", "pw-forget-2").await;
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/account/devices/dev-2/forget",
        Some(&tb),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Forgetting the device in use signs this session out too.
    let v = ok(
        &app,
        Method::POST,
        "/api/account/devices/dev-1/forget",
        &t1,
        json!(null),
    )
    .await;
    assert_eq!((&v["signed_out"], &v["current"]), (&json!(1), &json!(true)));
    assert_eq!(
        call(&app, Method::GET, "/api/account", Some(&t1), json!(null))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, Method::GET, "/api/account", Some(&tb), json!(null))
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_sweeper_forgets_unused_devices_and_expired_remember_tokens() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("sweep-dev@example.com", "pw-sweep-1");
    register(&app, email, pw).await;
    let mut sessions = Vec::new();
    for device in ["dev-1", "dev-2", "dev-3"] {
        let (s, l) = login(&app, email, pw, device).await;
        assert_eq!(s, StatusCode::OK, "{l}");
        sessions.push(l);
    }
    // dev-2 signs out; dev-1 and dev-3 keep their sessions.
    let t2 = sessions[1]["access_token"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            Method::POST,
            "/api/auth/logout",
            Some(t2),
            json!(null)
        )
        .await
        .0,
        StatusCode::OK
    );
    let now = crate::db::now();
    for (sql, value) in [
        ("UPDATE devices SET last_seen = $1", now - 91 * 86_400),
        (
            "UPDATE devices SET remember_hash = 'expired', remember_expires = $1 WHERE id = 'dev-3'",
            now - 1,
        ),
        (
            "UPDATE devices SET remember_hash = 'valid', remember_expires = $1 WHERE id = 'dev-1'",
            now + 3600,
        ),
    ] {
        sqlx::query(sql)
            .bind(value)
            .execute(&state.db)
            .await
            .unwrap();
    }
    crate::forget_old_devices(&state.db).await.unwrap();
    let left: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id, remember_hash FROM devices ORDER BY id")
            .fetch_all(&state.db)
            .await
            .unwrap();
    assert_eq!(
        left,
        [
            ("dev-1".to_owned(), Some("valid".to_owned())),
            ("dev-3".to_owned(), None)
        ],
        "dev-2 had no session and wasn't seen for 90 days"
    );
    // Refreshing a session marks its device as seen.
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/refresh",
        None,
        json!({ "refresh_token": sessions[0]["refresh_token"] }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let seen: i64 = sqlx::query_scalar("SELECT last_seen FROM devices WHERE id = 'dev-1'")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(seen >= now, "{seen}");
}
