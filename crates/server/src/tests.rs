//! End-to-end API tests: a real client flow (core crypto + OPAQUE) against
//! the router with an in-memory SQLite database.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use passauth_core::crypto::SymmetricKey;
use passauth_core::item::{EncryptedItem, ITEM_FORMAT, Item, Login, b64};
use passauth_core::kdf::KdfParams;
use passauth_core::keys::{AccountBundle, UnlockedAccount, derive_master_keys, share_vault_key};
use passauth_core::opaque;
use passauth_core::totp::Totp;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::Config;
use crate::state::App;

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
    call(app, Method::POST, "/api/auth/login/finish", None, json!({
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
    let vk = c.unlocked.open_vault_key(&c.vault_id, wk).unwrap();
    assert_eq!(back.decrypt(&vk).unwrap(), item);

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
    let (s, en) = call(
        &app,
        Method::POST,
        "/api/account/2fa/totp/enable",
        Some(&t),
        json!({ "code": totp.generate(now) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{en}");
    let recovery = en["recovery_codes"][0].as_str().unwrap().to_owned();

    let (s, l) = login(&app, "dave@example.com", "pw-dave-12", "d2").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(l["two_factor_required"], true);
    assert!(l.get("access_token").is_none());
    let tf = l["two_factor_token"].clone();

    // The code used to enable is consumed; the next step's code works.
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/verify",
        None,
        json!({ "two_factor_token": tf, "provider": "totp", "code": "000000" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
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
    let resp = get_raw(&app, "/api/icons/github.com").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(resp.headers()["cache-control"], "no-store");
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
    let (_, found) = call(
        app,
        Method::GET,
        &format!("/api/users/lookup?email={email}"),
        Some(owner_token),
        json!(null),
    )
    .await;
    let sealed = share_vault_key(
        &owner.vault_id,
        &owner.vault_key,
        found["public_key"].as_str().unwrap(),
    )
    .unwrap();
    call(
        app,
        Method::POST,
        &format!("/api/vaults/{}/members", owner.vault_id),
        Some(owner_token),
        json!({ "user_id": found["user_id"], "role": role, "sealed_key": sealed }),
    )
    .await
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

#[tokio::test]
async fn deleting_an_account_keeps_vaults_with_another_owner() {
    let (app, state) = app_with_state().await;
    let alice = register(&app, "del-a@example.com", "pw-alice-1").await;
    register(&app, "del-b@example.com", "pw-bobby-1").await;
    let ta = token(&app, "del-a@example.com", "pw-alice-1").await;
    let tb = token(&app, "del-b@example.com", "pw-bobby-1").await;
    let (s, _) = share(&app, &alice, &ta, "del-b@example.com", "admin").await;
    assert_eq!(s, StatusCode::OK);
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
    let (s, _) = call(
        &app,
        Method::POST,
        "/api/account/2fa/totp/enable",
        Some(&t),
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
