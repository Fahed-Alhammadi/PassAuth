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

async fn app() -> Router {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("warn")
        .try_init();
    crate::router(App::new(Config::for_tests()).await.unwrap())
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
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
    assert_eq!(v["config"]["database"], "sqlite");
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
        ..Config::for_tests()
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
    let state = App::new(Config::for_tests()).await.unwrap();
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
