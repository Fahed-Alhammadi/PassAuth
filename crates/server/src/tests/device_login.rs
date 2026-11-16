//! Approve a sign-in from another device: the whole flow with and without two-step
//! login, remembered devices, access codes, the approval's proof, the single
//! exchange, denial, expiry and the sweeper, what ends open sign-ins, answers and
//! exchanges racing each other, emails without an account, rate limits and the cap on
//! shown requests, addresses, live-sync notices, the two-step policy and the admin
//! switch.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};

use passauth_core::crypto::{KeyPair, random_bytes, seal_to};

use super::*;
use crate::auth_requests::{CHALLENGE_AAD, SERVER_LIMIT_KEY, fingerprint_phrase};

/// The new device: a key pair made for one request, and the access code it polls with.
struct NewDevice {
    keys: KeyPair,
    code: String,
    id: String,
}

impl NewDevice {
    fn new(id: &str) -> Self {
        Self {
            keys: KeyPair::generate().unwrap(),
            code: b64(&random_bytes::<32>().unwrap()),
            id: id.into(),
        }
    }

    fn public_key(&self) -> String {
        b64(&self.keys.public_bytes())
    }

    /// The words this device shows, derived from its own key.
    fn phrase(&self) -> String {
        fingerprint_phrase(&self.keys.public_bytes())
    }

    fn body(&self, email: &str) -> Value {
        json!({
            "email": email, "public_key": self.public_key(), "access_code": self.code,
            "device_id": self.id, "device_name": "New phone", "device_kind": "ios",
        })
    }

    /// Opens the sealed account key it was handed.
    fn open(&self, sealed: &Value, request: &str) -> SymmetricKey {
        let sealed = unb64(sealed.as_str().expect("a sealed key")).unwrap();
        SymmetricKey::from_slice(&self.keys.open(&sealed, request.as_bytes()).unwrap()).unwrap()
    }
}

/// A request from TCP peer `ip` (IPv4 or IPv6) with extra headers.
async fn call_peer(
    app: &Router,
    ip: &str,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::from(body.to_string())).unwrap();
    let peer = std::net::SocketAddr::new(ip.parse().unwrap(), 40000);
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

/// Another address for each request [`ask`] makes, so tests that aren't about the
/// limits never meet them.
fn next_address() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!("198.18.{}.{}", (n >> 8) & 0xff, n & 0xff)
}

/// `POST /api/auth/requests` that must succeed; returns the body.
async fn ask(app: &Router, nd: &NewDevice, email: &str) -> Value {
    ask_with(app, nd.body(email)).await
}

async fn ask_with(app: &Router, body: Value) -> Value {
    let (s, v) = ask_from(app, &next_address(), body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// `POST /api/auth/requests` from TCP peer `ip`.
async fn ask_from(app: &Router, ip: &str, body: Value) -> (StatusCode, Value) {
    call_peer(app, ip, Method::POST, "/api/auth/requests", &[], body).await
}

fn id_of(request: &Value) -> String {
    request["id"].as_str().unwrap().to_owned()
}

/// Polls request `id` with access code `code` (in its header).
async fn poll(app: &Router, id: &str, code: &str) -> (StatusCode, Value) {
    call_with(
        app,
        Method::GET,
        &format!("/api/auth/requests/{id}"),
        None,
        &[("x-passauth-access-code", code)],
        json!(null),
    )
    .await
}

/// [`poll`] that must succeed; returns the body.
async fn polled(app: &Router, id: &str, nd: &NewDevice) -> Value {
    let (s, v) = poll(app, id, &nd.code).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

/// The account's pending requests, as its apps list them.
async fn listed(app: &Router, token: &str) -> Vec<Value> {
    ok(
        app,
        Method::GET,
        "/api/account/auth-requests",
        token,
        json!(null),
    )
    .await["requests"]
        .as_array()
        .unwrap()
        .clone()
}

/// Request `id` as the account's apps list it.
async fn listed_one(app: &Router, token: &str, id: &str) -> Value {
    listed(app, token)
        .await
        .into_iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("request {id} is listed"))
}

async fn answer(app: &Router, token: &str, id: &str, body: Value) -> (StatusCode, Value) {
    call(
        app,
        Method::POST,
        &format!("/api/account/auth-requests/{id}"),
        Some(token),
        body,
    )
    .await
}

/// The approving app seals the account key to the request's public key. (The
/// associated data is this test's own; the apps' scheme belongs to the core.)
fn seal(c: &Client, public_key: &str, id: &str) -> String {
    let pk: [u8; 32] = unb64(public_key).unwrap().try_into().unwrap();
    b64(&seal_to(&pk, c.unlocked.account_key.as_bytes(), id.as_bytes()).unwrap())
}

/// The approving app opens a listed request's challenge with the account's own
/// private key.
fn proof(c: &Client, req: &Value) -> String {
    let aad = [CHALLENGE_AAD, req["id"].as_str().unwrap().as_bytes()].concat();
    let sealed = unb64(req["challenge"].as_str().unwrap()).unwrap();
    b64(&c.unlocked.keypair.open(&sealed, &aad).unwrap())
}

/// What an unlocked app sends to approve `req` (as listed) of `nd`.
fn approval(c: &Client, nd: &NewDevice, req: &Value) -> Value {
    let id = req["id"].as_str().unwrap();
    json!({ "approve": true, "sealed_key": seal(c, &nd.public_key(), id), "proof": proof(c, req) })
}

/// Approve request `id` of `nd` from the session of `token`.
async fn approve(app: &Router, c: &Client, token: &str, nd: &NewDevice, id: &str) {
    let req = listed_one(app, token, id).await;
    let (s, v) = answer(app, token, id, approval(c, nd, &req)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({ "id": id, "status": "approved" }));
}

async fn session_id(app: &Router, token: &str) -> String {
    ok(
        app,
        Method::GET,
        "/api/account/sessions",
        token,
        json!(null),
    )
    .await["current"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn keys(v: &Value) -> BTreeSet<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

/// Moves every request `secs` seconds further into the past.
async fn age(state: &AppState, secs: i64) {
    sqlx::query(
        "UPDATE auth_requests SET created_at = created_at - $1, expires_at = expires_at - $1",
    )
    .bind(secs)
    .execute(&state.db)
    .await
    .unwrap();
}

/// What the server still keeps of request `id`: (status, sealed key, remember-token
/// hash, address).
async fn kept(
    state: &AppState,
    id: &str,
) -> (String, Option<String>, Option<String>, Option<String>) {
    sqlx::query_as("SELECT status, sealed_key, remember_hash, ip FROM auth_requests WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_new_device_signs_in_when_a_signed_in_one_approves() {
    let (app, state) = app_with_state().await;
    let email = "dl-a@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let me = user_id(&app, &ta).await;
    let nd = NewDevice::new("new-phone");
    let (s, r) = call_with(
        &app,
        Method::POST,
        "/api/auth/requests",
        None,
        &[("x-passauth-client", "ios/1.2.3")],
        nd.body(email),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let id = id_of(&r);
    assert_eq!(
        keys(&r),
        BTreeSet::from(["id", "fingerprint_phrase", "expires_at"])
    );
    // Both screens show the same words, each derived on its own device.
    assert_eq!(r["fingerprint_phrase"], nd.phrase());
    let expires = r["expires_at"].as_i64().unwrap();
    assert!((expires - (crate::db::now() + 900)).abs() <= 2, "{r}");
    assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "pending" }));

    let list = listed(&app, &ta).await;
    assert_eq!(list.len(), 1, "{list:?}");
    let req = &list[0];
    let pk: [u8; 32] = unb64(req["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        fingerprint_phrase(&pk),
        nd.phrase(),
        "re-derived on the approving app"
    );
    assert_eq!(
        req,
        &json!({
            "id": id, "public_key": nd.public_key(), "fingerprint_phrase": nd.phrase(),
            "challenge": req["challenge"], "device_name": "New phone", "device_kind": "ios",
            "client": "ios/1.2.3", "ip": null, "created_at": req["created_at"],
            "expires_at": expires,
        })
    );
    // A fresh challenge each time, the same value inside.
    let again = listed_one(&app, &ta, &id).await;
    assert_ne!(again["challenge"], req["challenge"]);
    assert_eq!(proof(&alice, &again), proof(&alice, req));

    approve(&app, &alice, &ta, &nd, &id).await;
    assert!(listed(&app, &ta).await.is_empty());
    let v = polled(&app, &id, &nd).await;
    assert_eq!(v["status"], "approved", "{v}");
    assert_eq!(
        nd.open(&v["sealed_key"], &id).as_bytes(),
        alice.unlocked.account_key.as_bytes()
    );
    assert_eq!((&v["user_id"], &v["email"]), (&json!(me), &json!(email)));
    assert!(v["bundle"].is_object() && v["refresh_token"].is_string());
    assert!(v.get("two_factor_required").is_none());
    // A normal session of the new device.
    let tn = v["access_token"].as_str().unwrap();
    assert!(vault_in(&synced(&app, tn).await, &alice.vault_id).is_some());
    let sessions = ok(&app, Method::GET, "/api/account/sessions", &ta, json!(null)).await;
    assert!(
        sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["device_id"] == "new-phone" && s["device_kind"] == "ios"),
        "{sessions}"
    );

    // Exactly once: nothing of the device's is left on the server.
    assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "used" }));
    assert_eq!(kept(&state, &id).await, ("used".into(), None, None, None));
    let (s, e) = answer(&app, &ta, &id, json!({ "approve": false })).await;
    assert_eq!((s, &e["error"]), (StatusCode::CONFLICT, &json!("conflict")));
    // The approval sent again by the session that gave it (a retry, sealed anew)
    // still succeeds.
    let (s, _) = answer(&app, &ta, &id, approval(&alice, &nd, req)).await;
    assert_eq!(s, StatusCode::OK);

    let events = stored_events(&state).await;
    let created = of_type(&events, "auth.request_created");
    assert_eq!(created.len(), 1);
    assert_eq!(
        (
            &created[0]["actor_id"],
            &created[0]["target_user_id"],
            &created[0]["client"],
            &created[0]["data"]
        ),
        (
            &json!(null),
            &json!(me),
            &json!("ios/1.2.3"),
            &json!({ "request": id, "device_kind": "ios" })
        )
    );
    let approved = of_type(&events, "auth.request_approved");
    assert_eq!(approved.len(), 1, "a retry writes no second event");
    assert_eq!(
        (
            &approved[0]["actor_id"],
            &approved[0]["session_id"],
            &approved[0]["data"]
        ),
        (
            &json!(me),
            &json!(session_id(&app, &ta).await),
            &json!({ "request": id, "device_kind": "ios" })
        )
    );
    let signed_in = of_type(&events, "auth.signed_in");
    assert_eq!(
        signed_in.last().unwrap()["data"],
        json!({
            "two_step": null, "device_kind": "ios", "new_device": true,
            "method": "device", "request": id,
        })
    );
    assert!(
        signed_in[0]["data"].get("method").is_none(),
        "password sign-ins keep their data"
    );
}

#[tokio::test]
async fn approving_needs_the_opened_challenge() {
    let (app, state) = app_with_state().await;
    let email = "dl-proof@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let nd = NewDevice::new("p1");
    let id = id_of(&ask(&app, &nd, email).await);
    let other = NewDevice::new("p2");
    let other_id = id_of(&ask(&app, &other, email).await);
    let req = listed_one(&app, &ta, &id).await;
    let other_req = listed_one(&app, &ta, &other_id).await;
    // A session without the account's keys (stolen, say) can list the request but
    // can't open its challenge: nothing it sends instead is accepted.
    let sealed = seal(&alice, &nd.public_key(), &id);
    for (proof, status) in [
        (json!(null), StatusCode::BAD_REQUEST),
        (
            json!(b64(&random_bytes::<32>().unwrap())),
            StatusCode::FORBIDDEN,
        ),
        (req["challenge"].clone(), StatusCode::FORBIDDEN),
        (json!(proof(&alice, &other_req)), StatusCode::FORBIDDEN),
    ] {
        let body = json!({ "approve": true, "sealed_key": sealed, "proof": proof });
        let (s, e) = answer(&app, &ta, &id, body).await;
        assert_eq!(s, status, "{e}");
    }
    assert_eq!(polled(&app, &id, &nd).await["status"], "pending");
    // Denying needs no proof.
    let (s, _) = answer(&app, &ta, &other_id, json!({ "approve": false })).await;
    assert_eq!(s, StatusCode::OK);
    approve(&app, &alice, &ta, &nd, &id).await;
    assert!(polled(&app, &id, &nd).await["access_token"].is_string());
    assert_eq!(
        of_type(&stored_events(&state).await, "auth.request_approved").len(),
        1
    );
}

#[tokio::test]
async fn two_step_login_still_applies_and_the_key_comes_only_with_the_session() {
    let (app, state) = app_with_state().await;
    let email = "dl-2fa@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let recovery = enable_totp(&app, email, "pw-alice-1", &ta).await;

    let nd = NewDevice::new("tablet");
    let id = id_of(&ask(&app, &nd, email).await);
    approve(&app, &alice, &ta, &nd, &id).await;
    let v = polled(&app, &id, &nd).await;
    assert_eq!(
        keys(&v),
        BTreeSet::from([
            "status",
            "two_factor_required",
            "two_factor_token",
            "providers"
        ]),
        "no key and no session before two-step login: {v}"
    );
    assert_eq!(
        (&v["status"], &v["two_factor_required"], &v["providers"]),
        (
            &json!("approved"),
            &json!(true),
            &json!(["totp", "recovery"])
        )
    );
    assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "used" }));
    let tf = v["two_factor_token"].clone();
    let verify = |code: &str, remember: bool| {
        let body = json!({ "two_factor_token": tf, "provider": "recovery", "code": code, "remember": remember });
        let app = app.clone();
        async move { call(&app, Method::POST, "/api/auth/2fa/verify", None, body).await }
    };
    let (s, e) = verify("wrong-code", false).await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_code"))
    );
    assert!(e.get("sealed_key").is_none());
    let (s, v) = verify(&recovery[0], true).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        nd.open(&v["sealed_key"], &id).as_bytes(),
        alice.unlocked.account_key.as_bytes()
    );
    assert!(v["access_token"].is_string());
    let remember = v["remember_token"].as_str().unwrap().to_owned();
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "auth.signed_in").last().unwrap()["data"],
        json!({
            "two_step": "recovery", "device_kind": "ios", "new_device": true,
            "method": "device", "request": id,
        })
    );

    // The device is remembered now: its next request skips two-step login...
    let again = NewDevice::new("tablet");
    let mut body = again.body(email);
    body["remember_token"] = json!(remember);
    let id2 = id_of(&ask_with(&app, body.clone()).await);
    approve(&app, &alice, &ta, &again, &id2).await;
    let v = polled(&app, &id2, &again).await;
    assert!(v["access_token"].is_string(), "{v}");
    assert_eq!(
        again.open(&v["sealed_key"], &id2).as_bytes(),
        alice.unlocked.account_key.as_bytes()
    );
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "auth.signed_in").last().unwrap()["data"]["two_step"],
        "remembered_device"
    );
    // ...but not with a wrong token, nor with the token from another device.
    for (device, token) in [("tablet", "not-the-token"), ("laptop", remember.as_str())] {
        let other = NewDevice::new(device);
        let mut body = other.body(email);
        body["remember_token"] = json!(token);
        let id3 = id_of(&ask_with(&app, body).await);
        approve(&app, &alice, &ta, &other, &id3).await;
        let v = polled(&app, &id3, &other).await;
        assert_eq!(v["two_factor_required"], true, "{device}: {v}");
    }
}

#[tokio::test]
async fn polling_needs_the_requests_own_access_code_in_its_header() {
    let app = app().await;
    register(&app, "dl-code@example.com", "pw-alice-1").await;
    let nd = NewDevice::new("d1");
    let id = id_of(&ask(&app, &nd, "dl-code@example.com").await);
    let other = NewDevice::new("d2");
    let other_id = id_of(&ask(&app, &other, "dl-code@example.com").await);
    for (request, code) in [
        (id.as_str(), ""),
        (id.as_str(), "wrong"),
        (id.as_str(), other.code.as_str()),
        (other_id.as_str(), nd.code.as_str()),
        ("no-such-request", nd.code.as_str()),
    ] {
        let (s, e) = poll(&app, request, code).await;
        assert_eq!(
            (s, &e["error"]),
            (StatusCode::NOT_FOUND, &json!("not_found")),
            "{request} {code}"
        );
    }
    // Never in the URL (proxies log query strings).
    for path in [
        format!("/api/auth/requests/{id}"),
        format!("/api/auth/requests/{id}?code={}", nd.code),
    ] {
        let (s, _) = call(&app, Method::GET, &path, None, json!(null)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(polled(&app, &id, &nd).await["status"], "pending");
}

#[tokio::test]
async fn a_denied_request_tells_the_new_device_and_stays_denied() {
    let (app, state) = app_with_state().await;
    let email = "dl-deny@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let tb = token(&app, email, "pw-alice-1").await;
    let nd = NewDevice::new("stranger");
    let mut body = nd.body(email);
    body["remember_token"] = json!("some-token");
    let id = id_of(&ask_with(&app, body).await);
    let req = listed_one(&app, &ta, &id).await;
    let (s, v) = answer(&app, &ta, &id, json!({ "approve": false })).await;
    assert_eq!(
        (s, v),
        (StatusCode::OK, json!({ "id": id, "status": "denied" }))
    );
    assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "denied" }));
    assert_eq!(kept(&state, &id).await, ("denied".into(), None, None, None));
    assert!(listed(&app, &ta).await.is_empty());
    // Approving afterwards is refused, from any device; denying again from the
    // same session is a retry.
    for t in [&ta, &tb] {
        let (s, _) = answer(&app, t, &id, approval(&alice, &nd, &req)).await;
        assert_eq!(s, StatusCode::CONFLICT);
    }
    let (s, _) = answer(&app, &tb, &id, json!({ "approve": false })).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = answer(&app, &ta, &id, json!({ "approve": false })).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "denied" }));
    let denied = stored_events(&state).await;
    let denied = of_type(&denied, "auth.request_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(
        (&denied[0]["actor_id"], &denied[0]["data"]),
        (
            &json!(user_id(&app, &ta).await),
            &json!({ "request": id, "device_kind": "ios" })
        )
    );
    // Another account can't answer (or see) the request.
    register(&app, "dl-deny-b@example.com", "pw-bobby-1").await;
    let tother = token(&app, "dl-deny-b@example.com", "pw-bobby-1").await;
    let nd2 = NewDevice::new("stranger-2");
    let id2 = id_of(&ask(&app, &nd2, email).await);
    assert!(listed(&app, &tother).await.is_empty());
    let (s, _) = answer(&app, &tother, &id2, json!({ "approve": false })).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Approving needs the sealed key.
    let req2 = listed_one(&app, &ta, &id2).await;
    for sealed in [
        json!(null),
        json!(""),
        json!("not base64url!"),
        json!("A".repeat(4097)),
    ] {
        let body = json!({ "approve": true, "sealed_key": sealed, "proof": proof(&alice, &req2) });
        let (s, _) = answer(&app, &ta, &id2, body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{sealed}");
    }
    assert_eq!(polled(&app, &id2, &nd2).await["status"], "pending");
}

#[tokio::test]
async fn requests_expire_and_are_deleted_a_day_later() {
    let (app, state) = app_with_state().await;
    let email = "dl-exp@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    // One nobody answers, one approved but never taken.
    let waiting = NewDevice::new("w");
    let w = id_of(&ask(&app, &waiting, email).await);
    let taken_late = NewDevice::new("l");
    let mut body = taken_late.body(email);
    body["remember_token"] = json!("some-token");
    let l = id_of(&ask_with(&app, body).await);
    approve(&app, &alice, &ta, &taken_late, &l).await;
    age(&state, 901).await;
    assert_eq!(
        polled(&app, &w, &waiting).await,
        json!({ "status": "expired" })
    );
    assert_eq!(
        polled(&app, &l, &taken_late).await,
        json!({ "status": "expired" })
    );
    assert!(listed(&app, &ta).await.is_empty());
    let (s, e) = answer(&app, &ta, &w, json!({ "approve": false })).await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::BAD_REQUEST, &json!("expired"))
    );

    // The sweeper marks them, dropping what was never taken...
    crate::auth_requests::sweep(&state).await.unwrap();
    for id in [&w, &l] {
        assert_eq!(kept(&state, id).await, ("expired".into(), None, None, None));
    }
    // ...and deletes them a day after they expired.
    age(&state, 86_000).await;
    crate::auth_requests::sweep(&state).await.unwrap();
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM auth_requests")
            .fetch_one(&state.db)
            .await
            .unwrap()
    };
    assert_eq!(count().await, 2, "not before a full day");
    age(&state, 1_000).await;
    crate::auth_requests::sweep(&state).await.unwrap();
    assert_eq!(count().await, 0);
    let (s, _) = poll(&app, &w, &waiting.code).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_new_master_password_or_signing_out_the_others_ends_open_sign_ins() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("dl-end@example.com", "pw-alice-1");
    let alice = register(&app, email, pw).await;
    let ta = token(&app, email, pw).await;
    enable_totp(&app, email, pw, &ta).await;
    let ask_approved = |name: &'static str| {
        let (app, ta, alice) = (app.clone(), ta.clone(), &alice);
        async move {
            let nd = NewDevice::new(name);
            let id = id_of(&ask(&app, &nd, email).await);
            approve(&app, alice, &ta, &nd, &id).await;
            (nd, id)
        }
    };
    // A sign-in that waits for its two-step login: its token stops working.
    let dropped = |tf: Value| {
        let app = app.clone();
        async move {
            // Any code: a dropped sign-in fails before the code is looked at.
            let body =
                json!({ "two_factor_token": tf, "provider": "recovery", "code": "0000-0000" });
            let (s, e) = call(&app, Method::POST, "/api/auth/2fa/verify", None, body).await;
            assert_eq!(
                (s, &e["error"]),
                (StatusCode::BAD_REQUEST, &json!("expired")),
                "{e}"
            );
        }
    };
    for end in ["new master password", "sign out other sessions"] {
        // One nobody answered, one approved and not yet taken, one taken that
        // waits for its two-step login.
        let waiting = NewDevice::new("w");
        let w = id_of(&ask(&app, &waiting, email).await);
        let (approved, a) = ask_approved("a").await;
        let (at_two_step, t) = ask_approved("t").await;
        let tf = polled(&app, &t, &at_two_step).await["two_factor_token"].clone();
        assert!(tf.is_string(), "{end}");
        if end == "new master password" {
            change_password(&app, email, pw, &ta).await;
        } else {
            ok(
                &app,
                Method::POST,
                "/api/account/sessions/revoke-others",
                &ta,
                json!({}),
            )
            .await;
        }
        for (nd, id) in [(&waiting, &w), (&approved, &a)] {
            assert_eq!(
                polled(&app, id, nd).await,
                json!({ "status": "expired" }),
                "{end}"
            );
        }
        dropped(tf).await;
        // Out of the quarter of an hour that counts towards the shown requests.
        age(&state, 901).await;
        state.limiter.clear();
    }
}

/// A new master password (here the same one under a new key-derivation salt) from
/// the session of `token`, which stays signed in; works with two-step login on.
async fn change_password(app: &Router, email: &str, pw: &str, token: &str) {
    let mut bundle: AccountBundle =
        serde_json::from_value(synced(app, token).await["bundle"].clone()).unwrap();
    bundle.kdf.salt = b64(&random_salt());
    let master = derive_master_keys(pw, None, &bundle.account_id, &bundle.kdf, false).unwrap();
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
    let (s, v) = call_with(
        app,
        Method::POST,
        "/api/account/keys/finish",
        Some(token),
        &[("x-reauth-token", &reauth)],
        json!({ "upload": upload, "bundle": bundle }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn a_disabled_account_gets_no_session_and_no_key() {
    let (app, state) = app_with_state().await;
    let email = "dl-disabled@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let me = user_id(&app, &ta).await;
    let recovery = enable_totp(&app, email, "pw-alice-1", &ta).await;
    let late = NewDevice::new("late");
    let id = id_of(&ask(&app, &late, email).await);
    approve(&app, &alice, &ta, &late, &id).await;
    let tf = polled(&app, &id, &late).await["two_factor_token"].clone();
    // Disabled the moment the code arrives (as if in the same instant as the admin):
    // the code is right, but the account's row says no.
    sqlx::query("UPDATE users SET disabled = 1 WHERE id = $1")
        .bind(&me)
        .execute(&state.db)
        .await
        .unwrap();
    let (s, e) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/verify",
        None,
        json!({ "two_factor_token": tf, "provider": "recovery", "code": recovery[0] }),
    )
    .await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::FORBIDDEN, &json!("account_disabled"))
    );
    assert!(e.get("sealed_key").is_none() && e.get("access_token").is_none());
    sqlx::query("UPDATE users SET disabled = 0 WHERE id = $1")
        .bind(&me)
        .execute(&state.db)
        .await
        .unwrap();

    // Disabled by the admin with an approval waiting: nothing to exchange, even
    // after the account is enabled again.
    let nd = NewDevice::new("waiting");
    let id = id_of(&ask(&app, &nd, email).await);
    approve(&app, &alice, &ta, &nd, &id).await;
    let admin = Some("test-admin");
    for action in ["disable", "enable"] {
        let path = format!("/api/admin/users/{me}/{action}");
        let (s, _) = call(&app, Method::POST, &path, admin, json!(null)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(polled(&app, &id, &nd).await, json!({ "status": "expired" }));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_answer_wins_and_only_one_poll_gets_the_session() {
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let app = crate::router(App::new(config).await.unwrap());
    let email = "dl-race@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let mut tokens = Vec::new();
    for n in 0..6 {
        let (s, l) = login(&app, email, "pw-alice-1", &format!("dev-{n}")).await;
        assert_eq!(s, StatusCode::OK, "{l}");
        tokens.push(l["access_token"].as_str().unwrap().to_owned());
    }
    for round in 0..3 {
        let nd = NewDevice::new(&format!("contested-{round}"));
        let id = id_of(&ask(&app, &nd, email).await);
        let req = listed_one(&app, &tokens[0], &id).await;
        // Six devices answer at once, two of them "deny".
        let tasks: Vec<_> = tokens
            .iter()
            .enumerate()
            .map(|(n, t)| {
                let body = if n % 3 == 2 {
                    json!({ "approve": false })
                } else {
                    approval(&alice, &nd, &req)
                };
                let (app, t, id) = (app.clone(), t.clone(), id.clone());
                tokio::spawn(async move { answer(&app, &t, &id, body).await })
            })
            .collect();
        let mut wins = Vec::new();
        for task in tasks {
            let (s, v) = task.await.unwrap();
            match s {
                StatusCode::OK => wins.push(v["status"].as_str().unwrap().to_owned()),
                StatusCode::CONFLICT => assert_eq!(v["error"], "conflict"),
                other => panic!("round {round}: {other} {v}"),
            }
        }
        assert_eq!(wins.len(), 1, "round {round}: exactly one answer wins");
        let v = polled(&app, &id, &nd).await;
        assert_eq!(v["status"], wins[0].as_str(), "round {round}: {v}");
        if wins[0] == "approved" {
            assert_eq!(
                nd.open(&v["sealed_key"], &id).as_bytes(),
                alice.unlocked.account_key.as_bytes()
            );
        }
    }

    // Six polls race for one approved request: one session, five "used".
    let nd = NewDevice::new("raced");
    let id = id_of(&ask(&app, &nd, email).await);
    approve(&app, &alice, &tokens[0], &nd, &id).await;
    let polls: Vec<_> = (0..6)
        .map(|_| {
            let (app, id, code) = (app.clone(), id.clone(), nd.code.clone());
            tokio::spawn(async move { poll(&app, &id, &code).await })
        })
        .collect();
    let mut sessions = 0;
    for p in polls {
        let (s, v) = p.await.unwrap();
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["access_token"].is_string() {
            sessions += 1;
        } else {
            assert_eq!(v, json!({ "status": "used" }));
        }
    }
    assert_eq!(sessions, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn emails_without_an_account_get_the_same_answer_and_nobody_sees_them() {
    let (app, state) = app_with_state().await;
    let real = "dl-real@example.com";
    register(&app, real, "pw-alice-1").await;
    let ta = token(&app, real, "pw-alice-1").await;
    register(&app, "dl-off@example.com", "pw-alice-1").await;
    let off = user_id(&app, &token(&app, "dl-off@example.com", "pw-alice-1").await).await;
    let (s, _) = call(
        &app,
        Method::POST,
        &format!("/api/admin/users/{off}/disable"),
        Some("test-admin"),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    register(&app, "dl-unverified@example.com", "pw-alice-1").await;
    sqlx::query("UPDATE users SET email_verified = 0 WHERE email = 'dl-unverified@example.com'")
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(
        admin_set(&app, json!({ "signups_verify": true })).await.0,
        StatusCode::OK
    );

    let emails = [
        real,
        "dl-nobody@example.com",
        "dl-off@example.com",
        "DL-Unverified@example.com",
    ];
    let mut asked = Vec::new();
    for email in emails {
        let nd = NewDevice::new("same-device");
        let started = std::time::Instant::now();
        let (s, r) = call(
            &app,
            Method::POST,
            "/api/auth/requests",
            None,
            nd.body(email),
        )
        .await;
        let took = started.elapsed();
        assert_eq!(s, StatusCode::OK, "{email}: {r}");
        assert!(
            took >= std::time::Duration::from_millis(100),
            "{email}: {took:?}"
        );
        assert_eq!(
            keys(&r),
            BTreeSet::from(["id", "fingerprint_phrase", "expires_at"])
        );
        assert_eq!(r["fingerprint_phrase"], nd.phrase(), "{email}");
        assert!((r["expires_at"].as_i64().unwrap() - (crate::db::now() + 900)).abs() <= 2);
        assert_eq!(
            polled(&app, &id_of(&r), &nd).await,
            json!({ "status": "pending" })
        );
        asked.push((id_of(&r), nd));
    }
    // Only the real account hears about its request; nothing is logged for the others.
    let list = listed(&app, &ta).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], json!(asked[0].0));
    assert_eq!(
        of_type(&stored_events(&state).await, "auth.request_created").len(),
        1
    );
    let unmatched: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_requests WHERE user_id IS NULL")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(unmatched, 3);
    // They end alike.
    age(&state, 901).await;
    for (id, nd) in &asked {
        assert_eq!(polled(&app, id, nd).await, json!({ "status": "expired" }));
    }
    sqlx::query("DELETE FROM auth_requests")
        .execute(&state.db)
        .await
        .unwrap();
    state.limiter.clear();

    // The limits are the same for every email: three per address...
    for (i, email) in emails.into_iter().enumerate() {
        let ip = format!("192.0.2.{i}");
        for n in 0..3 {
            let (s, v) = ask_from(&app, &ip, NewDevice::new("d").body(email)).await;
            assert_eq!(s, StatusCode::OK, "{email} #{n}: {v}");
        }
        let (s, e) = ask_from(&app, &ip, NewDevice::new("d").body(email)).await;
        assert_eq!(
            (s, &e["error"]),
            (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited")),
            "{email}"
        );
    }
    // ...and from other addresses any number is answered, but only five a quarter
    // of an hour reach the account (the rest are stored like unknown emails' ones).
    for n in 0..6 {
        for email in emails {
            let ip = format!("198.51.100.{n}");
            let (s, v) = ask_from(&app, &ip, NewDevice::new("d").body(email)).await;
            assert_eq!(s, StatusCode::OK, "{email} from {ip}: {v}");
        }
    }
    assert_eq!(listed(&app, &ta).await.len(), 5);
    let shown: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auth_requests WHERE user_id IS NOT NULL AND status = 'pending'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(shown, 5);
}

#[tokio::test]
async fn new_requests_and_polls_are_rate_limited() {
    let (app, state) = app_with_state().await;
    let body = |n: usize| NewDevice::new("d").body(&format!("rl-{n}@example.com"));
    // Ten per address in ten minutes; IPv6 counts by /48.
    for (n, ip) in [
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
        "203.0.113.5",
    ]
    .into_iter()
    .enumerate()
    {
        let (s, v) = ask_from(&app, ip, body(n)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let (s, e) = ask_from(&app, "203.0.113.5", body(10)).await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("rate_limited"))
    );
    assert_eq!(
        ask_from(&app, "198.51.100.7", body(10)).await.0,
        StatusCode::OK,
        "another address may"
    );
    for n in 0..10 {
        let ip = format!("2001:db8:1:{n:x}::1");
        assert_eq!(ask_from(&app, &ip, body(20 + n)).await.0, StatusCode::OK);
    }
    assert_eq!(
        ask_from(&app, "2001:db8:1:ffff::9", body(30)).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "the same /48"
    );
    assert_eq!(
        ask_from(&app, "2001:db8:2::1", body(30)).await.0,
        StatusCode::OK
    );

    // A ceiling for the whole server.
    for _ in 0..1000 {
        let _ = state
            .limiter
            .hit(crate::state::Class::Target, SERVER_LIMIT_KEY, 1000, 600);
    }
    assert_eq!(
        ask_from(&app, "192.0.2.77", body(40)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    state.limiter.clear();

    // Polls: 120 a minute per address.
    let nd = NewDevice::new("p");
    let (_, r) = ask_from(&app, "192.0.2.50", nd.body("rl-poll@example.com")).await;
    let path = format!("/api/auth/requests/{}", id_of(&r));
    let poll_from = |ip: &'static str| {
        let (app, path, code) = (app.clone(), path.clone(), nd.code.clone());
        async move {
            let headers = [("x-passauth-access-code", code.as_str())];
            call_peer(&app, ip, Method::GET, &path, &headers, json!(null))
                .await
                .0
        }
    };
    for _ in 0..120 {
        assert_eq!(poll_from("192.0.2.60").await, StatusCode::OK);
    }
    assert_eq!(poll_from("192.0.2.60").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(poll_from("192.0.2.61").await, StatusCode::OK);
}

#[tokio::test]
async fn addresses_follow_the_admins_event_ip_switch_and_are_dropped_once_answered() {
    let (app, state) = app_with_state().await;
    let email = "dl-ip@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let nd = NewDevice::new("i1");
    let (_, r) = ask_from(&app, "203.0.113.9", nd.body(email)).await;
    let id = id_of(&r);
    assert_eq!(listed_one(&app, &ta, &id).await["ip"], "203.0.113.9");
    approve(&app, &alice, &ta, &nd, &id).await;
    assert_eq!(kept(&state, &id).await.3, None, "not needed once answered");

    assert_eq!(
        admin_set(&app, json!({ "event_ip": false })).await.0,
        StatusCode::OK
    );
    let nd = NewDevice::new("i2");
    let (_, r) = ask_from(&app, "203.0.113.9", nd.body(email)).await;
    let id = id_of(&r);
    assert_eq!(listed_one(&app, &ta, &id).await["ip"], json!(null));
    assert_eq!(kept(&state, &id).await.3, None);
}

#[tokio::test]
async fn bad_requests_are_refused() {
    let app = app().await;
    let nd = NewDevice::new("v");
    for (field, value) in [
        ("public_key", json!(b64(&[0; 32]))),
        ("public_key", json!(b64(&[7; 31]))),
        ("public_key", json!("not a key")),
        ("access_code", json!("too-short")),
        ("access_code", json!("a".repeat(129))),
        ("access_code", json!("spaces are not base64url at all")),
        ("device_id", json!("")),
        ("device_kind", json!("no spaces")),
        ("email", json!("no-at-sign")),
    ] {
        let mut body = nd.body("v@example.com");
        body[field] = value.clone();
        let (s, e) = call(&app, Method::POST, "/api/auth/requests", None, body).await;
        assert_eq!(
            (s, &e["error"]),
            (StatusCode::BAD_REQUEST, &json!("bad_request")),
            "{field}: {value}"
        );
    }
}

#[tokio::test]
async fn approving_devices_hear_about_requests_and_answers() {
    let (app, state) = app_with_state().await;
    let addr = serve(state).await;
    let email = "dl-ws@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let t1 = token(&app, email, "pw-alice-1").await;
    let t2 = token(&app, email, "pw-alice-1").await;
    let mut ws1 = socket(addr, &t1).await;
    let mut ws2 = socket(addr, &t2).await;
    // A request for an email without an account reaches nobody: the first message
    // the sockets get is about the real one.
    ask(&app, &NewDevice::new("g"), "dl-ws-nobody@example.com").await;
    let nd = NewDevice::new("n");
    let id = id_of(&ask(&app, &nd, email).await);
    for ws in [&mut ws1, &mut ws2] {
        assert_eq!(
            next_message(ws).await.unwrap(),
            json!({ "type": "auth_request", "id": id })
        );
    }
    approve(&app, &alice, &t1, &nd, &id).await;
    for ws in [&mut ws1, &mut ws2] {
        assert_eq!(
            next_message(ws).await.unwrap(),
            json!({ "type": "auth_request_answered", "id": id })
        );
    }
}

#[tokio::test]
async fn the_two_step_policy_applies_to_approving_and_to_the_new_session() {
    let app = app().await;
    let email = "dl-policy@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    assert_eq!(
        admin_set(&app, json!({ "require_two_step": true })).await.0,
        StatusCode::OK
    );
    let nd = NewDevice::new("p");
    let id = id_of(&ask(&app, &nd, email).await);
    // Without a method the account's apps can't list or answer requests...
    let (s, e) = call(
        &app,
        Method::GET,
        "/api/account/auth-requests",
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::FORBIDDEN, &json!("two_step_required"))
    );
    let (s, e) = answer(&app, &ta, &id, json!({ "approve": false })).await;
    assert_eq!(
        (s, &e["error"]),
        (StatusCode::FORBIDDEN, &json!("two_step_required"))
    );
    // ...and once it has one, the new device needs it too.
    enable_totp(&app, email, "pw-alice-1", &ta).await;
    assert_eq!(listed(&app, &ta).await.len(), 1);
    approve(&app, &alice, &ta, &nd, &id).await;
    let v = polled(&app, &id, &nd).await;
    assert_eq!(v["two_factor_required"], true, "{v}");
}

#[tokio::test]
async fn the_admin_switch_turns_the_feature_off() {
    let app = app().await;
    let email = "dl-off-switch@example.com";
    let alice = register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let nd = NewDevice::new("s");
    let id = id_of(&ask(&app, &nd, email).await);
    let req = listed_one(&app, &ta, &id).await;
    let features = |app: Router| async move {
        call(&app, Method::GET, "/api/config", None, json!(null))
            .await
            .1["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "login_with_device")
    };
    let switch = |on: bool| {
        let app = app.clone();
        async move {
            let (s, v) = admin_set(&app, json!({ "login_with_device": on })).await;
            assert_eq!(s, StatusCode::OK, "{v}");
        }
    };
    assert!(features(app.clone()).await);
    switch(false).await;
    assert!(!features(app.clone()).await);
    let off = json!("login_with_device_disabled");
    let (s, e) = call(
        &app,
        Method::POST,
        "/api/auth/requests",
        None,
        NewDevice::new("t").body(email),
    )
    .await;
    assert_eq!((s, &e["error"]), (StatusCode::FORBIDDEN, &off));
    let (s, e) = poll(&app, &id, &nd.code).await;
    assert_eq!((s, &e["error"]), (StatusCode::FORBIDDEN, &off));
    let (s, e) = call(
        &app,
        Method::GET,
        "/api/account/auth-requests",
        Some(&ta),
        json!(null),
    )
    .await;
    assert_eq!((s, &e["error"]), (StatusCode::FORBIDDEN, &off));
    let (s, e) = answer(&app, &ta, &id, approval(&alice, &nd, &req)).await;
    assert_eq!((s, &e["error"]), (StatusCode::FORBIDDEN, &off));
    // On again: the request is still there.
    switch(true).await;
    assert_eq!(listed(&app, &ta).await.len(), 1);
    approve(&app, &alice, &ta, &nd, &id).await;
    assert!(polled(&app, &id, &nd).await["access_token"].is_string());

    // Off while a device sign-in waits at its two-step login: none of its steps
    // goes on, and no code is used up.
    let recovery = enable_totp(&app, email, "pw-alice-1", &ta).await;
    for path in [
        "/api/auth/2fa/email",
        "/api/auth/2fa/passkey/start",
        "/api/auth/2fa/verify",
    ] {
        switch(true).await;
        let late = NewDevice::new("late");
        let id = id_of(&ask(&app, &late, email).await);
        approve(&app, &alice, &ta, &late, &id).await;
        let tf = polled(&app, &id, &late).await["two_factor_token"].clone();
        switch(false).await;
        let body = json!({ "two_factor_token": tf, "provider": "recovery", "code": recovery[0] });
        let (s, e) = call(&app, Method::POST, path, None, body).await;
        assert_eq!(
            (s, &e["error"]),
            (StatusCode::FORBIDDEN, &off),
            "{path}: {e}"
        );
        assert!(e.get("sealed_key").is_none() && e.get("access_token").is_none());
    }
    let left = ok(&app, Method::GET, "/api/account", &ta, json!(null)).await;
    assert_eq!(left["recovery_codes_left"], 10, "no code was used up");
}

#[tokio::test]
async fn a_security_key_finishes_a_device_sign_in_too() {
    let (app, state) = app_with_state().await;
    let (email, pw) = ("dl-key@example.com", "pw-alice-1");
    let alice = register(&app, email, pw).await;
    let ta = token(&app, email, pw).await;
    let ra = reauth_token(&app, email, pw, &ta).await;
    let (s, start) = call_with(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/start",
        Some(&ta),
        &[("x-reauth-token", &ra)],
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let (key, credential) = SoftKey::create(&start["options"]);
    ok(
        &app,
        Method::POST,
        "/api/account/2fa/passkey/register/finish",
        &ta,
        json!({ "registration_id": start["registration_id"], "name": "Blue key", "credential": credential }),
    )
    .await;

    let nd = NewDevice::new("desk");
    let id = id_of(&ask(&app, &nd, email).await);
    approve(&app, &alice, &ta, &nd, &id).await;
    let v = polled(&app, &id, &nd).await;
    assert_eq!(v["providers"], json!(["passkey", "recovery"]), "{v}");
    let tf = v["two_factor_token"].clone();
    let (s, o) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/start",
        None,
        json!({ "two_factor_token": tf }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{o}");
    let (s, v) = call(
        &app,
        Method::POST,
        "/api/auth/2fa/passkey/finish",
        None,
        json!({ "two_factor_token": tf, "credential": key.assert(&o["options"], true) }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        nd.open(&v["sealed_key"], &id).as_bytes(),
        alice.unlocked.account_key.as_bytes()
    );
    let events = stored_events(&state).await;
    let data = &of_type(&events, "auth.signed_in").last().unwrap()["data"];
    assert_eq!(
        (&data["two_step"], &data["method"]),
        (&json!("passkey"), &json!("device"))
    );
}

/// What the approving app shows as the new device claims it (device name, app):
/// at most 64 characters of plain text, without control or format characters such
/// as a right-to-left override.
#[tokio::test]
async fn claimed_device_and_app_names_are_short_plain_text() {
    let app = app().await;
    let email = "dl-names@example.com";
    register(&app, email, "pw-alice-1").await;
    let ta = token(&app, email, "pw-alice-1").await;
    let nd = NewDevice::new("names");
    let mut body = nd.body(email);
    body["device_name"] = json!(format!(
        "Pay\u{202E}lapyaP\u{200B} {}\u{E0041}",
        "x".repeat(100)
    ));
    let client = format!("{}/{}", "a".repeat(32), "1".repeat(32));
    let (s, v) = call_peer(
        &app,
        &next_address(),
        Method::POST,
        "/api/auth/requests",
        &[("x-passauth-client", &client)],
        body,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let list = listed(&app, &ta).await;
    let name = list[0]["device_name"].as_str().unwrap();
    assert_eq!(name, format!("PaylapyaP {}", "x".repeat(54)));
    assert_eq!(list[0]["client"], json!(&client[..64]));
}
