//! Sign-in request push notifications: registering a phone's push token (checks,
//! one per session, a token moving to a new session), the token going with its
//! session, the relay asked on a new sign-in request for an account (never for an
//! unknown email), a token the relay reports gone, and the admin's switch and relay
//! address.

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State as AxState;
use axum::http::HeaderMap;
use passauth_core::crypto::{KeyPair, random_bytes};

use super::*;

const ADMIN: Option<&str> = Some("test-admin");

/// An APNs device token as the phone reports it (upper case here: stored lower case).
fn device_token(n: u8) -> String {
    format!("{n:02X}").repeat(32)
}

fn registration(token: &str) -> Value {
    json!({ "platform": "apns", "token": token, "environment": "sandbox" })
}

async fn put_push(app: &Router, token: &str, body: Value) -> (StatusCode, Value) {
    call(app, Method::PUT, "/api/account/push", Some(token), body).await
}

/// `(session_id, user_id, token, environment)` of every kept token.
async fn kept(state: &AppState) -> Vec<(String, String, String, String)> {
    sqlx::query_as(
        "SELECT session_id, user_id, token, environment FROM push_tokens ORDER BY session_id",
    )
    .fetch_all(&state.db)
    .await
    .unwrap()
}

async fn session_of(app: &Router, token: &str) -> String {
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

async fn features(app: &Router) -> Vec<String> {
    let (_, v) = call(app, Method::GET, "/api/config", None, json!(null)).await;
    serde_json::from_value(v["features"].clone()).unwrap()
}

/// A new device asks to sign in to `email`.
async fn ask(app: &Router, email: &str) {
    let keys = KeyPair::generate().unwrap();
    let body = json!({
        "email": email,
        "public_key": b64(&keys.public_bytes()),
        "access_code": b64(&random_bytes::<32>().unwrap()),
        "device_id": "new-phone",
        "device_name": "New phone",
        "device_kind": "ios",
    });
    let (s, v) = call(app, Method::POST, "/api/auth/requests", None, body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// What the fake relay received: `(path, user agent, body)`.
type Received = Arc<Mutex<Vec<(String, String, Value)>>>;

/// A relay on 127.0.0.1 that records every request and answers `status`.
struct FakeRelay {
    url: String,
    received: Received,
    status: Arc<AtomicU16>,
}

impl FakeRelay {
    async fn start() -> Self {
        let received: Received = Arc::default();
        let status = Arc::new(AtomicU16::new(202));
        async fn notify(
            AxState((received, status)): AxState<(Received, Arc<AtomicU16>)>,
            uri: axum::http::Uri,
            headers: HeaderMap,
            body: String,
        ) -> (StatusCode, &'static str) {
            let agent = headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = serde_json::from_str(&body).unwrap_or(Value::Null);
            received
                .lock()
                .unwrap()
                .push((uri.path().to_owned(), agent, body));
            let s = StatusCode::from_u16(status.load(Ordering::Relaxed)).unwrap();
            (s, "{}")
        }
        let router = Router::new()
            .route("/v1/notify", axum::routing::post(notify))
            .with_state((received.clone(), status.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            url,
            received,
            status,
        }
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    /// Waits (up to 5 s) until `n` notifications arrived.
    async fn wait_for(&self, n: usize) {
        for _ in 0..500 {
            if self.count() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the relay got {} notifications, not {n}", self.count());
    }
}

/// An app whose push relay is `relay` (set on the admin page).
async fn app_with_relay(relay: &FakeRelay) -> (Router, AppState) {
    let (app, state) = app_with_state().await;
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        ADMIN,
        json!({ "push_relay_url": relay.url }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["push_relay_url"], relay.url);
    (app, state)
}

#[tokio::test]
async fn push_tokens_are_checked_kept_per_session_and_forgotten() {
    let (app, state) = app_with_state().await;
    assert!(features(&app).await.contains(&"push".to_owned()));
    let email = "push-a@example.com";
    register(&app, email, "pw-push-a-1").await;
    let t1 = token(&app, email, "pw-push-a-1").await;
    let me = user_id(&app, &t1).await;
    let s1 = session_of(&app, &t1).await;

    for bad in [
        json!({ "platform": "fcm", "token": device_token(1), "environment": "sandbox" }),
        json!({ "platform": "apns", "token": "abc", "environment": "sandbox" }),
        json!({ "platform": "apns", "token": "zz".repeat(32), "environment": "sandbox" }),
        json!({ "platform": "apns", "token": "ab".repeat(101), "environment": "sandbox" }),
        json!({ "platform": "apns", "token": device_token(1), "environment": "staging" }),
    ] {
        let (s, v) = put_push(&app, &t1, bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/account/push",
        None,
        registration(&device_token(1)),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(kept(&state).await.is_empty());

    let (s, v) = put_push(&app, &t1, registration(&device_token(1))).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let lower = device_token(1).to_ascii_lowercase();
    assert_eq!(
        kept(&state).await,
        vec![(s1.clone(), me.clone(), lower.clone(), "sandbox".into())]
    );
    // One per session: a new token replaces the old one.
    let body = json!({ "platform": "apns", "token": device_token(2), "environment": "production" });
    let (s, _) = put_push(&app, &t1, body).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rows = kept(&state).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0].2, rows[0].3.as_str()),
        (&device_token(2).to_ascii_lowercase(), "production")
    );

    // The phone signs in again (a new session): the token moves there.
    let t2 = token(&app, email, "pw-push-a-1").await;
    let s2 = session_of(&app, &t2).await;
    let (s, _) = put_push(&app, &t2, registration(&device_token(2))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rows = kept(&state).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, s2);

    // DELETE forgets this session's token only.
    let (s, _) = put_push(&app, &t1, registration(&device_token(3))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        Method::DELETE,
        "/api/account/push",
        Some(&t1),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let rows = kept(&state).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, s2);

    // Signing out takes the session's token with it.
    ok(&app, Method::POST, "/api/auth/logout", &t2, json!({})).await;
    assert!(kept(&state).await.is_empty());

    // So do revoking the other sessions, revoking one, and the admin revoking them all.
    let t3 = token(&app, email, "pw-push-a-1").await;
    let t4 = token(&app, email, "pw-push-a-1").await;
    for (t, n) in [(&t1, 4), (&t3, 5), (&t4, 6)] {
        let (s, _) = put_push(&app, t, registration(&device_token(n))).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    }
    assert_eq!(kept(&state).await.len(), 3);
    ok(
        &app,
        Method::POST,
        "/api/account/sessions/revoke-others",
        &t1,
        json!({}),
    )
    .await;
    assert_eq!(
        kept(&state)
            .await
            .into_iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        vec![s1.clone()]
    );
    let t5 = token(&app, email, "pw-push-a-1").await;
    let (s, _) = put_push(&app, &t5, registration(&device_token(7))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let s5 = session_of(&app, &t5).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/account/sessions/{s5}"),
        &t1,
        json!(null),
    )
    .await;
    assert_eq!(kept(&state).await.len(), 1);
    let (s, v) = call(
        &app,
        Method::POST,
        &format!("/api/admin/users/{me}/sessions/revoke"),
        ADMIN,
        json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(kept(&state).await.is_empty());

    // A session that expired: the sweeper's query drops its token.
    let t6 = token(&app, email, "pw-push-a-1").await;
    let (s, _) = put_push(&app, &t6, registration(&device_token(8))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&me)
        .execute(&state.db)
        .await
        .unwrap();
    crate::push::sweep(&state).await.unwrap();
    assert!(kept(&state).await.is_empty());
}

#[tokio::test]
async fn a_new_master_password_or_deleting_the_account_drops_push_tokens() {
    let (app, state) = app_with_state().await;
    let email = "push-d@example.com";
    register(&app, email, "pw-push-d-1").await;
    let t1 = token(&app, email, "pw-push-d-1").await;
    let me = user_id(&app, &t1).await;
    let t2 = token(&app, email, "pw-push-d-1").await;
    for (t, n) in [(&t1, 1), (&t2, 2)] {
        let (s, _) = put_push(&app, t, registration(&device_token(n))).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    }
    // A new master password signs the other sessions out: their tokens go, this one's stays.
    let s1 = session_of(&app, &t1).await;
    super::device_login::change_password(&app, email, "pw-push-d-1", &t1).await;
    assert_eq!(
        kept(&state)
            .await
            .into_iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        vec![s1]
    );
    // Deleting the account (the account's own and the admin's deletion both end here).
    crate::account::delete_user(&state, &me, crate::events::Event::new("account.deleted"))
        .await
        .unwrap();
    assert!(kept(&state).await.is_empty());
}

#[tokio::test]
async fn a_sign_in_request_wakes_the_accounts_phones_through_the_relay() {
    let relay = FakeRelay::start().await;
    let (app, state) = app_with_relay(&relay).await;
    let email = "push-b@example.com";
    register(&app, email, "pw-push-b-1").await;
    let t1 = token(&app, email, "pw-push-b-1").await;
    let (s, _) = put_push(&app, &t1, registration(&device_token(9))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // No account behind the email: nobody is woken.
    ask(&app, "nobody-push@example.com").await;
    // The account's request: one notification per token.
    ask(&app, email).await;
    relay.wait_for(1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let received = relay.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1, "{received:?}");
    let (path, agent, body) = &received[0];
    assert_eq!(path, "/v1/notify");
    assert_eq!(
        agent,
        &format!("PassAuth-Server/{}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        body,
        &json!({
            "platform": "apns",
            "token": device_token(9).to_ascii_lowercase(),
            "environment": "sandbox",
            "kind": "auth_request",
        }),
        "the token, its environment and the kind: nothing about the account or the request"
    );
    // The relay said it was sent: the token stays.
    assert_eq!(kept(&state).await.len(), 1);
}

#[tokio::test]
async fn a_token_the_relay_reports_gone_is_deleted() {
    let relay = FakeRelay::start().await;
    let (app, state) = app_with_relay(&relay).await;
    let email = "push-c@example.com";
    register(&app, email, "pw-push-c-1").await;
    let t1 = token(&app, email, "pw-push-c-1").await;
    let (s, _) = put_push(&app, &t1, registration(&device_token(10))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Other refusals keep the token.
    for status in [400, 429, 502] {
        relay.status.store(status, Ordering::Relaxed);
        let before = relay.count();
        // Four asks from one address: past the per-address limit, which isn't tested here.
        state.limiter.clear();
        ask(&app, email).await;
        relay.wait_for(before + 1).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(kept(&state).await.len(), 1, "kept after {status}");
    }

    relay.status.store(410, Ordering::Relaxed);
    let before = relay.count();
    state.limiter.clear();
    ask(&app, email).await;
    relay.wait_for(before + 1).await;
    for _ in 0..200 {
        if kept(&state).await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the token the relay reported gone is still kept");
}

#[tokio::test]
async fn the_admin_switch_and_relay_address() {
    let relay = FakeRelay::start().await;
    let (app, state) = app_with_relay(&relay).await;
    let (_, v) = call(&app, Method::GET, "/api/admin/settings", ADMIN, json!(null)).await;
    assert_eq!(
        (
            &v["push_enabled"],
            &v["push_relay_url"],
            &v["push_relay_default"]
        ),
        (
            &json!(true),
            &json!(relay.url),
            &json!(crate::push::DEFAULT_RELAY_URL)
        )
    );
    for bad in [
        "http://push.example.com",
        "push.example.com",
        "https://u:p@push.example.com",
    ] {
        let (s, v) = call(
            &app,
            Method::PUT,
            "/api/admin/settings",
            ADMIN,
            json!({ "push_relay_url": bad }),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }

    let email = "push-e@example.com";
    register(&app, email, "pw-push-e-1").await;
    let t1 = token(&app, email, "pw-push-e-1").await;
    let (s, _) = put_push(&app, &t1, registration(&device_token(11))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Off: the feature goes, the kept tokens go, nobody registers, nothing is sent.
    let (s, v) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        ADMIN,
        json!({ "push_enabled": false }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["push_enabled"], false);
    assert!(!features(&app).await.contains(&"push".to_owned()));
    assert!(kept(&state).await.is_empty());
    let (s, v) = put_push(&app, &t1, registration(&device_token(11))).await;
    assert_eq!(
        (s, &v["error"]),
        (StatusCode::CONFLICT, &json!("push_disabled"))
    );
    // A token kept from before (written directly): still never sent while off.
    sqlx::query(
        "INSERT INTO push_tokens (session_id, user_id, platform, token, environment, created_at, updated_at)
         SELECT id, user_id, 'apns', $1, 'sandbox', 0, 0 FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $2)",
    )
    .bind(device_token(12).to_ascii_lowercase())
    .bind(email)
    .execute(&state.db)
    .await
    .unwrap();
    ask(&app, email).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.count(), 0);
    // DELETE still answers.
    let (s, _) = call(
        &app,
        Method::DELETE,
        "/api/account/push",
        Some(&t1),
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Back on: registering works again, and the setting survives in the database.
    let (s, _) = call(
        &app,
        Method::PUT,
        "/api/admin/settings",
        ADMIN,
        json!({ "push_enabled": true }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(features(&app).await.contains(&"push".to_owned()));
    let (s, _) = put_push(&app, &t1, registration(&device_token(11))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        crate::db::setting(&state.db, crate::push::RELAY_SETTING)
            .await
            .unwrap()
            .as_deref(),
        Some(relay.url.as_str())
    );
}
