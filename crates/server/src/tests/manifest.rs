//! Vault manifests (migration 17): the compatibility gate, the first manifest and a
//! new baseline, every item write with and without its manifest, retried creates and
//! imports, moves, key replacement, the trash sweeper, and what `/sync` hands out.
//! The tests play the apps' part with the core (`passauth_core::manifest`), so each
//! accepted write is also checked the way an app checks a sync. Review fixes: the
//! chain (every manifest names the one it replaces, the log lets a device follow it,
//! and a history that doesn't contain what a device saw is told apart) and the gate
//! that counts only members who can write. Second round: every manifest, a baseline
//! too, is exactly one version up; baselines are limited per member and vault; the
//! log is kept by age and count; every write's answer names the link of the vault's
//! manifest; accepting the server's copy on a device needs no request; and a row
//! nobody can open is deleted like any other.

use passauth_core::manifest::{self, Entry, LogEntry, Row, Seen, Status};

use super::sec789::{expire_sessions_of, session_as};
use super::*;
use crate::auth::keeps_manifests;

const NEW_APP: &str = "ios/0.12.0";

#[test]
fn manifest_keepers_are_known_apps_at_their_first_release() {
    for yes in [
        "web/0.15.0",
        "desktop/0.13.0",
        "macos-autofill/0.13.1",
        "extension/0.12.0",
        "ios/0.12.0",
        "android/0.12.0-debug",
        "android/1",
    ] {
        assert!(keeps_manifests(Some(yes)), "{yes}");
    }
    for no in [
        "web/0.14.0",
        "desktop/0.12.9",
        "macos-autofill/0.12.0",
        "extension/0.11.0",
        "ios/0.11.0",
        "android/0.11.0",
        "cli/9.9.9",
        "ios/",
        "",
    ] {
        assert!(!keeps_manifests(Some(no)), "{no}");
    }
    assert!(!keeps_manifests(None));
}

/// An account whose only session is an app that keeps manifests.
async fn member(app: &Router, email: &str) -> (Client, String) {
    let pw = "pw-manifest-1";
    let c = register(app, email, pw).await;
    let t = session_as(app, email, pw, Some(NEW_APP)).await;
    (c, t)
}

fn entry(id: &str, trashed: bool, body: &Value) -> Entry {
    Entry::new(id, trashed, body["data"].as_str().unwrap())
}

/// The vault's item rows in a sync answer, as the core counts them.
fn entries(sync: &Value, vault: &str) -> Vec<Entry> {
    sync["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["vault_id"] == vault)
        .map(|i| serde_json::from_value(i.clone()).unwrap())
        .collect()
}

fn row<'a>(sync: &'a Value, vault: &str) -> &'a Value {
    vault_in(sync, vault).unwrap()
}

fn manifest_seq(sync: &Value, vault: &str) -> u64 {
    row(sync, vault)["manifest_seq"].as_u64().unwrap()
}

/// The vault row's manifest as the core takes it.
fn head<'a>(sync: &'a Value, vault: &str) -> Row<'a> {
    let v = row(sync, vault);
    Row {
        seq: v["manifest_seq"].as_u64().unwrap(),
        prev: v["manifest_prev"].as_str(),
        sealed: v["manifest"].as_str(),
    }
}

/// The link of the manifest a sync answer shows (base64url).
fn link_of(sync: &Value, vault: &str) -> String {
    let h = head(sync, vault);
    manifest::row_link(h.seq, h.prev.unwrap(), h.sealed.unwrap()).unwrap()
}

/// What a device remembers after accepting the manifest a sync answer shows.
fn seen(sync: &Value, vault: &str) -> Seen {
    Seen::parse(manifest_seq(sync, vault), &link_of(sync, vault)).unwrap()
}

/// A device that remembers `version` of some history the server doesn't have.
fn stranger(version: u64) -> Seen {
    Seen {
        version,
        link: [9; 32],
    }
}

fn verdict_with(
    sync: &Value,
    (vault, key): (&str, &SymmetricKey),
    remembered: Option<&Seen>,
    log: Option<&[LogEntry]>,
) -> Status {
    let epoch = row(sync, vault)["key_epoch"].as_u64().unwrap();
    manifest::verify(
        key,
        vault,
        epoch,
        head(sync, vault),
        remembered,
        log,
        &entries(sync, vault),
    )
    .unwrap()
    .status
}

/// "Use the server's copy" on a device, without a request: what the device remembers
/// from then on when the vault as `sync` shows it stands on its own (`None`: it
/// doesn't, and nothing may be remembered).
fn accepted(sync: &Value, (vault, key): (&str, &SymmetricKey)) -> Option<Seen> {
    let epoch = row(sync, vault)["key_epoch"].as_u64().unwrap();
    let items = entries(sync, vault);
    let check = manifest::accept(key, vault, epoch, head(sync, vault), &items).unwrap();
    match check.status {
        Status::Ok => Some(Seen::parse(check.version, &check.link.unwrap()).unwrap()),
        _ => {
            assert_eq!((check.version, check.link), (0, None));
            None
        }
    }
}

/// What an app concludes about `vault` from one sync answer alone.
fn verdict(sync: &Value, vault: (&str, &SymmetricKey), remembered: Option<&Seen>) -> Status {
    verdict_with(sync, vault, remembered, None)
}

/// One answer of the vault's manifest log.
async fn log_page(app: &Router, t: &str, vault: &str, query: &str) -> (StatusCode, Value) {
    let path = format!("/api/vaults/{vault}/manifest-log{query}");
    call(app, Method::GET, &path, Some(t), json!(null)).await
}

/// The vault's manifest log after `after`, every page of it, as the core takes it.
async fn log_after(app: &Router, t: &str, vault: &str, after: u64) -> Vec<LogEntry> {
    let (mut all, mut after) = (Vec::new(), after);
    loop {
        let (s, page) = log_page(app, t, vault, &format!("?after={after}")).await;
        assert_eq!(s, StatusCode::OK, "{page}");
        let entries: Vec<LogEntry> = serde_json::from_value(page["entries"].clone()).unwrap();
        after = entries.last().map_or(after, |e| e.seq);
        all.extend(entries);
        if page["more"] != true {
            return all;
        }
    }
}

/// What an app concludes the whole way: the sync answer, and when the core asks for
/// it, the vault's log after what the device remembers.
async fn followed(
    app: &Router,
    t: &str,
    sync: &Value,
    vault: (&str, &SymmetricKey),
    remembered: &Seen,
) -> Status {
    match verdict(sync, vault, Some(remembered)) {
        Status::NeedLog => {
            let log = log_after(app, t, vault.0, remembered.version).await;
            verdict_with(sync, vault, Some(remembered), Some(&log))
        }
        other => other,
    }
}

/// The versions in the vault's log.
async fn logged(app: &Router, t: &str, vault: &str) -> Vec<u64> {
    let log = log_after(app, t, vault, 0).await;
    log.iter().map(|e| e.seq).collect()
}

/// Every version in the vault's log, as the database holds it.
async fn logged_all(state: &crate::state::AppState, vault: &str) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM vault_manifest_log WHERE vault_id = $1 ORDER BY seq")
        .bind(vault)
        .fetch_all(&state.db)
        .await
        .unwrap()
}

fn sent(vault: &str, w: &manifest::Written) -> Value {
    json!({ "vault_id": vault, "seq": w.seq, "prev": w.prev, "sealed": w.sealed })
}

/// A manifest entry that is right in all but the manifest it names.
fn misnamed(m: &Value) -> Value {
    let mut m = m.clone();
    m["prev"] = json!(b64(&[5; 32]));
    m
}

const NO_PREV: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// A full sync, which must check out for `vault`; returns it.
async fn checked(app: &Router, t: &str, vault: (&str, &SymmetricKey)) -> Value {
    let sync = synced(app, t).await;
    assert_eq!(
        verdict(&sync, vault, None),
        Status::Ok,
        "{}",
        sync["vaults"]
    );
    sync
}

/// `{vault_id, seq, prev, sealed}`: the vault's next manifest after a write that
/// removes and adds these entries, from the state `sync` shows.
fn next(
    sync: &Value,
    (vault, key): (&str, &SymmetricKey),
    removed: &[Entry],
    added: &[Entry],
) -> Value {
    let epoch = row(sync, vault)["key_epoch"].as_u64().unwrap();
    let w = manifest::advance(key, vault, epoch, head(sync, vault), removed, added).unwrap();
    assert_eq!(w.prev, link_of(sync, vault));
    sent(vault, &w)
}

fn query(m: &Value) -> String {
    format!(
        "manifest_seq={}&manifest_prev={}&manifest={}",
        m["seq"],
        m["prev"].as_str().unwrap(),
        m["sealed"].as_str().unwrap()
    )
}

/// Start `vault`'s first manifest from a fresh sync; returns the answer.
async fn start(app: &Router, t: &str, (vault, key): (&str, &SymmetricKey)) -> (StatusCode, Value) {
    let sync = synced(app, t).await;
    let v = row(&sync, vault);
    let w = manifest::start(
        key,
        vault,
        v["key_epoch"].as_u64().unwrap(),
        1,
        None,
        &entries(&sync, vault),
    )
    .unwrap();
    assert_eq!(w.prev, NO_PREV);
    call(
        app,
        Method::PUT,
        &format!("/api/vaults/{vault}/manifest"),
        Some(t),
        json!({ "base_seq": 0, "seq": 1, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] }),
    )
    .await
}

async fn started(app: &Router, t: &str, vault: (&str, &SymmetricKey)) {
    let (s, v) = start(app, t, vault).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

fn code_of(answer: &(StatusCode, Value)) -> (StatusCode, &str) {
    (answer.0, answer.1["error"].as_str().unwrap_or_default())
}

const REQUIRED: (StatusCode, &str) = (StatusCode::BAD_REQUEST, "manifest_required");
const CONFLICT: (StatusCode, &str) = (StatusCode::CONFLICT, "manifest_conflict");

#[tokio::test]
async fn a_first_manifest_waits_for_every_members_apps() {
    let (app, state) = app_with_state().await;
    let (alice, ta) = member(&app, "mg-a@example.com").await;
    let (_bob, tb) = member(&app, "mg-b@example.com").await;
    let (_dave, td) = member(&app, "mg-d@example.com").await;
    let vault = (alice.vault_id.as_str(), &alice.vault_key);
    let ok_of = |sync: &Value| row(sync, vault.0)["manifest_ok"].clone();
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("vault_manifest")),
        "{config}"
    );

    let sync = synced(&app, &ta).await;
    assert_eq!(ok_of(&sync), json!(true));
    assert_eq!(row(&sync, vault.0)["manifest_seq"], 0);
    assert_eq!(row(&sync, vault.0)["manifest"], json!(null));
    assert_eq!(verdict(&sync, vault, None), Status::None);
    assert_eq!(sync["trash_days"], 0);
    assert!((sync["server_time"].as_i64().unwrap() - crate::db::now()).abs() < 5);

    // An app of the account from before manifests: not yet.
    session_as(
        &app,
        "mg-a@example.com",
        "pw-manifest-1",
        Some("web/0.14.0"),
    )
    .await;
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(false));
    assert_eq!(
        code_of(&start(&app, &ta, vault).await),
        (StatusCode::CONFLICT, "manifest_not_ready")
    );
    expire_sessions_of(&state, Some("web/0.14.0")).await;
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(true));

    // A member who only reads never sends a manifest: their old apps don't hold the
    // vault's first one off (review fix), before or after they accept.
    session_as(
        &app,
        "mg-d@example.com",
        "pw-manifest-1",
        Some("android/0.11.0"),
    )
    .await;
    session_as(&app, "mg-d@example.com", "pw-manifest-1", None).await;
    assert_eq!(
        share(&app, &alice, &ta, "mg-d@example.com", "read").await.0,
        StatusCode::OK
    );
    accept(&app, &td, vault.0).await;
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(true));
    assert_eq!(ok_of(&synced(&app, &td).await), json!(true));

    // Another member who can write: their old app counts, once they have accepted;
    // an invitee's doesn't.
    session_as(
        &app,
        "mg-b@example.com",
        "pw-manifest-1",
        Some("web/0.14.0"),
    )
    .await;
    assert_eq!(
        share(&app, &alice, &ta, "mg-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(true));
    accept(&app, &tb, vault.0).await;
    for t in [&ta, &tb, &td] {
        assert_eq!(ok_of(&synced(&app, t).await), json!(false));
    }
    assert_eq!(
        code_of(&start(&app, &ta, vault).await),
        (StatusCode::CONFLICT, "manifest_not_ready")
    );
    expire_sessions_of(&state, Some("web/0.14.0")).await;
    // The reader's old apps are still signed in, and it may start all the same.
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(true));

    // Reading the vault isn't enough to start its manifest.
    assert_eq!(start(&app, &td, vault).await.0, StatusCode::FORBIDDEN);
    // Nor is someone else's vault there at all.
    let (_carol, tc) = member(&app, "mg-c@example.com").await;
    let (s, _) = call(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}/manifest", vault.0),
        Some(&tc),
        json!({ "base_seq": 0, "seq": 1, "prev": NO_PREV, "sealed": "AAAA", "vault_seq": 0 }),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The other writer starts it as well as the owner could.
    started(&app, &tb, vault).await;
    let sync = checked(&app, &ta, vault).await;
    assert_eq!(manifest_seq(&sync, vault.0), 1);
    assert_eq!(ok_of(&sync), json!(true));
    // The reader sees and checks the same.
    checked(&app, &td, vault).await;
    // Once it has one, an old app signing in changes nothing about it.
    session_as(
        &app,
        "mg-b@example.com",
        "pw-manifest-1",
        Some("ios/0.11.0"),
    )
    .await;
    let sync = synced(&app, &ta).await;
    assert_eq!(
        (manifest_seq(&sync, vault.0), ok_of(&sync)),
        (1, json!(true))
    );
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "vault.manifest_started")[0]["data"],
        json!({ "from": 0, "to": 1 })
    );
}

#[tokio::test]
async fn a_manifest_starts_only_from_the_vaults_current_state() {
    let (app, state) = app_with_state().await;
    let (c, t) = member(&app, "ms@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (_, body) = new_item(vault, "one");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let sync = synced(&app, &t).await;
    let first = manifest::start(vault.1, vault.0, 0, 1, None, &entries(&sync, vault.0)).unwrap();
    let sealed = first.sealed.clone();
    let path = format!("/api/vaults/{}/manifest", vault.0);
    let put = |body: Value| {
        let (app, t, path) = (app.clone(), t.clone(), path.clone());
        async move { call(&app, Method::PUT, &path, Some(&t), body).await }
    };
    let seq = row(&sync, vault.0)["seq"].as_i64().unwrap();
    // A vault that has none takes no manifest with a write: only this request starts one.
    let (_, mut body) = new_item(vault, "early");
    body["manifests"] = json!([sent(vault.0, &first)]);
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), body).await),
        CONFLICT
    );
    // Written since the sync it was computed from.
    let (_, body) = new_item(vault, "two");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let stale =
        json!({ "base_seq": 0, "seq": 1, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq });
    assert_eq!(code_of(&put(stale).await), CONFLICT);
    // Shapes.
    let other = b64(&[5; 32]);
    for bad in [
        json!({ "base_seq": 0, "seq": 0, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 1, "seq": 1, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": -1, "seq": 1, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": NO_PREV, "sealed": "", "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": NO_PREV, "sealed": "not base64!", "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": NO_PREV, "sealed": "A".repeat(1025), "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 9_007_199_254_740_992_i64, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": "", "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": "AAAA", "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": format!("{NO_PREV}A"), "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "prev": "not base64 at all, forty-three characters!!", "sealed": sealed, "vault_seq": seq + 1 }),
        // One version up, always: no first manifest above version 1 (which would let
        // a member put a vault's version anywhere, its ceiling included).
        json!({ "base_seq": 0, "seq": 2, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 9_007_199_254_740_991_i64, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 3, "seq": 5, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 3, "seq": 3, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 3, "seq": 2, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 }),
    ] {
        assert_eq!(put(bad.clone()).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A base it isn't at, and a first manifest that names a predecessor.
    let wrong =
        json!({ "base_seq": 3, "seq": 4, "prev": NO_PREV, "sealed": sealed, "vault_seq": seq + 1 });
    assert_eq!(code_of(&put(wrong).await), CONFLICT);
    let wrong =
        json!({ "base_seq": 0, "seq": 1, "prev": other, "sealed": sealed, "vault_seq": seq + 1 });
    assert_eq!(code_of(&put(wrong).await), CONFLICT);
    assert_eq!(manifest_seq(&synced(&app, &t).await, vault.0), 0);
    assert!(logged(&app, &t, vault.0).await.is_empty());

    started(&app, &t, vault).await;
    let sync = checked(&app, &t, vault).await;
    // Started once: a second first manifest is a conflict.
    assert_eq!(code_of(&start(&app, &t, vault).await), CONFLICT);

    // A new baseline ("Use the server's copy" where the stored manifest is wrong): the
    // next version, naming the manifest it replaces, like any other write.
    let first_seen = seen(&sync, vault.0);
    let baseline = |sync: &Value, seq: u64, prev: Option<&str>| {
        let w = manifest::start(vault.1, vault.0, 0, seq, prev, &entries(sync, vault.0)).unwrap();
        let v = row(sync, vault.0);
        json!({ "base_seq": v["manifest_seq"], "seq": seq, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] })
    };
    let v = row(&sync, vault.0);
    for off_chain in [None, Some(b64(&[5; 32]))] {
        let body = baseline(&sync, 2, off_chain.as_deref());
        assert_eq!(code_of(&put(body).await), CONFLICT, "{off_chain:?}");
    }
    // Review fix (round 2): never a jump, however small or large. A device that
    // remembers a higher version doesn't need one: it takes the baseline, or the
    // server's copy as it is, in place of its memory.
    let link = link_of(&sync, vault.0);
    for jump in [3, 9, 1_000_001, 9_007_199_254_740_991] {
        let (s, v) = put(baseline(&sync, jump, Some(&link))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{jump}: {v}");
    }
    assert_eq!(manifest_seq(&synced(&app, &t).await, vault.0), 1);
    let body = baseline(&sync, 2, Some(&link));
    let wrote = manifest::row_link(2, &link, body["sealed"].as_str().unwrap()).unwrap();
    let answer = ok(&app, Method::PUT, &path, &t, body).await;
    assert_eq!(answer["manifest_seq"], 2);
    assert_eq!(answer["manifest_link"], json!(wrote));
    assert_eq!(
        answer["vault_seq"].as_i64().unwrap(),
        v["seq"].as_i64().unwrap() + 1
    );
    let sync = synced(&app, &t).await;
    assert_eq!(
        row(&sync, vault.0)["manifest_prev"],
        json!(b64(&first_seen.link))
    );
    assert_eq!(link_of(&sync, vault.0), wrote);
    assert_eq!(verdict(&sync, vault, None), Status::Ok);
    // Its writer (which remembers what it wrote) and a device on the history it
    // replaced follow it. One that saw another history is told at once (the very
    // next version names something else), one further back after asking for the
    // log, and one that saw a later version calls it a rollback…
    let writer = Seen::parse(2, &wrote).unwrap();
    assert_eq!(verdict(&sync, vault, Some(&writer)), Status::Ok);
    assert_eq!(verdict(&sync, vault, Some(&first_seen)), Status::Ok);
    assert_eq!(verdict(&sync, vault, Some(&stranger(1))), Status::Mismatch);
    assert_eq!(verdict(&sync, vault, Some(&stranger(2))), Status::Mismatch);
    assert_eq!(verdict(&sync, vault, Some(&stranger(10))), Status::Rollback);
    // …and each of those clears its warning without a request: the vault as served
    // checks out on its own, so the device takes the served manifest as its memory.
    let taken = accepted(&sync, vault).expect("the served vault stands on its own");
    assert_eq!(taken, writer);
    assert_eq!(verdict(&sync, vault, Some(&taken)), Status::Ok);
    assert_eq!(logged(&app, &t, vault.0).await, [1, 2]);

    // Writes go on from the baseline, and the devices that accepted follow them.
    let (id, mut body) = new_item(vault, "after the baseline");
    body["manifests"] = json!([next(&sync, vault, &[], &[entry(&id, false, &body)])]);
    let made = ok(&app, Method::POST, "/api/items", &t, body).await;
    assert_eq!(made["manifest_seq"], 3);
    let sync = checked(&app, &t, vault).await;
    assert_eq!(verdict(&sync, vault, Some(&taken)), Status::Ok);
    assert_eq!(verdict(&sync, vault, Some(&first_seen)), Status::NeedLog);
    assert_eq!(
        followed(&app, &t, &sync, vault, &first_seen).await,
        Status::Ok
    );
    assert_eq!(
        followed(&app, &t, &sync, vault, &stranger(1)).await,
        Status::Mismatch
    );
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "vault.manifest_reset")[0]["data"],
        json!({ "from": 1, "to": 2 })
    );
}

/// A writer stores a manifest nobody can open through an ordinary write (the server
/// can't tell). Nobody can accept that locally; a baseline gets the vault back, also
/// when the device that writes it remembers a version the server no longer has.
#[tokio::test]
async fn a_baseline_repairs_a_manifest_that_does_not_open() {
    let app = app().await;
    let (c, t) = member(&app, "mb@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    started(&app, &t, vault).await;
    let sync = checked(&app, &t, vault).await;
    let before = seen(&sync, vault.0);
    let (_, mut body) = new_item(vault, "x");
    body["manifests"] = json!([{ "vault_id": vault.0, "seq": 2, "prev": link_of(&sync, vault.0), "sealed": "AAAA" }]);
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let sync = synced(&app, &t).await;
    assert_eq!(verdict(&sync, vault, None), Status::Mismatch);
    assert_eq!(verdict(&sync, vault, Some(&before)), Status::Mismatch);
    assert_eq!(accepted(&sync, vault), None, "nothing to accept");
    // The baseline: one version above the served row and naming it, whatever the
    // device remembers (here: version 40 of a history the server doesn't have).
    let far = stranger(40);
    assert_eq!(verdict(&sync, vault, Some(&far)), Status::Rollback);
    let v = row(&sync, vault.0);
    let w = manifest::start(
        vault.1,
        vault.0,
        0,
        3,
        Some(&link_of(&sync, vault.0)),
        &entries(&sync, vault.0),
    )
    .unwrap();
    let path = format!("/api/vaults/{}/manifest", vault.0);
    let answer = ok(
        &app,
        Method::PUT,
        &path,
        &t,
        json!({ "base_seq": 2, "seq": 3, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] }),
    )
    .await;
    assert_eq!(answer["manifest_link"], json!(w.link));
    // Its writer replaces its memory with what it wrote and is fine from then on;
    // the device from before the broken manifest follows by the log.
    let wrote = Seen::parse(w.seq, &w.link).unwrap();
    let sync = checked(&app, &t, vault).await;
    assert_eq!(verdict(&sync, vault, Some(&wrote)), Status::Ok);
    assert_eq!(followed(&app, &t, &sync, vault, &before).await, Status::Ok);
    // Had it kept the old memory, the warning would have stayed.
    assert_eq!(verdict(&sync, vault, Some(&far)), Status::Rollback);
}

/// Review fix (round 2): baselines are limited per member and vault, so nobody floods
/// a vault's log or its members' activity list with them; a member who used up their
/// own budget doesn't take away anyone else's, and requests that are refused anyway
/// cost nothing.
#[tokio::test]
async fn baselines_are_limited_for_each_member_of_a_vault() {
    let app = app().await;
    let (c, ta) = member(&app, "mq-a@example.com").await;
    let (_b, tb) = member(&app, "mq-b@example.com").await;
    let home = (c.vault_id.as_str(), &c.vault_key);
    let (id, key) = new_vault(&app, &c, &ta).await;
    let vault = (id.as_str(), &key);
    assert_eq!(
        share_vault(&app, vault, &ta, "mq-b@example.com", "write", None)
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &tb, vault.0).await;
    started(&app, &ta, home).await;
    started(&app, &ta, vault).await;
    // No key is needed for the server to take a baseline: any text of the right
    // shape, each built on the last without syncing (the re-review's flood).
    let put = |t: &str, vault: &str, base: u64, prev: &str, vault_seq: u64| {
        let (app, t) = (app.clone(), t.to_owned());
        let path = format!("/api/vaults/{vault}/manifest");
        let body = json!({ "base_seq": base, "seq": base + 1, "prev": prev, "sealed": "AAAA", "vault_seq": vault_seq });
        async move { call(&app, Method::PUT, &path, Some(&t), body).await }
    };
    let sync = synced(&app, &ta).await;
    let mut seq = 1;
    let mut vault_seq = row(&sync, vault.0)["seq"].as_u64().unwrap();
    let mut prev = link_of(&sync, vault.0);
    let limit = u64::from(crate::vault::BASELINES_PER_HOUR);
    // Refused requests don't count: a stale sync, another base, a jump.
    for _ in 0..limit {
        let stale = put(&ta, vault.0, seq, &prev, vault_seq - 1).await;
        assert_eq!(code_of(&stale), CONFLICT);
        let off = put(&ta, vault.0, seq, &b64(&[5; 32]), vault_seq).await;
        assert_eq!(code_of(&off), CONFLICT);
    }
    for _ in 0..limit {
        let (s, v) = put(&ta, vault.0, seq, &prev, vault_seq).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        seq += 1;
        vault_seq += 1;
        prev = manifest::row_link(seq, &prev, "AAAA").unwrap();
        assert_eq!(v["manifest_link"], json!(prev));
    }
    let over = put(&ta, vault.0, seq, &prev, vault_seq).await;
    assert_eq!(
        (over.0, over.1["error"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("rate_limited")),
        "{}",
        over.1
    );
    // Nothing was stored by the refused one, and ordinary writes aren't touched.
    let sync = synced(&app, &ta).await;
    assert_eq!(manifest_seq(&sync, vault.0), 1 + limit);
    assert_eq!(link_of(&sync, vault.0), prev);
    // The other member repairs the vault all the same (their own budget)…
    let v = row(&sync, vault.0);
    let w = manifest::start(
        vault.1,
        vault.0,
        0,
        seq + 1,
        Some(&prev),
        &entries(&sync, vault.0),
    )
    .unwrap();
    let repaired = call(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}/manifest", vault.0),
        Some(&tb),
        json!({ "base_seq": seq, "seq": seq + 1, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] }),
    )
    .await;
    assert_eq!(repaired.0, StatusCode::OK, "{}", repaired.1);
    let sync = checked(&app, &tb, vault).await;
    // …the first member's writes go on (only baselines are counted)…
    let (item, mut body) = new_item(vault, "still writable");
    body["manifests"] = json!([next(&sync, vault, &[], &[entry(&item, false, &body)])]);
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    // …and so do that member's baselines in another vault.
    let sync = synced(&app, &ta).await;
    let home_seq = row(&sync, home.0)["seq"].as_u64().unwrap();
    let (s, v) = put(&ta, home.0, 1, &link_of(&sync, home.0), home_seq).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A first manifest is never counted: a vault made now still starts.
    let (id, key) = new_vault(&app, &c, &ta).await;
    started(&app, &ta, (id.as_str(), &key)).await;
}

#[tokio::test]
async fn every_item_write_carries_the_next_manifest() {
    let (app, state) = app_with_state().await;
    let (c, t) = member(&app, "mw@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (kept, kept_body) = new_item(vault, "kept");
    ok(&app, Method::POST, "/api/items", &t, kept_body.clone()).await;
    started(&app, &t, vault).await;
    let mut sync = checked(&app, &t, vault).await;
    let stale_manifest = next(&sync, vault, &[], &[]);
    let revision_of = |sync: &Value, id: &str| item_in(sync, id).unwrap()["revision"].clone();
    // Asserts that nothing was written by a refused request.
    let unchanged = |before: &Value| {
        let (app, t, before) = (app.clone(), t.clone(), before.clone());
        async move {
            let now = synced(&app, &t).await;
            assert_eq!(now["items"], before["items"]);
            assert_eq!(now["vaults"], before["vaults"]);
        }
    };

    // Create.
    let (a, a_body) = new_item(vault, "a");
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), a_body.clone()).await),
        REQUIRED
    );
    let mut with = a_body.clone();
    with["manifests"] = json!([next(&sync, vault, &[], &[entry(&a, false, &a_body)])]);
    let made = ok(&app, Method::POST, "/api/items", &t, with.clone()).await;
    assert_eq!(made["manifest_seq"], 2);
    sync = checked(&app, &t, vault).await;
    // The same manifest again with another write: no longer the next one.
    let (b, b_body) = new_item(vault, "b");
    let mut late = b_body.clone();
    late["manifests"] = json!([stale_manifest]);
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), late).await),
        CONFLICT
    );
    // One that skips a version, and one for another vault only.
    let mut skipping = next(&sync, vault, &[], &[entry(&b, false, &b_body)]);
    skipping["seq"] = json!(4);
    let mut skip = b_body.clone();
    skip["manifests"] = json!([skipping]);
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), skip).await),
        CONFLICT
    );
    let mut elsewhere = b_body.clone();
    elsewhere["manifests"] = json!([{ "vault_id": uuid::Uuid::new_v4().to_string(), "seq": 3, "prev": NO_PREV, "sealed": "AAAA" }]);
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), elsewhere).await),
        REQUIRED
    );
    unchanged(&sync).await;
    // A retried create finds its item: no manifest needed, none stored.
    for retry in [with.clone(), a_body.clone()] {
        let again = ok(&app, Method::POST, "/api/items", &t, retry).await;
        assert_eq!(
            (
                &again["manifest_seq"],
                &again["vault_seq"],
                &again["revision"]
            ),
            (&json!(2), &made["vault_seq"], &made["revision"])
        );
    }
    unchanged(&sync).await;

    // Edit.
    let path = format!("/api/items/{a}");
    let mut edit = item_body(&a, vault, "a2");
    edit["revision"] = revision_of(&sync, &a);
    assert_eq!(
        code_of(&call(&app, Method::PUT, &path, Some(&t), edit.clone()).await),
        REQUIRED
    );
    let manifest_of_edit = next(
        &sync,
        vault,
        &[entry(&a, false, &a_body)],
        &[entry(&a, false, &edit)],
    );
    // The item's own conflict is reported first.
    let mut stale = edit.clone();
    stale["revision"] = json!(1);
    stale["manifests"] = json!([manifest_of_edit]);
    assert_eq!(
        code_of(&call(&app, Method::PUT, &path, Some(&t), stale).await),
        (StatusCode::CONFLICT, "revision_conflict")
    );
    unchanged(&sync).await;
    edit["manifests"] = json!([manifest_of_edit]);
    let edited = ok(&app, Method::PUT, &path, &t, edit.clone()).await;
    assert_eq!(edited["manifest_seq"], 3);
    sync = checked(&app, &t, vault).await;

    // Trash, restore, delete for good: the manifest rides in the query.
    let trash = next(
        &sync,
        vault,
        &[entry(&a, false, &edit)],
        &[entry(&a, true, &edit)],
    );
    assert_eq!(
        code_of(&call(&app, Method::DELETE, &path, Some(&t), json!(null)).await),
        REQUIRED
    );
    let whole = query(&trash);
    for half in [
        "manifest_seq=4".to_owned(),
        whole.split_once("&manifest=").unwrap().0.to_owned(),
        whole.replacen("manifest_seq=4&", "", 1),
        whole.replace(trash["prev"].as_str().unwrap(), "AAAA"),
    ] {
        let (s, v) = call(
            &app,
            Method::DELETE,
            &format!("{path}?{half}"),
            Some(&t),
            json!(null),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{half}: {v}");
    }
    let wrong = format!(
        "{path}?{}",
        query(&next(&sync, vault, &[], &[])).replace("seq=4", "seq=5")
    );
    assert_eq!(
        code_of(&call(&app, Method::DELETE, &wrong, Some(&t), json!(null)).await),
        CONFLICT
    );
    unchanged(&sync).await;
    let trashed = ok(
        &app,
        Method::DELETE,
        &format!("{path}?{}", query(&trash)),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(trashed["manifest_seq"], 4);
    sync = checked(&app, &t, vault).await;

    let restore_path = format!("{path}/restore");
    let restore = next(
        &sync,
        vault,
        &[entry(&a, true, &edit)],
        &[entry(&a, false, &edit)],
    );
    assert_eq!(
        code_of(&call(&app, Method::POST, &restore_path, Some(&t), json!(null)).await),
        REQUIRED
    );
    let restored = ok(
        &app,
        Method::POST,
        &format!(
            "{restore_path}?{}&revision={}",
            query(&restore),
            trashed["revision"]
        ),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(restored["manifest_seq"], 5);
    sync = checked(&app, &t, vault).await;

    let purge_path = format!("{path}/permanent");
    let purge = next(&sync, vault, &[entry(&a, false, &edit)], &[]);
    assert_eq!(
        code_of(&call(&app, Method::DELETE, &purge_path, Some(&t), json!(null)).await),
        REQUIRED
    );
    unchanged(&sync).await;
    let purged = ok(
        &app,
        Method::DELETE,
        &format!("{purge_path}?{}", query(&purge)),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(purged["manifest_seq"], 6);
    sync = checked(&app, &t, vault).await;
    assert!(item_in(&sync, &a).is_none());

    // Import: all or nothing with its manifest; a retry stores nothing.
    let batch: Vec<(String, Value)> = (0..3).map(|n| new_item(vault, &format!("i{n}"))).collect();
    let bodies: Vec<Value> = batch.iter().map(|(_, b)| b.clone()).collect();
    let added: Vec<Entry> = batch.iter().map(|(id, b)| entry(id, false, b)).collect();
    assert_eq!(
        code_of(
            &call(
                &app,
                Method::POST,
                "/api/items/import",
                Some(&t),
                json!({ "items": bodies })
            )
            .await
        ),
        REQUIRED
    );
    unchanged(&sync).await;
    let import = json!({ "items": bodies, "manifests": [next(&sync, vault, &[], &added)] });
    let imported = ok(&app, Method::POST, "/api/items/import", &t, import.clone()).await;
    assert_eq!(
        (&imported["manifest_seq"], &imported["imported"]),
        (&json!(7), &json!(3))
    );
    assert_eq!(imported["manifest_seqs"], json!({ vault.0: 7 }));
    sync = checked(&app, &t, vault).await;
    for retry in [import, json!({ "items": bodies })] {
        let again = ok(&app, Method::POST, "/api/items/import", &t, retry).await;
        assert_eq!(
            (&again["manifest_seq"], &again["vault_seq"]),
            (&json!(7), &imported["vault_seq"])
        );
    }
    unchanged(&sync).await;

    // Several trashed items deleted for good as one write.
    let mut gone = Vec::new();
    for (id, body) in &batch[..2] {
        let m = next(
            &sync,
            vault,
            &[entry(id, false, body)],
            &[entry(id, true, body)],
        );
        ok(
            &app,
            Method::DELETE,
            &format!("/api/items/{id}?{}", query(&m)),
            &t,
            json!(null),
        )
        .await;
        sync = checked(&app, &t, vault).await;
        gone.push(entry(id, true, body));
    }
    let purge_path = format!("/api/vaults/{}/trash/purge", vault.0);
    let ids = json!([{ "id": batch[0].0 }, { "id": batch[1].0, "revision": revision_of(&sync, &batch[1].0) }]);
    assert_eq!(
        code_of(
            &call(
                &app,
                Method::POST,
                &purge_path,
                Some(&t),
                json!({ "items": ids })
            )
            .await
        ),
        REQUIRED
    );
    // An item that isn't in the trash: nothing is deleted.
    let with_live = json!({
        "items": [{ "id": batch[0].0 }, { "id": batch[2].0 }],
        "manifests": [next(&sync, vault, &gone[..1], &[])],
    });
    assert_eq!(
        code_of(&call(&app, Method::POST, &purge_path, Some(&t), with_live).await),
        (StatusCode::CONFLICT, "revision_conflict")
    );
    assert_eq!(
        call(
            &app,
            Method::POST,
            &purge_path,
            Some(&t),
            json!({ "items": [] })
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    unchanged(&sync).await;
    let emptied = ok(
        &app,
        Method::POST,
        &purge_path,
        &t,
        json!({ "items": ids, "manifests": [next(&sync, vault, &gone, &[])] }),
    )
    .await;
    assert_eq!(
        (&emptied["purged"], &emptied["manifest_seq"]),
        (&json!(2), &json!(10))
    );
    sync = checked(&app, &t, vault).await;
    assert_eq!(
        ids_of(&sync, vault.0),
        sorted(vec![kept.clone(), batch[2].0.clone()])
    );
    // A delta from before names both as deleted.
    let events = stored_events(&state).await;
    assert!(
        of_type(&events, "trash.emptied")
            .iter()
            .any(|e| e["data"]["count"] == 2),
        "{events:?}"
    );
    // Other vault writes (a rename) need no manifest and leave it alone.
    let meta = b64(&vault.1.encrypt(br#"{"name":"Renamed"}"#, b"meta").unwrap());
    ok(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}", vault.0),
        &t,
        json!({ "meta": meta }),
    )
    .await;
    assert_eq!(manifest_seq(&checked(&app, &t, vault).await, vault.0), 10);
}

fn ids_of(sync: &Value, vault: &str) -> Vec<String> {
    sorted(entries(sync, vault).into_iter().map(|e| e.id).collect())
}

#[tokio::test]
async fn a_move_carries_the_manifest_of_each_vault_that_has_one() {
    let app = app().await;
    let (c, t) = member(&app, "mm@example.com").await;
    let a = (c.vault_id.as_str(), &c.vault_key);
    let (b_id, b_key) = new_vault(&app, &c, &t).await;
    let b = (b_id.as_str(), &b_key);
    let (plain_id, plain_key) = new_vault(&app, &c, &t).await;
    let plain = (plain_id.as_str(), &plain_key);
    let (id, in_a) = new_item(a, "wanderer");
    ok(&app, Method::POST, "/api/items", &t, in_a.clone()).await;
    started(&app, &t, a).await;
    started(&app, &t, b).await;
    let path = format!("/api/items/{id}");
    let both = |sync: &Value| {
        assert_eq!(verdict(sync, a, None), Status::Ok);
        assert_eq!(verdict(sync, b, None), Status::Ok);
    };
    let mut sync = synced(&app, &t).await;
    both(&sync);

    // a → b: both manifests, or nothing moves.
    let in_b = item_body(&id, b, "wanderer");
    let leave_a = next(&sync, a, &[entry(&id, false, &in_a)], &[]);
    let enter_b = next(&sync, b, &[], &[entry(&id, false, &in_b)]);
    for partial in [json!([]), json!([leave_a]), json!([enter_b])] {
        let mut body = in_b.clone();
        body["manifests"] = partial;
        assert_eq!(
            code_of(&call(&app, Method::PUT, &path, Some(&t), body).await),
            REQUIRED
        );
    }
    let mut stale_b = enter_b.clone();
    stale_b["seq"] = json!(1);
    let mut body = in_b.clone();
    body["manifests"] = json!([leave_a, stale_b]);
    assert_eq!(
        code_of(&call(&app, Method::PUT, &path, Some(&t), body).await),
        CONFLICT
    );
    // One of the two doesn't name the manifest it replaces: nothing moves either.
    for off_chain in [
        json!([misnamed(&leave_a), enter_b]),
        json!([leave_a, misnamed(&enter_b)]),
    ] {
        let mut body = in_b.clone();
        body["manifests"] = off_chain;
        assert_eq!(
            code_of(&call(&app, Method::PUT, &path, Some(&t), body).await),
            CONFLICT
        );
    }
    let after = synced(&app, &t).await;
    assert_eq!(after["items"], sync["items"]);
    assert_eq!(after["vaults"], sync["vaults"]);
    both(&after);
    let mut body = in_b.clone();
    body["manifests"] = json!([leave_a, enter_b]);
    let moved = ok(&app, Method::PUT, &path, &t, body).await;
    assert_eq!(moved["manifest_seq"], 2, "the target vault's");
    sync = synced(&app, &t).await;
    both(&sync);
    assert_eq!((manifest_seq(&sync, a.0), manifest_seq(&sync, b.0)), (2, 2));
    assert_eq!(item_in(&sync, &id).unwrap()["vault_id"], b.0);

    // b → a vault without a manifest: only b's.
    let in_plain = item_body(&id, plain, "wanderer");
    let mut body = in_plain.clone();
    assert_eq!(
        code_of(&call(&app, Method::PUT, &path, Some(&t), body.clone()).await),
        REQUIRED
    );
    body["manifests"] = json!([next(&sync, b, &[entry(&id, false, &in_b)], &[])]);
    ok(&app, Method::PUT, &path, &t, body).await;
    sync = synced(&app, &t).await;
    both(&sync);
    assert_eq!(verdict(&sync, plain, None), Status::None);
    assert_eq!(item_in(&sync, &id).unwrap()["vault_id"], plain.0);

    // …and back into one that has: only the target's.
    let back = item_body(&id, a, "wanderer");
    let mut body = back.clone();
    assert_eq!(
        code_of(&call(&app, Method::PUT, &path, Some(&t), body.clone()).await),
        REQUIRED
    );
    body["manifests"] = json!([next(&sync, a, &[], &[entry(&id, false, &back)])]);
    ok(&app, Method::PUT, &path, &t, body).await;
    sync = synced(&app, &t).await;
    both(&sync);
    assert_eq!(
        (
            manifest_seq(&sync, a.0),
            manifest_seq(&sync, b.0),
            manifest_seq(&sync, plain.0)
        ),
        (3, 3, 0)
    );
}

#[tokio::test]
async fn a_key_replacement_carries_a_manifest_made_with_the_new_key() {
    let app = app().await;
    let (alice, ta) = member(&app, "mr-a@example.com").await;
    let (_bob, tb) = member(&app, "mr-b@example.com").await;
    let vault = (alice.vault_id.as_str(), &alice.vault_key);
    assert_eq!(
        share(&app, &alice, &ta, "mr-b@example.com", "write")
            .await
            .0,
        StatusCode::OK
    );
    accept(&app, &tb, vault.0).await;
    let (x, x_body) = new_item(vault, "x");
    ok(&app, Method::POST, "/api/items", &ta, x_body.clone()).await;
    started(&app, &ta, vault).await;
    // The other member trashes a second item, with the manifest, from their own sync.
    let sync = checked(&app, &tb, vault).await;
    let (y, mut y_body) = new_item(vault, "y");
    y_body["manifests"] = json!([next(&sync, vault, &[], &[entry(&y, false, &y_body)])]);
    ok(&app, Method::POST, "/api/items", &tb, y_body.clone()).await;
    let sync = checked(&app, &tb, vault).await;
    let m = next(
        &sync,
        vault,
        &[entry(&y, false, &y_body)],
        &[entry(&y, true, &y_body)],
    );
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{y}?{}", query(&m)),
        &tb,
        json!(null),
    )
    .await;
    let sync = checked(&app, &ta, vault).await;

    let (a, b) = (user_id(&app, &ta).await, user_id(&app, &tb).await);
    let old_head_link = link_of(&sync, vault.0);
    let new_key = SymmetricKey::generate().unwrap();
    let rekeyed = (vault.0, &new_key);
    let items = json!([item_body(&x, rekeyed, "x"), item_body(&y, rekeyed, "y")]);
    let fresh = vec![entry(&x, false, &items[0]), entry(&y, true, &items[1])];
    let keys = |members: &[&str]| -> Value {
        members
            .iter()
            .map(|u| json!({ "user_id": u, "wrapped_key": "a2V5", "key_kind": if *u == a { "account" } else { "sealed" } }))
            .collect()
    };
    // The rotation's manifest: the new key, the new epoch, and the link of the
    // manifest it replaces (sealed under the old key).
    let old_head = seen(&sync, vault.0);
    let link = link_of(&sync, vault.0);
    let sealed = |epoch: u64, seq: u64| {
        json!([sent(
            vault.0,
            &manifest::start(&new_key, vault.0, epoch, seq, Some(&link), &fresh).unwrap()
        )])
    };
    let rotate = format!("/api/vaults/{}/rotate", vault.0);
    let body = |manifests: Value| json!({ "keys": keys(&[&a, &b]), "items": items, "key_epoch": 0, "manifests": manifests });
    assert_eq!(
        code_of(&call(&app, Method::POST, &rotate, Some(&ta), body(json!([]))).await),
        REQUIRED
    );
    assert_eq!(
        code_of(&call(&app, Method::POST, &rotate, Some(&ta), body(sealed(1, 5))).await),
        CONFLICT
    );
    // The right version, but not naming the manifest it replaces (as a first
    // manifest, or another one): off the chain, refused.
    for prev in [None, Some(b64(&[5; 32]))] {
        let w = manifest::start(&new_key, vault.0, 1, 4, prev.as_deref(), &fresh).unwrap();
        assert_eq!(
            code_of(
                &call(
                    &app,
                    Method::POST,
                    &rotate,
                    Some(&ta),
                    body(json!([sent(vault.0, &w)]))
                )
                .await
            ),
            CONFLICT
        );
    }
    let before = synced(&app, &ta).await;
    assert_eq!(before["items"], sync["items"]);
    assert_eq!(row(&before, vault.0)["key_epoch"], 0);
    let done = ok(&app, Method::POST, &rotate, &ta, body(sealed(1, 4))).await;
    assert_eq!(
        (&done["key_epoch"], &done["manifest_seq"]),
        (&json!(1), &json!(4))
    );
    // Both members check the vault with the new key at the new epoch; the old key
    // no longer opens the manifest. A device that last saw the old key's manifest
    // follows the chain across the replacement without opening anything old.
    for t in [&ta, &tb] {
        let sync = checked(&app, t, rekeyed).await;
        assert_eq!(verdict(&sync, vault, None), Status::Mismatch);
        assert_eq!(row(&sync, vault.0)["key_epoch"], 1);
        assert_eq!(row(&sync, vault.0)["manifest_prev"], json!(link));
        assert_eq!(verdict(&sync, rekeyed, Some(&old_head)), Status::Ok);
    }
    assert_eq!(logged(&app, &tb, vault.0).await, [1, 2, 3, 4]);
    let first_key_sync = synced(&app, &ta).await;

    // Removing a member replaces the key in the same write: the same rule.
    let newer = SymmetricKey::generate().unwrap();
    let rekeyed = (vault.0, &newer);
    let items = json!([item_body(&x, rekeyed, "x"), item_body(&y, rekeyed, "y")]);
    let fresh = vec![entry(&x, false, &items[0]), entry(&y, true, &items[1])];
    let remove = format!("/api/vaults/{}/members/{b}/remove", vault.0);
    let body = |manifests: Value| json!({ "keys": keys(&[&a]), "items": items, "key_epoch": 1, "manifests": manifests });
    assert_eq!(
        code_of(&call(&app, Method::POST, &remove, Some(&ta), body(json!([]))).await),
        REQUIRED
    );
    let sync = synced(&app, &tb).await;
    assert!(vault_in(&sync, vault.0).is_some(), "still a member");
    let link = link_of(&sync, vault.0);
    let off_chain = manifest::start(&newer, vault.0, 2, 5, Some(&old_head_link), &fresh).unwrap();
    assert_eq!(
        code_of(
            &call(
                &app,
                Method::POST,
                &remove,
                Some(&ta),
                body(json!([sent(vault.0, &off_chain)]))
            )
            .await
        ),
        CONFLICT
    );
    assert!(vault_in(&synced(&app, &tb).await, vault.0).is_some());
    let m = json!([sent(
        vault.0,
        &manifest::start(&newer, vault.0, 2, 5, Some(&link), &fresh).unwrap()
    )]);
    let done = ok(&app, Method::POST, &remove, &ta, body(m)).await;
    assert_eq!(
        (&done["key_epoch"], &done["manifest_seq"]),
        (&json!(2), &json!(5))
    );
    let sync = checked(&app, &ta, rekeyed).await;
    assert!(vault_in(&synced(&app, &tb).await, vault.0).is_none());
    // Two key replacements on, a device that last saw the first key's manifest
    // (version 3) follows through the log; the removed member can't read the log.
    assert_eq!(verdict(&sync, rekeyed, Some(&old_head)), Status::NeedLog);
    assert_eq!(
        followed(&app, &ta, &sync, rekeyed, &old_head).await,
        Status::Ok
    );
    assert_eq!(
        followed(&app, &ta, &sync, rekeyed, &seen(&first_key_sync, vault.0)).await,
        Status::Ok
    );
    assert_eq!(logged(&app, &ta, vault.0).await, [1, 2, 3, 4, 5]);
    assert_eq!(
        log_page(&app, &tb, vault.0, "").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_sweeper_leaves_old_trash_of_manifest_vaults_to_the_apps() {
    let (app, state) = app_with_state().await;
    let (c, t) = member(&app, "mt@example.com").await;
    let kept = (c.vault_id.as_str(), &c.vault_key);
    let (plain_id, plain_key) = new_vault(&app, &c, &t).await;
    let plain = (plain_id.as_str(), &plain_key);
    let mut old = Vec::new();
    for vault in [kept, plain] {
        let (id, body) = new_item(vault, "old");
        ok(&app, Method::POST, "/api/items", &t, body.clone()).await;
        ok(
            &app,
            Method::DELETE,
            &format!("/api/items/{id}"),
            &t,
            json!(null),
        )
        .await;
        sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
            .bind(crate::db::now() - 10 * 86_400)
            .bind(&id)
            .execute(&state.db)
            .await
            .unwrap();
        old.push((id, body));
    }
    started(&app, &t, kept).await;
    assert_eq!(
        admin_set(&app, json!({ "trash_days": 7 })).await.0,
        StatusCode::OK
    );
    assert_eq!(crate::vault::purge_trash(&state).await.unwrap(), 1);
    let sync = checked(&app, &t, kept).await;
    assert!(
        item_in(&sync, &old[0].0).is_some(),
        "the manifest vault's stays"
    );
    assert!(
        item_in(&sync, &old[1].0).is_none(),
        "the other vault's is gone"
    );
    assert_eq!(crate::vault::purge_trash(&state).await.unwrap(), 0);
    assert_eq!(manifest_seq(&sync, kept.0), 1);

    // The app sees what is due from the sync answer alone and deletes it itself.
    let (days, clock) = (
        sync["trash_days"].as_i64().unwrap(),
        sync["server_time"].as_i64().unwrap(),
    );
    assert_eq!(days, 7);
    let due: Vec<&Value> = sync["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| {
            i["vault_id"] == kept.0
                && i["deleted_at"]
                    .as_i64()
                    .is_some_and(|d| d < clock - days * 86_400)
        })
        .collect();
    assert_eq!(due.len(), 1);
    let gone = [entry(&old[0].0, true, &old[0].1)];
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/trash/purge", kept.0),
        &t,
        json!({
            "items": [{ "id": due[0]["id"], "revision": due[0]["revision"] }],
            "manifests": [next(&sync, kept, &gone, &[])],
        }),
    )
    .await;
    let sync = checked(&app, &t, kept).await;
    assert!(item_in(&sync, &old[0].0).is_none());
    assert_eq!(manifest_seq(&sync, kept.0), 2);
}

/// Apply a delta answer to a full one the way the apps do.
fn merged(base: &Value, delta: &Value) -> Value {
    let mut items: Vec<Value> = base["items"].as_array().unwrap().clone();
    let gone: Vec<(&Value, &Value)> = delta["deleted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| (&d["id"], &d["vault_id"]))
        .collect();
    let reset = delta["reset"].as_array().unwrap();
    items
        .retain(|i| !gone.contains(&(&i["id"], &i["vault_id"])) && !reset.contains(&i["vault_id"]));
    for i in delta["items"].as_array().unwrap() {
        items.retain(|old| old["id"] != i["id"]);
        items.push(i.clone());
    }
    let mut out = delta.clone();
    out["items"] = items.into();
    out
}

#[tokio::test]
async fn summary_and_delta_syncs_check_out_too() {
    let app = app().await;
    let (c, t) = member(&app, "md@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let mut made = Vec::new();
    for name in ["one", "two", "three"] {
        let (id, body) = new_item(vault, name);
        ok(&app, Method::POST, "/api/items", &t, body.clone()).await;
        made.push((id, body));
    }
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{}", made[0].0),
        &t,
        json!(null),
    )
    .await;
    started(&app, &t, vault).await;
    let full = checked(&app, &t, vault).await;
    let at_first = seen(&full, vault.0);
    assert!(
        item_in(&full, &made[0].0)
            .unwrap()
            .get("data_sha256")
            .is_none()
    );

    // `trash=summary`: the trashed row comes without its data but with the hash the
    // manifest counts it by.
    let (_, summary) = call(
        &app,
        Method::GET,
        "/api/sync?trash=summary",
        Some(&t),
        json!(null),
    )
    .await;
    let trashed = item_in(&summary, &made[0].0).unwrap();
    assert!(trashed.get("data").is_none() && trashed.get("item_key").is_none());
    assert_eq!(
        trashed["data_sha256"],
        json!(b64(&manifest::data_hash(
            made[0].1["data"].as_str().unwrap()
        )))
    );
    assert!(
        item_in(&summary, &made[1].0)
            .unwrap()
            .get("data_sha256")
            .is_none()
    );
    assert_eq!(verdict(&summary, vault, None), Status::Ok);
    // Without the hash an app can't tell, and says so.
    let mut bare = summary.clone();
    for i in bare["items"].as_array_mut().unwrap() {
        i.as_object_mut().unwrap().remove("data_sha256");
    }
    assert_eq!(verdict(&bare, vault, None), Status::Incomplete);

    // Writes, then a delta on top of each earlier answer: the merged copy checks out.
    let sync = full.clone();
    let m = next(
        &sync,
        vault,
        &[entry(&made[1].0, false, &made[1].1)],
        &[entry(&made[1].0, true, &made[1].1)],
    );
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{}?{}", made[1].0, query(&m)),
        &t,
        json!(null),
    )
    .await;
    let sync = checked(&app, &t, vault).await;
    let m = next(&sync, vault, &[entry(&made[0].0, true, &made[0].1)], &[]);
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{}/permanent?{}", made[0].0, query(&m)),
        &t,
        json!(null),
    )
    .await;
    let (four, mut body) = new_item(vault, "four");
    let sync = checked(&app, &t, vault).await;
    body["manifests"] = json!([next(&sync, vault, &[], &[entry(&four, false, &body)])]);
    ok(&app, Method::POST, "/api/items", &t, body).await;

    let d = delta(&app, &t, &full["cursor"], "").await;
    assert_eq!(d["items"].as_array().unwrap().len(), 2);
    let now = merged(&full, &d);
    // Three versions on from what the device saw: it asks for the log and follows it.
    assert_eq!(verdict(&now, vault, Some(&at_first)), Status::NeedLog);
    assert_eq!(followed(&app, &t, &now, vault, &at_first).await, Status::Ok);
    assert_eq!(manifest_seq(&now, vault.0), 4);
    let d = delta(&app, &t, &summary["cursor"], "&trash=summary").await;
    let now = merged(&summary, &d);
    assert_eq!(followed(&app, &t, &now, vault, &at_first).await, Status::Ok);
    assert!(item_in(&now, &made[1].0).unwrap().get("data").is_none());
    // The base alone (what the server would have to serve to hide the changes) is
    // what a device that saw version 4 calls a rollback, and the new manifest over
    // the old items a mismatch.
    assert_eq!(
        verdict(&full, vault, Some(&seen(&now, vault.0))),
        Status::Rollback
    );
    let mut hidden = full.clone();
    hidden["vaults"] = now["vaults"].clone();
    assert_eq!(verdict(&hidden, vault, Some(&at_first)), Status::Mismatch);
    assert_eq!(verdict(&hidden, vault, None), Status::Mismatch);
}

#[tokio::test]
async fn apps_from_before_keep_working_on_vaults_without_a_manifest() {
    let app = app().await;
    let pw = "pw-manifest-1";
    let c = register(&app, "mo@example.com", pw).await;
    let old = session_as(&app, "mo@example.com", pw, Some("ios/0.11.0")).await;
    let new = session_as(&app, "mo@example.com", pw, Some(NEW_APP)).await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    // No manifest: every write as before, from both.
    let (id, body) = new_item(vault, "plain");
    ok(&app, Method::POST, "/api/items", &old, body).await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{id}"),
        &new,
        json!(null),
    )
    .await;
    ok(
        &app,
        Method::POST,
        &format!("/api/items/{id}/restore"),
        &old,
        json!(null),
    )
    .await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{id}"),
        &old,
        json!(null),
    )
    .await;
    // Emptying the trash in one request works without a manifest too.
    let purged = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/trash/purge", vault.0),
        &new,
        json!({ "items": [{ "id": id }] }),
    )
    .await;
    assert_eq!(
        (&purged["purged"], &purged["manifest_seq"]),
        (&json!(1), &json!(0))
    );
    // And while the old app is signed in, nobody starts a manifest under it.
    let sync = synced(&app, &new).await;
    assert_eq!(row(&sync, vault.0)["manifest_ok"], false);
    assert_eq!(
        code_of(&start(&app, &new, vault).await),
        (StatusCode::CONFLICT, "manifest_not_ready")
    );
    assert_eq!(
        verdict(&synced(&app, &old).await, vault, None),
        Status::None
    );
}

/// Writers that all computed the same next manifest: exactly one write is stored, the
/// others are told to sync and compute again, and the vault still checks out.
#[tokio::test]
async fn writes_at_the_same_time_take_turns() {
    let app = app().await;
    let (c, t) = member(&app, "mc@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    started(&app, &t, vault).await;
    let sync = checked(&app, &t, vault).await;
    let mut tasks = Vec::new();
    for n in 0..6 {
        let (id, mut body) = new_item(vault, &format!("racer {n}"));
        body["manifests"] = json!([next(&sync, vault, &[], &[entry(&id, false, &body)])]);
        let (app, t) = (app.clone(), t.clone());
        tasks.push(tokio::spawn(async move {
            call(&app, Method::POST, "/api/items", Some(&t), body).await
        }));
    }
    let mut won = 0;
    for task in tasks {
        let answer = task.await.unwrap();
        if answer.0 == StatusCode::OK {
            won += 1;
        } else {
            assert_eq!(code_of(&answer), CONFLICT);
        }
    }
    assert_eq!(won, 1);
    let sync = checked(&app, &t, vault).await;
    assert_eq!(
        (manifest_seq(&sync, vault.0), ids_of(&sync, vault.0).len()),
        (2, 1)
    );
}

/// Review fix: the server takes a manifest only when it names the vault's current one
/// as its predecessor, on every path that writes one.
#[tokio::test]
async fn every_write_must_name_the_manifest_it_replaces() {
    let app = app().await;
    let (c, t) = member(&app, "mn@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (a, a_body) = new_item(vault, "a");
    let (z, z_body) = new_item(vault, "z");
    for body in [&a_body, &z_body] {
        ok(&app, Method::POST, "/api/items", &t, body.clone()).await;
    }
    let trash = format!("/api/items/{z}");
    ok(&app, Method::DELETE, &trash, &t, json!(null)).await;
    started(&app, &t, vault).await;
    let sync = checked(&app, &t, vault).await;
    assert_eq!(row(&sync, vault.0)["manifest_prev"], NO_PREV);
    // Each write with the manifest it should carry, except that the manifest names
    // another predecessor: some other link, or none (as a first manifest would).
    let off_chain = |m: Value| {
        let mut as_first = m.clone();
        as_first["prev"] = json!(NO_PREV);
        [misnamed(&m), as_first]
    };
    let (live, gone) = (entry(&a, false, &a_body), entry(&z, true, &z_body));
    let (n, n_body) = new_item(vault, "new");
    let edit = item_body(&a, vault, "a2");
    let mut requests: Vec<(Method, String, Value)> = Vec::new();
    for m in off_chain(next(&sync, vault, &[], &[entry(&n, false, &n_body)])) {
        let mut body = n_body.clone();
        body["manifests"] = json!([m.clone()]);
        requests.push((Method::POST, "/api/items".into(), body));
        let import = json!({ "items": [n_body], "manifests": [m] });
        requests.push((Method::POST, "/api/items/import".into(), import));
    }
    let edited = [entry(&a, false, &edit)];
    for m in off_chain(next(&sync, vault, std::slice::from_ref(&live), &edited)) {
        let mut body = edit.clone();
        body["manifests"] = json!([m]);
        requests.push((Method::PUT, format!("/api/items/{a}"), body));
    }
    let trashed = [entry(&a, true, &a_body)];
    for m in off_chain(next(&sync, vault, std::slice::from_ref(&live), &trashed)) {
        let path = format!("/api/items/{a}?{}", query(&m));
        requests.push((Method::DELETE, path, json!(null)));
    }
    let restored = [entry(&z, false, &z_body)];
    for m in off_chain(next(&sync, vault, std::slice::from_ref(&gone), &restored)) {
        let path = format!("/api/items/{z}/restore?{}", query(&m));
        requests.push((Method::POST, path, json!(null)));
    }
    for m in off_chain(next(&sync, vault, std::slice::from_ref(&gone), &[])) {
        let path = format!("/api/items/{z}/permanent?{}", query(&m));
        requests.push((Method::DELETE, path, json!(null)));
        let purge = json!({ "items": [{ "id": z }], "manifests": [m] });
        requests.push((
            Method::POST,
            format!("/api/vaults/{}/trash/purge", vault.0),
            purge,
        ));
    }
    assert_eq!(requests.len(), 14);
    for (method, path, body) in requests {
        let what = format!("{method} {path}");
        let answer = call(&app, method, &path, Some(&t), body).await;
        assert_eq!(code_of(&answer), CONFLICT, "{what}");
    }
    let after = synced(&app, &t).await;
    assert_eq!(after["items"], sync["items"]);
    assert_eq!(after["vaults"], sync["vaults"]);
    assert_eq!(logged(&app, &t, vault.0).await, [1]);
    // The same write naming the right one goes through, and the next names it in turn.
    let mut body = n_body.clone();
    body["manifests"] = json!([next(&sync, vault, &[], &[entry(&n, false, &n_body)])]);
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let now = checked(&app, &t, vault).await;
    assert_eq!(
        row(&now, vault.0)["manifest_prev"],
        json!(link_of(&sync, vault.0))
    );
    assert_eq!(
        verdict(&now, vault, Some(&seen(&sync, vault.0))),
        Status::Ok
    );
}

/// Review fix (the finding itself): a server keeps device A on one history, lets
/// device B build another from an older state, and then serves B's to A. The version
/// is as high as A remembers and the items add up to B's manifest; A is told all the
/// same, because B's history doesn't contain the manifest A last saw.
#[tokio::test]
async fn a_device_moved_onto_another_history_is_told() {
    let (app, state) = app_with_state().await;
    let (c, ta) = member(&app, "mf@example.com").await;
    let tb = session_as(&app, "mf@example.com", "pw-manifest-1", Some(NEW_APP)).await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    started(&app, &ta, vault).await;
    let v1 = checked(&app, &ta, vault).await;
    let common = seen(&v1, vault.0);
    // Device A adds an item: version 2, which A remembers (it wrote it).
    let (a_item, mut body) = new_item(vault, "from A");
    let a_manifest = next(&v1, vault, &[], &[entry(&a_item, false, &body)]);
    body["manifests"] = json!([a_manifest]);
    ok(&app, Method::POST, "/api/items", &ta, body).await;
    let a2 = checked(&app, &ta, vault).await;
    let a_seen = seen(&a2, vault.0);
    assert_eq!(a_seen.version, 2);

    // The server goes back to version 1 for device B (the test edits its database)…
    let rewind = |sync: &Value| {
        let (state, sync, vault) = (state.clone(), sync.clone(), vault.0.to_owned());
        async move {
            let v = row(&sync, &vault);
            sqlx::query(
                "UPDATE vaults SET manifest = $1, manifest_seq = $2, manifest_prev = $3 WHERE id = $4",
            )
            .bind(v["manifest"].as_str().unwrap())
            .bind(v["manifest_seq"].as_i64().unwrap())
            .bind(v["manifest_prev"].as_str().unwrap())
            .bind(&vault)
            .execute(&state.db)
            .await
            .unwrap();
            sqlx::query("DELETE FROM vault_manifest_log WHERE vault_id = $1 AND seq > $2")
                .bind(&vault)
                .bind(v["manifest_seq"].as_i64().unwrap())
                .execute(&state.db)
                .await
                .unwrap();
        }
    };
    rewind(&v1).await;
    sqlx::query("DELETE FROM items WHERE id = $1")
        .bind(&a_item)
        .execute(&state.db)
        .await
        .unwrap();
    // …where B, which last saw version 1, notices nothing and writes its own version 2.
    let b1 = synced(&app, &tb).await;
    assert_eq!(verdict(&b1, vault, Some(&common)), Status::Ok);
    let write_from_b = |sync: Value, name: &'static str| {
        let (app, tb) = (app.clone(), tb.clone());
        let key = SymmetricKey::from_bytes(*vault.1.as_bytes());
        let id = vault.0.to_owned();
        async move {
            let vault = (id.as_str(), &key);
            let (item, mut body) = new_item(vault, name);
            body["manifests"] = json!([next(&sync, vault, &[], &[entry(&item, false, &body)])]);
            ok(&app, Method::POST, "/api/items", &tb, body).await;
            checked(&app, &tb, vault).await
        }
    };
    let b2 = write_from_b(b1, "from B").await;
    assert_eq!(manifest_seq(&b2, vault.0), 2);

    // Then it serves B's history to A: version 2 again, and the items are what B's
    // manifest records. A device that remembers nothing can't tell; A can.
    let joined = synced(&app, &ta).await;
    assert!(item_in(&joined, &a_item).is_none(), "A's item is gone");
    assert_eq!(verdict(&joined, vault, None), Status::Ok);
    assert_eq!(verdict(&joined, vault, Some(&common)), Status::Ok);
    assert_eq!(verdict(&joined, vault, Some(&a_seen)), Status::Mismatch);
    // B's history moves on before A is shown it: versions 3 and 4. A asks for the log,
    // and the log doesn't lead back to what A saw.
    let mut sync = b2;
    for name in ["from B again", "and again"] {
        sync = write_from_b(sync, name).await;
        let joined = synced(&app, &ta).await;
        assert_eq!(joined["vaults"], sync["vaults"]);
        // (The very next version is settled without the log, later ones with it.)
        let first_look = match manifest_seq(&joined, vault.0) - a_seen.version {
            1 => Status::Mismatch,
            _ => Status::NeedLog,
        };
        assert_eq!(verdict(&joined, vault, Some(&a_seen)), first_look);
        assert_eq!(
            followed(&app, &ta, &joined, vault, &a_seen).await,
            Status::Mismatch
        );
        // Nor when the server puts A's own version 2 into the log it hands out.
        let mut log = log_after(&app, &ta, vault.0, 2).await;
        log.push(LogEntry {
            seq: 2,
            prev: row(&a2, vault.0)["manifest_prev"].as_str().unwrap().into(),
            digest: b64(&manifest::sealed_digest(
                row(&a2, vault.0)["manifest"].as_str().unwrap(),
            )),
        });
        assert_eq!(
            verdict_with(&joined, vault, Some(&a_seen), Some(&log)),
            Status::Mismatch
        );
        // B, and a device that only saw version 1, follow B's history.
        assert_eq!(
            followed(&app, &tb, &joined, vault, &common).await,
            Status::Ok
        );
    }

    // A's user looks and takes the server's copy. The vault as served stands on its
    // own (B's manifest records B's items), so this is A's decision alone and needs no
    // request: A's memory becomes the served manifest, and A follows B's history from
    // there, while its old memory would still be told.
    let joined = synced(&app, &ta).await;
    let taken = accepted(&joined, vault).expect("B's history stands on its own");
    assert_eq!(taken, seen(&joined, vault.0));
    assert_eq!(verdict(&joined, vault, Some(&taken)), Status::Ok);
    let b5 = write_from_b(synced(&app, &tb).await, "after A accepted").await;
    assert_eq!(verdict(&b5, vault, Some(&taken)), Status::Ok);
    assert_eq!(
        followed(&app, &ta, &b5, vault, &a_seen).await,
        Status::Mismatch
    );
    // A baseline does the same for every device on the served history at once (it is
    // what a member writes when the served manifest itself is wrong): one version
    // up, built on the manifest the server shows.
    let joined = synced(&app, &ta).await;
    let v = row(&joined, vault.0);
    let seq = manifest_seq(&joined, vault.0) + 1;
    let w = manifest::start(
        vault.1,
        vault.0,
        0,
        seq,
        Some(&link_of(&joined, vault.0)),
        &entries(&joined, vault.0),
    )
    .unwrap();
    let answer = ok(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}/manifest", vault.0),
        &ta,
        json!({ "base_seq": v["manifest_seq"], "seq": seq, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] }),
    )
    .await;
    assert_eq!(answer["manifest_seq"], seq);
    let wrote = Seen::parse(w.seq, &w.link).unwrap();
    let now = synced(&app, &tb).await;
    // A (which wrote it), B (whose history it continues) and the old device accept it;
    // another device still on A's old history is told in its turn.
    assert_eq!(verdict(&now, vault, Some(&wrote)), Status::Ok);
    assert_eq!(
        verdict(&now, vault, Some(&seen(&joined, vault.0))),
        Status::Ok
    );
    assert_eq!(followed(&app, &tb, &now, vault, &common).await, Status::Ok);
    assert_eq!(
        followed(&app, &ta, &now, vault, &a_seen).await,
        Status::Mismatch
    );
    let events = stored_events(&state).await;
    assert_eq!(
        of_type(&events, "vault.manifest_reset")[0]["data"],
        json!({ "from": 5, "to": 6 })
    );
}

#[tokio::test]
async fn the_manifest_log_follows_every_stored_manifest() {
    let (app, state) = app_with_state().await;
    let (c, t) = member(&app, "ml@example.com").await;
    let home = (c.vault_id.as_str(), &c.vault_key);
    let (id, key) = new_vault(&app, &c, &t).await;
    let vault = (id.as_str(), &key);
    assert!(logged(&app, &t, vault.0).await.is_empty());
    started(&app, &t, home).await;
    started(&app, &t, vault).await;
    // Versions 1 to 7, and what a device remembers at each.
    let mut sync = checked(&app, &t, vault).await;
    let mut seen_at = vec![seen(&sync, vault.0)];
    for n in 2..=7 {
        let (item, mut body) = new_item(vault, &format!("item {n}"));
        body["manifests"] = json!([next(&sync, vault, &[], &[entry(&item, false, &body)])]);
        ok(&app, Method::POST, "/api/items", &t, body).await;
        sync = checked(&app, &t, vault).await;
        seen_at.push(seen(&sync, vault.0));
    }
    let at = |version: usize| &seen_at[version - 1];

    // One entry a manifest: its version, the link it replaced, the hash of its text.
    let log = log_after(&app, &t, vault.0, 0).await;
    assert_eq!(
        log.iter().map(|e| e.seq).collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(log[0].prev, NO_PREV);
    for (n, e) in log.iter().enumerate().skip(1) {
        assert_eq!(e.prev, b64(&seen_at[n - 1].link), "version {}", e.seq);
    }
    let head = row(&sync, vault.0);
    assert_eq!(log[6].prev, head["manifest_prev"]);
    assert_eq!(
        log[6].digest,
        b64(&manifest::sealed_digest(head["manifest"].as_str().unwrap()))
    );
    // Pages.
    let seqs = |page: &Value| -> Vec<i64> {
        let entries = page["entries"].as_array().unwrap();
        entries.iter().map(|e| e["seq"].as_i64().unwrap()).collect()
    };
    for (query, entries, more) in [
        ("", vec![1, 2, 3, 4, 5, 6, 7], false),
        ("?after=4", vec![5, 6, 7], false),
        ("?after=0&limit=3", vec![1, 2, 3], true),
        ("?after=3&limit=3", vec![4, 5, 6], true),
        ("?after=4&limit=3", vec![5, 6, 7], false),
        ("?after=6&limit=3", vec![7], false),
        ("?after=7", vec![], false),
        ("?after=700", vec![], false),
    ] {
        let (s, page) = log_page(&app, &t, vault.0, query).await;
        assert_eq!(
            (s, seqs(&page), &page["more"]),
            (StatusCode::OK, entries, &json!(more)),
            "{query}"
        );
    }
    for bad in ["?after=-1", "?limit=0", "?limit=2001", "?after=x"] {
        let (s, _) = log_page(&app, &t, vault.0, bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
    // Members only, whatever their role; not invitees, strangers or nobody.
    let (_reader, tr) = member(&app, "ml-r@example.com").await;
    let (_other, to) = member(&app, "ml-o@example.com").await;
    let path = format!("/api/vaults/{}/manifest-log", vault.0);
    assert_eq!(
        share_vault(&app, vault, &t, "ml-r@example.com", "read", None)
            .await
            .0,
        StatusCode::OK
    );
    for stranger in [&tr, &to] {
        assert_eq!(
            log_page(&app, stranger, vault.0, "").await.0,
            StatusCode::NOT_FOUND
        );
    }
    accept(&app, &tr, vault.0).await;
    assert_eq!(logged(&app, &tr, vault.0).await, [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(
        call(&app, Method::GET, &path, None, json!(null)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let unknown = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        log_page(&app, &t, &unknown, "").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        log_page(&app, &t, "not-a-vault", "").await.0,
        StatusCode::BAD_REQUEST
    );
    // The reader follows the chain like anyone.
    let sync = synced(&app, &tr).await;
    assert_eq!(followed(&app, &tr, &sync, vault, at(2)).await, Status::Ok);

    // The log keeps what is recent by count or by age. With the three newest left
    // (and nothing young enough to stay for its age), a device at version 4 still
    // follows (the oldest entry names it), one further behind can't tell a pruned
    // log from a withheld one and is warned, until its user accepts the server's
    // copy on that device, which the vault as served always allows here.
    let keep = |newest, age, most| crate::vault::ManifestLogKeep { newest, age, most };
    let prune = |keep, at: i64| {
        let (state, vault) = (state.clone(), vault.0.to_owned());
        async move {
            let mut conn = state.db.acquire().await.unwrap();
            crate::vault::prune_manifest_log(&mut conn, &vault, 7, keep, at)
                .await
                .unwrap();
        }
    };
    let t0 = crate::db::now();
    // Every entry is younger than the age kept: nothing goes, however few "newest".
    prune(keep(1, 3600, 100), t0).await;
    assert_eq!(logged(&app, &t, vault.0).await, [1, 2, 3, 4, 5, 6, 7]);
    // …except beyond the hard cap, which counts whatever the age.
    prune(keep(1, 3600, 6), t0).await;
    assert_eq!(logged(&app, &t, vault.0).await, [2, 3, 4, 5, 6, 7]);
    // Old entries (here: seen from two hours on) go, but for the newest three.
    prune(keep(3, 3600, 100), t0 + 7200).await;
    assert_eq!(logged(&app, &t, vault.0).await, [5, 6, 7]);
    assert_eq!(logged(&app, &t, home.0).await, [1], "another vault's stays");
    for (version, expected) in [
        (7, Status::Ok),
        (6, Status::Ok),
        (5, Status::Ok),
        (4, Status::Ok),
        (3, Status::Mismatch),
        (1, Status::Mismatch),
    ] {
        assert_eq!(
            followed(&app, &t, &sync, vault, at(version)).await,
            expected,
            "a device at version {version}"
        );
    }
    let taken = accepted(&sync, vault).expect("the vault stands on its own");
    assert_eq!(followed(&app, &t, &sync, vault, &taken).await, Status::Ok);

    // A write stores its entry with the time, and every 64th version of a vault
    // prunes in its own transaction by the real rule: bring the vault to version 63
    // with old entries, add entries far behind the newest 5000 (old ones and young
    // ones), write version 64, and see what stays.
    let stored_at: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT seq, created_at FROM vault_manifest_log WHERE vault_id = $1 ORDER BY seq",
    )
    .bind(vault.0)
    .fetch_all(&state.db)
    .await
    .unwrap();
    assert!(stored_at.iter().all(|(_, at)| (t0 - 60..=t0).contains(at)));
    let keep = crate::vault::MANIFEST_LOG_KEEP;
    assert_eq!(
        (keep.newest, keep.age, keep.most),
        (5000, 90 * 86_400, 200_000)
    );
    let count = || {
        let (state, vault) = (state.clone(), vault.0.to_owned());
        async move {
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT COUNT(*), COALESCE(MIN(seq), 0) FROM vault_manifest_log WHERE vault_id = $1",
            )
            .bind(vault)
            .fetch_one(&state.db)
            .await
            .unwrap()
        }
    };
    // The test moves the vault's manifest to version 63 directly, with the rows the
    // log would hold (version n names n − 1), all a hundred days old.
    sqlx::query("UPDATE vault_manifest_log SET created_at = $2 WHERE vault_id = $1")
        .bind(vault.0)
        .bind(t0 - 100 * 86_400)
        .execute(&state.db)
        .await
        .unwrap();
    let head = row(&sync, vault.0);
    let mut prev = link_of(&sync, vault.0);
    let mut sealed = head["manifest"].as_str().unwrap().to_owned();
    for seq in 8..=63_i64 {
        sealed = format!("AAAA{seq}");
        sqlx::query(
            "INSERT INTO vault_manifest_log (vault_id, seq, prev, digest, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(vault.0)
        .bind(seq)
        .bind(&prev)
        .bind(b64(&manifest::sealed_digest(&sealed)))
        .bind(t0 - 100 * 86_400)
        .execute(&state.db)
        .await
        .unwrap();
        if seq < 63 {
            prev = manifest::row_link(seq as u64, &prev, &sealed).unwrap();
        }
    }
    sqlx::query(
        "UPDATE vaults SET manifest = $2, manifest_seq = 63, manifest_prev = $3 WHERE id = $1",
    )
    .bind(vault.0)
    .bind(&sealed)
    .bind(&prev)
    .execute(&state.db)
    .await
    .unwrap();
    assert_eq!(count().await, (59, 5));
    // Entries more than 5000 versions behind (the test gives them the versions
    // below −4936 that a longer history would have left there): three old, two
    // young.
    let behind = |seqs: [i64; 5]| {
        let (state, vault) = (state.clone(), vault.0.to_owned());
        async move {
            for (n, seq) in seqs.into_iter().enumerate() {
                let at = if n < 3 {
                    t0 - 100 * 86_400
                } else {
                    t0 - 86_400
                };
                sqlx::query(
                    "INSERT INTO vault_manifest_log (vault_id, seq, prev, digest, created_at)
                     VALUES ($1, $2, 'x', 'x', $3)",
                )
                .bind(&vault)
                .bind(seq)
                .bind(at)
                .execute(&state.db)
                .await
                .unwrap();
            }
        }
    };
    behind([-5000, -4999, -4936, -4998, -4997]).await;
    assert_eq!(count().await, (64, -5000));
    // The stored manifest is one nobody can open: a baseline (version 64) repairs
    // it, and prunes: the old entries behind the newest 5000 go, the young ones
    // stay for their age, and the 60 newest stay, old as they are.
    let sync = synced(&app, &t).await;
    assert_eq!(accepted(&sync, vault), None);
    let v = row(&sync, vault.0);
    let w = manifest::start(
        vault.1,
        vault.0,
        0,
        64,
        Some(&link_of(&sync, vault.0)),
        &entries(&sync, vault.0),
    )
    .unwrap();
    ok(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}/manifest", vault.0),
        &t,
        json!({ "base_seq": 63, "seq": 64, "prev": w.prev, "sealed": w.sealed, "vault_seq": v["seq"] }),
    )
    .await;
    assert_eq!(count().await, (62, -4998));
    let sync = checked(&app, &t, vault).await;
    // The device that accepted at version 7 follows the whole way by the log.
    assert_eq!(followed(&app, &t, &sync, vault, &taken).await, Status::Ok);
    // Version 65 doesn't prune (only every 64th does): the same kind of rows stay.
    behind([-5010, -5009, -5008, -5007, -5006]).await;
    let (item, mut body) = new_item(vault, "item 65");
    body["manifests"] = json!([next(&sync, vault, &[], &[entry(&item, false, &body)])]);
    let made = ok(&app, Method::POST, "/api/items", &t, body).await;
    assert_eq!(made["manifest_seq"], 65);
    assert_eq!(count().await, (68, -5010));
    // By the real rule at a later time and a higher version: what is old and not
    // among the newest goes, what is young stays, the cap holds.
    let mut conn = state.db.acquire().await.unwrap();
    sqlx::query("UPDATE vault_manifest_log SET created_at = $2 WHERE vault_id = $1 AND seq > 60 AND seq < 64")
        .bind(vault.0)
        .bind(t0)
        .execute(&mut *conn)
        .await
        .unwrap();
    let small = crate::vault::ManifestLogKeep { newest: 2, ..keep };
    crate::vault::prune_manifest_log(&mut conn, vault.0, 65, small, t0)
        .await
        .unwrap();
    drop(conn);
    // Young: 61…65 and the four from a day ago; old but among the newest two: none.
    assert_eq!(
        logged_all(&state, vault.0).await,
        [-5007, -5006, -4998, -4997, 61, 62, 63, 64, 65]
    );
    // The cap counts whatever the age.
    let mut conn = state.db.acquire().await.unwrap();
    let capped = crate::vault::ManifestLogKeep { most: 3, ..keep };
    crate::vault::prune_manifest_log(&mut conn, vault.0, 65, capped, t0)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(logged_all(&state, vault.0).await, [63, 64, 65]);

    // The log goes with its vault.
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{}", vault.0),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(count().await.0, 0);
    assert_eq!(logged(&app, &t, home.0).await, [1]);
}

/// The link of a manifest entry as a write sent it.
fn link_sent(m: &Value) -> String {
    manifest::row_link(
        m["seq"].as_u64().unwrap(),
        m["prev"].as_str().unwrap(),
        m["sealed"].as_str().unwrap(),
    )
    .unwrap()
}

/// Review fix (round 2): every answer of a write that can carry a manifest names the
/// link of the vault's manifest after the request. An app applies its write to its
/// own copy only when that is the link of what it sent; the version alone can't tell
/// a stored write from a retried one that found its item under another sealing.
#[tokio::test]
async fn every_write_answer_names_the_link_of_the_vaults_manifest() {
    let app = app().await;
    let (c, t) = member(&app, "mk@example.com").await;
    let (_bob, tb) = member(&app, "mk-b@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (other_id, other_key) = new_vault(&app, &c, &t).await;
    let other = (other_id.as_str(), &other_key);
    let (plain_id, plain_key) = new_vault(&app, &c, &t).await;
    let plain = (plain_id.as_str(), &plain_key);

    // Without a manifest: version 0 and no link, on every answer.
    let (p, body) = new_item(plain, "plain");
    let made = ok(&app, Method::POST, "/api/items", &t, body.clone()).await;
    assert_eq!(
        (&made["manifest_seq"], &made["manifest_link"]),
        (&json!(0), &Value::Null)
    );
    let again = ok(&app, Method::POST, "/api/items", &t, body).await;
    assert_eq!(again["manifest_link"], Value::Null);
    let trashed = ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{p}"),
        &t,
        json!(null),
    )
    .await;
    assert!(trashed.as_object().unwrap().contains_key("manifest_link"));
    assert_eq!(trashed["manifest_link"], Value::Null);

    // The first manifest's answer names it.
    let (s, first) = start(&app, &t, vault).await;
    assert_eq!(s, StatusCode::OK, "{first}");
    started(&app, &t, other).await;
    let sync = checked(&app, &t, vault).await;
    assert_eq!(first["manifest_link"], json!(link_of(&sync, vault.0)));
    // After every write: the answer's link is the link of what was sent, and of
    // what the next sync shows.
    let same = |answer: &Value, m: &Value, sync: &Value, vault: &str| {
        assert_eq!(answer["manifest_seq"], m["seq"], "{answer}");
        assert_eq!(answer["manifest_link"], json!(link_sent(m)), "{answer}");
        assert_eq!(link_sent(m), link_of(sync, vault));
    };

    // Create.
    let before_x = sync.clone();
    let (x, mut x_body) = new_item(vault, "x");
    let m = next(&sync, vault, &[], &[entry(&x, false, &x_body)]);
    x_body["manifests"] = json!([m]);
    let made = ok(&app, Method::POST, "/api/items", &t, x_body.clone()).await;
    let sync = checked(&app, &t, vault).await;
    same(&made, &m, &sync, vault.0);
    // The same create again (its answer was lost), with the same manifest: stored
    // nothing, and the link says the vault's manifest is the one sent.
    let again = ok(&app, Method::POST, "/api/items", &t, x_body.clone()).await;
    assert_eq!(again["manifest_link"], made["manifest_link"]);
    assert_eq!(again["vault_seq"], made["vault_seq"]);
    // The re-review's case: the retry seals the manifest afresh (the same base, the
    // same content, another nonce). The version and the vault's number answer
    // exactly as for a stored write; only the link shows that the vault holds
    // another sealing (the first attempt's), so the app must not remember what it
    // sent this time.
    let m2 = next(&before_x, vault, &[], &[entry(&x, false, &x_body)]);
    assert_eq!((&m2["seq"], &m2["prev"]), (&m["seq"], &m["prev"]));
    assert_ne!(link_sent(&m2), link_sent(&m), "another sealing");
    let mut retry = x_body.clone();
    retry["manifests"] = json!([m2]);
    let again = ok(&app, Method::POST, "/api/items", &t, retry).await;
    assert_eq!(again["manifest_seq"], m2["seq"]);
    assert_eq!(again["vault_seq"], made["vault_seq"]);
    assert_ne!(again["manifest_link"], json!(link_sent(&m2)));
    assert_eq!(again["manifest_link"], json!(link_sent(&m)));
    // A device that remembered the second sealing would be on a history the server
    // never had; one that goes by the answer's link is right.
    let now = synced(&app, &t).await;
    let wrong = Seen::parse(m2["seq"].as_u64().unwrap(), &link_sent(&m2)).unwrap();
    assert_eq!(verdict(&now, vault, Some(&wrong)), Status::Mismatch);
    let right = Seen::parse(
        again["manifest_seq"].as_u64().unwrap(),
        again["manifest_link"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(verdict(&now, vault, Some(&right)), Status::Ok);
    // A retry after the vault moved on: the link is the current manifest's, which is
    // neither attempt's.
    let (y, mut y_body) = new_item(vault, "y");
    let my = next(&sync, vault, &[], &[entry(&y, false, &y_body)]);
    y_body["manifests"] = json!([my]);
    let made_y = ok(&app, Method::POST, "/api/items", &t, y_body.clone()).await;
    let sync = checked(&app, &t, vault).await;
    same(&made_y, &my, &sync, vault.0);
    let late = ok(&app, Method::POST, "/api/items", &t, x_body.clone()).await;
    assert_eq!(late["manifest_link"], json!(link_sent(&my)));

    // Import into two vaults, one of them without a manifest; then the same again.
    let (i1, b1) = new_item(vault, "imported");
    let (_, b2) = new_item(plain, "imported too");
    let mi = next(&sync, vault, &[], &[entry(&i1, false, &b1)]);
    let import = json!({ "items": [b1, b2], "manifests": [mi] });
    let done = ok(&app, Method::POST, "/api/items/import", &t, import.clone()).await;
    let sync = checked(&app, &t, vault).await;
    assert_eq!(done["manifest_seqs"][vault.0], mi["seq"]);
    assert_eq!(done["manifest_links"][vault.0], json!(link_sent(&mi)));
    assert_eq!(done["manifest_links"][plain.0], Value::Null);
    assert!(
        done.get("manifest_link").is_none(),
        "two vaults: no single one"
    );
    assert_eq!(link_sent(&mi), link_of(&sync, vault.0));
    let replay = ok(&app, Method::POST, "/api/items/import", &t, import).await;
    assert_eq!(replay["manifest_links"], done["manifest_links"]);
    // Into one vault: the single fields too.
    let (i3, b3) = new_item(vault, "imported alone");
    let mi = next(&sync, vault, &[], &[entry(&i3, false, &b3)]);
    let import = json!({ "items": [b3], "manifests": [mi] });
    let done = ok(&app, Method::POST, "/api/items/import", &t, import).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &mi, &sync, vault.0);
    assert_eq!(done["manifest_links"][vault.0], done["manifest_link"]);

    // Edit.
    let edited = item_body(&x, vault, "x edited");
    let m = next(
        &sync,
        vault,
        &[entry(&x, false, &x_body)],
        &[entry(&x, false, &edited)],
    );
    let mut body = edited.clone();
    body["manifests"] = json!([m]);
    let done = ok(&app, Method::PUT, &format!("/api/items/{x}"), &t, body).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &m, &sync, vault.0);
    assert!(done.get("manifest_links").is_none(), "not a move");

    // Move to the other vault: the answer's single fields are the new vault's, and
    // `manifest_links` names both.
    let in_other = item_body(&x, other, "x edited");
    let leave = next(&sync, vault, &[entry(&x, false, &edited)], &[]);
    let enter = next(&sync, other, &[], &[entry(&x, false, &in_other)]);
    let mut body = in_other.clone();
    body["manifests"] = json!([leave, enter]);
    let done = ok(&app, Method::PUT, &format!("/api/items/{x}"), &t, body).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &enter, &sync, other.0);
    assert_eq!(done["manifest_links"][other.0], json!(link_sent(&enter)));
    assert_eq!(done["manifest_links"][vault.0], json!(link_sent(&leave)));
    assert_eq!(link_sent(&leave), link_of(&sync, vault.0));
    // …and on to the vault without a manifest: null for that one.
    let in_plain = item_body(&x, plain, "x edited");
    let leave = next(&sync, other, &[entry(&x, false, &in_other)], &[]);
    let mut body = in_plain.clone();
    body["manifests"] = json!([leave]);
    let done = ok(&app, Method::PUT, &format!("/api/items/{x}"), &t, body).await;
    assert_eq!(
        (&done["manifest_seq"], &done["manifest_link"]),
        (&json!(0), &Value::Null)
    );
    assert_eq!(done["manifest_links"][plain.0], Value::Null);
    assert_eq!(done["manifest_links"][other.0], json!(link_sent(&leave)));

    // Trash, restore, delete for good (the three requests without a body).
    let sync = checked(&app, &t, vault).await;
    let m = next(
        &sync,
        vault,
        &[entry(&y, false, &y_body)],
        &[entry(&y, true, &y_body)],
    );
    let path = format!("/api/items/{y}?{}", query(&m));
    let done = ok(&app, Method::DELETE, &path, &t, json!(null)).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &m, &sync, vault.0);
    let m = next(
        &sync,
        vault,
        &[entry(&y, true, &y_body)],
        &[entry(&y, false, &y_body)],
    );
    let path = format!("/api/items/{y}/restore?{}", query(&m));
    let done = ok(&app, Method::POST, &path, &t, json!(null)).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &m, &sync, vault.0);
    let m = next(&sync, vault, &[entry(&y, false, &y_body)], &[]);
    let path = format!("/api/items/{y}/permanent?{}", query(&m));
    let done = ok(&app, Method::DELETE, &path, &t, json!(null)).await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &m, &sync, vault.0);

    // Trash and bulk purge.
    let i1_row = item_in(&sync, &i1).unwrap().clone();
    let m = next(
        &sync,
        vault,
        &[entry(&i1, false, &i1_row)],
        &[entry(&i1, true, &i1_row)],
    );
    let path = format!("/api/items/{i1}?{}", query(&m));
    ok(&app, Method::DELETE, &path, &t, json!(null)).await;
    let sync = checked(&app, &t, vault).await;
    let m = next(&sync, vault, &[entry(&i1, true, &i1_row)], &[]);
    let done = ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/trash/purge", vault.0),
        &t,
        json!({ "items": [{ "id": i1 }], "manifests": [m] }),
    )
    .await;
    let sync = checked(&app, &t, vault).await;
    same(&done, &m, &sync, vault.0);

    // Key replacement, and removing a member with one.
    assert_eq!(
        share(&app, &c, &t, "mk-b@example.com", "write").await.0,
        StatusCode::OK
    );
    accept(&app, &tb, vault.0).await;
    let (a, b) = (user_id(&app, &t).await, user_id(&app, &tb).await);
    let sync = checked(&app, &t, vault).await;
    assert_eq!(ids_of(&sync, vault.0), [i3.as_str()], "the one item left");
    let keys = |members: &[&str]| -> Value {
        members
            .iter()
            .map(|u| json!({ "user_id": u, "wrapped_key": "a2V5", "key_kind": if *u == a { "account" } else { "sealed" } }))
            .collect()
    };
    let mut link = link_of(&sync, vault.0);
    let mut seq = manifest_seq(&sync, vault.0);
    for (epoch, path, members) in [
        (1, format!("/api/vaults/{}/rotate", vault.0), vec![&a, &b]),
        (
            2,
            format!("/api/vaults/{}/members/{b}/remove", vault.0),
            vec![&a],
        ),
    ] {
        let new_key = SymmetricKey::generate().unwrap();
        let rekeyed = (vault.0, &new_key);
        let items = json!([item_body(&i3, rekeyed, "imported alone")]);
        let fresh = vec![entry(&i3, false, &items[0])];
        let w = manifest::start(&new_key, vault.0, epoch, seq + 1, Some(&link), &fresh).unwrap();
        let members: Vec<&str> = members.iter().map(|m| m.as_str()).collect();
        let body = json!({ "keys": keys(&members), "items": items, "key_epoch": epoch - 1, "manifests": [sent(vault.0, &w)] });
        let done = ok(&app, Method::POST, &path, &t, body).await;
        assert_eq!(done["manifest_seq"], w.seq, "{path}");
        assert_eq!(done["manifest_link"], json!(w.link), "{path}");
        let sync = checked(&app, &t, rekeyed).await;
        assert_eq!(link_of(&sync, vault.0), w.link);
        (link, seq) = (w.link, w.seq);
    }
}

/// An item nobody can open (its wrapped key is rubbish; a member with write access
/// can store one, and the manifest only covers `data`): the vault's manifest checks
/// out, but apps can't show the item and warn. Any member who can write removes it
/// with ordinary requests, without opening it: the row counts by its id, state and
/// `data`, which every app has.
#[tokio::test]
async fn an_item_nobody_can_open_is_deleted_like_any_other() {
    let app = app().await;
    let (c, t) = member(&app, "mu@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (good, good_body) = new_item(vault, "good");
    ok(&app, Method::POST, "/api/items", &t, good_body).await;
    started(&app, &t, vault).await;
    let unopenable = |name: &str| {
        let (id, mut body) = new_item(vault, name);
        body["key"] = json!(b64(&[7; 72]));
        (id, body)
    };
    let opens = |sync: &Value, id: &str| {
        let row = item_in(sync, id).unwrap();
        let enc: EncryptedItem = serde_json::from_value(json!({
            "id": id, "vault_id": vault.0, "key": row["item_key"], "data": row["data"],
        }))
        .unwrap();
        enc.decrypt(vault.1).is_ok()
    };
    // Stored with a correct manifest: the server can't tell, the manifest checks out.
    let sync = checked(&app, &t, vault).await;
    let (live, mut live_body) = unopenable("live");
    live_body["manifests"] = json!([next(&sync, vault, &[], &[entry(&live, false, &live_body)])]);
    ok(&app, Method::POST, "/api/items", &t, live_body).await;
    let sync = checked(&app, &t, vault).await;
    let (other, mut other_body) = unopenable("for the trash");
    other_body["manifests"] = json!([next(
        &sync,
        vault,
        &[],
        &[entry(&other, false, &other_body)]
    )]);
    ok(&app, Method::POST, "/api/items", &t, other_body).await;
    let sync = checked(&app, &t, vault).await;
    assert!(opens(&sync, &good));
    assert!(!opens(&sync, &live) && !opens(&sync, &other));

    // One request: delete the live row for good. The manifest's `removed` entry is
    // the row as synced (id, `deleted_at`, `data`); nothing of it was opened.
    let rows = entries(&sync, vault.0);
    let as_synced = |id: &str| rows.iter().find(|e| e.id == id).unwrap().clone();
    let revision = item_in(&sync, &live).unwrap()["revision"].as_i64().unwrap();
    let m = next(&sync, vault, &[as_synced(&live)], &[]);
    let done = ok(
        &app,
        Method::DELETE,
        &format!(
            "/api/items/{live}/permanent?revision={revision}&{}",
            query(&m)
        ),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(done["manifest_link"], json!(link_sent(&m)));
    let sync = checked(&app, &t, vault).await;
    assert!(item_in(&sync, &live).is_none());

    // Or two: into the trash, then out of it with the batch request.
    let row = item_in(&sync, &other).unwrap().clone();
    let m = next(
        &sync,
        vault,
        &[entry(&other, false, &row)],
        &[entry(&other, true, &row)],
    );
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{other}?{}", query(&m)),
        &t,
        json!(null),
    )
    .await;
    let sync = checked(&app, &t, vault).await;
    let trashed: Vec<Entry> = entries(&sync, vault.0)
        .into_iter()
        .filter(|e| e.id == other)
        .collect();
    assert_eq!(trashed.len(), 1);
    let m = next(&sync, vault, &trashed, &[]);
    ok(
        &app,
        Method::POST,
        &format!("/api/vaults/{}/trash/purge", vault.0),
        &t,
        json!({ "items": [{ "id": other }], "manifests": [m] }),
    )
    .await;
    // The vault is whole again: one item, which opens.
    let sync = checked(&app, &t, vault).await;
    assert_eq!(ids_of(&sync, vault.0), [good.as_str()]);
    assert!(opens(&sync, &good));
}
