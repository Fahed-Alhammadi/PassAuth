//! Vault manifests (migration 17): the compatibility gate, the first manifest and a
//! new baseline, every item write with and without its manifest, retried creates and
//! imports, moves, key replacement, the trash sweeper, and what `/sync` hands out.
//! The tests play the apps' part with the core (`passauth_core::manifest`), so each
//! accepted write is also checked the way an app checks a sync.

use passauth_core::manifest::{self, Entry, Status};

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

/// What an app concludes about `vault` from one sync answer.
fn verdict(sync: &Value, (vault, key): (&str, &SymmetricKey), remembered: Option<u64>) -> Status {
    let v = row(sync, vault);
    manifest::verify(
        key,
        vault,
        v["key_epoch"].as_u64().unwrap(),
        v["manifest_seq"].as_u64().unwrap(),
        v["manifest"].as_str(),
        remembered,
        &entries(sync, vault),
    )
    .unwrap()
    .status
}

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

/// `{vault_id, seq, sealed}`: the vault's next manifest after a write that removes
/// and adds these entries, from the state `sync` shows.
fn next(
    sync: &Value,
    (vault, key): (&str, &SymmetricKey),
    removed: &[Entry],
    added: &[Entry],
) -> Value {
    let v = row(sync, vault);
    let (seq, sealed) = manifest::advance(
        key,
        vault,
        v["key_epoch"].as_u64().unwrap(),
        v["manifest_seq"].as_u64().unwrap(),
        v["manifest"].as_str().unwrap(),
        removed,
        added,
    )
    .unwrap();
    json!({ "vault_id": vault, "seq": seq, "sealed": sealed })
}

fn query(m: &Value) -> String {
    format!(
        "manifest_seq={}&manifest={}",
        m["seq"],
        m["sealed"].as_str().unwrap()
    )
}

/// Start `vault`'s first manifest from a fresh sync; returns the answer.
async fn start(app: &Router, t: &str, (vault, key): (&str, &SymmetricKey)) -> (StatusCode, Value) {
    let sync = synced(app, t).await;
    let v = row(&sync, vault);
    let sealed = manifest::start(
        key,
        vault,
        v["key_epoch"].as_u64().unwrap(),
        1,
        &entries(&sync, vault),
    )
    .unwrap();
    call(
        app,
        Method::PUT,
        &format!("/api/vaults/{vault}/manifest"),
        Some(t),
        json!({ "base_seq": 0, "seq": 1, "sealed": sealed, "vault_seq": v["seq"] }),
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

    // Another member's old app counts too, once they have accepted; an invitee's doesn't.
    session_as(&app, "mg-b@example.com", "pw-manifest-1", None).await;
    assert_eq!(
        share(&app, &alice, &ta, "mg-b@example.com", "read").await.0,
        StatusCode::OK
    );
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(true));
    accept(&app, &tb, vault.0).await;
    assert_eq!(ok_of(&synced(&app, &ta).await), json!(false));
    assert_eq!(ok_of(&synced(&app, &tb).await), json!(false));
    assert_eq!(
        code_of(&start(&app, &ta, vault).await),
        (StatusCode::CONFLICT, "manifest_not_ready")
    );
    expire_sessions_of(&state, None).await;

    // Reading the vault isn't enough to start its manifest.
    assert_eq!(start(&app, &tb, vault).await.0, StatusCode::FORBIDDEN);
    // Nor is someone else's vault there at all.
    let (_carol, tc) = member(&app, "mg-c@example.com").await;
    let (s, _) = call(
        &app,
        Method::PUT,
        &format!("/api/vaults/{}/manifest", vault.0),
        Some(&tc),
        json!({ "base_seq": 0, "seq": 1, "sealed": "AAAA", "vault_seq": 0 }),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    started(&app, &ta, vault).await;
    let sync = checked(&app, &ta, vault).await;
    assert_eq!(manifest_seq(&sync, vault.0), 1);
    assert_eq!(ok_of(&sync), json!(true));
    // The reader sees and checks the same.
    checked(&app, &tb, vault).await;
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
    let app = app().await;
    let (c, t) = member(&app, "ms@example.com").await;
    let vault = (c.vault_id.as_str(), &c.vault_key);
    let (_, body) = new_item(vault, "one");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let sync = synced(&app, &t).await;
    let sealed = manifest::start(vault.1, vault.0, 0, 1, &entries(&sync, vault.0)).unwrap();
    let path = format!("/api/vaults/{}/manifest", vault.0);
    let put = |body: Value| {
        let (app, t, path) = (app.clone(), t.clone(), path.clone());
        async move { call(&app, Method::PUT, &path, Some(&t), body).await }
    };
    let seq = row(&sync, vault.0)["seq"].as_i64().unwrap();
    // A vault that has none takes no manifest with a write: only this request starts one.
    let (_, mut body) = new_item(vault, "early");
    body["manifests"] = json!([{ "vault_id": vault.0, "seq": 1, "sealed": sealed }]);
    assert_eq!(
        code_of(&call(&app, Method::POST, "/api/items", Some(&t), body).await),
        CONFLICT
    );
    // Written since the sync it was computed from.
    let (_, body) = new_item(vault, "two");
    ok(&app, Method::POST, "/api/items", &t, body).await;
    let stale = json!({ "base_seq": 0, "seq": 1, "sealed": sealed, "vault_seq": seq });
    assert_eq!(code_of(&put(stale).await), CONFLICT);
    // Shapes.
    for bad in [
        json!({ "base_seq": 0, "seq": 0, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 1, "seq": 1, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": -1, "seq": 1, "sealed": sealed, "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "sealed": "", "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "sealed": "not base64!", "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 1, "sealed": "A".repeat(1025), "vault_seq": seq + 1 }),
        json!({ "base_seq": 0, "seq": 9_007_199_254_740_992_i64, "sealed": sealed, "vault_seq": seq + 1 }),
    ] {
        assert_eq!(put(bad.clone()).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A base it isn't at.
    let wrong = json!({ "base_seq": 3, "seq": 4, "sealed": sealed, "vault_seq": seq + 1 });
    assert_eq!(code_of(&put(wrong).await), CONFLICT);
    assert_eq!(manifest_seq(&synced(&app, &t).await, vault.0), 0);

    started(&app, &t, vault).await;
    let sync = checked(&app, &t, vault).await;
    // Started once: a second first manifest is a conflict.
    assert_eq!(code_of(&start(&app, &t, vault).await), CONFLICT);

    // A new baseline ("Use the server's copy") may jump ahead of what a device remembers.
    let v = row(&sync, vault.0);
    let sealed = manifest::start(vault.1, vault.0, 0, 9, &entries(&sync, vault.0)).unwrap();
    let answer = ok(
        &app,
        Method::PUT,
        &path,
        &t,
        json!({ "base_seq": 1, "seq": 9, "sealed": sealed, "vault_seq": v["seq"] }),
    )
    .await;
    assert_eq!(answer["manifest_seq"], 9);
    assert_eq!(
        answer["vault_seq"].as_i64().unwrap(),
        v["seq"].as_i64().unwrap() + 1
    );
    let sync = synced(&app, &t).await;
    assert_eq!(verdict(&sync, vault, Some(8)), Status::Ok);
    assert_eq!(verdict(&sync, vault, Some(10)), Status::Rollback);
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
    elsewhere["manifests"] =
        json!([{ "vault_id": uuid::Uuid::new_v4().to_string(), "seq": 3, "sealed": "AAAA" }]);
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
    let half = format!("{path}?manifest_seq=4");
    assert_eq!(
        call(&app, Method::DELETE, &half, Some(&t), json!(null))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
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
    let after = synced(&app, &t).await;
    assert_eq!(after["items"], sync["items"]);
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
    let sealed = |epoch: u64, seq: u64| json!([{ "vault_id": vault.0, "seq": seq, "sealed": manifest::start(&new_key, vault.0, epoch, seq, &fresh).unwrap() }]);
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
    let before = synced(&app, &ta).await;
    assert_eq!(before["items"], sync["items"]);
    assert_eq!(row(&before, vault.0)["key_epoch"], 0);
    let done = ok(&app, Method::POST, &rotate, &ta, body(sealed(1, 4))).await;
    assert_eq!(
        (&done["key_epoch"], &done["manifest_seq"]),
        (&json!(1), &json!(4))
    );
    // Both members check the vault with the new key at the new epoch; the old key
    // no longer opens the manifest.
    for t in [&ta, &tb] {
        let sync = checked(&app, t, rekeyed).await;
        assert_eq!(verdict(&sync, vault, None), Status::Mismatch);
        assert_eq!(row(&sync, vault.0)["key_epoch"], 1);
    }

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
    let m = json!([{ "vault_id": vault.0, "seq": 5, "sealed": manifest::start(&newer, vault.0, 2, 5, &fresh).unwrap() }]);
    let done = ok(&app, Method::POST, &remove, &ta, body(m)).await;
    assert_eq!(
        (&done["key_epoch"], &done["manifest_seq"]),
        (&json!(2), &json!(5))
    );
    checked(&app, &ta, rekeyed).await;
    assert!(vault_in(&synced(&app, &tb).await, vault.0).is_none());
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
    assert_eq!(verdict(&now, vault, Some(1)), Status::Ok);
    assert_eq!(manifest_seq(&now, vault.0), 4);
    let d = delta(&app, &t, &summary["cursor"], "&trash=summary").await;
    let now = merged(&summary, &d);
    assert_eq!(verdict(&now, vault, Some(1)), Status::Ok);
    assert!(item_in(&now, &made[1].0).unwrap().get("data").is_none());
    // The base alone (what the server would have to serve to hide the changes) is
    // what a device that saw version 4 calls a rollback, and the new manifest over
    // the old items a mismatch.
    assert_eq!(verdict(&full, vault, Some(4)), Status::Rollback);
    let mut hidden = full.clone();
    hidden["vaults"] = now["vaults"].clone();
    assert_eq!(verdict(&hidden, vault, Some(1)), Status::Mismatch);
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
