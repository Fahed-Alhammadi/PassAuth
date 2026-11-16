//! Attachments: upload and download, roles, size limits while streaming, quotas,
//! the paths that delete files, moves, the sweeper, the admin switch and backups.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use axum::http::HeaderMap;

use super::*;
use crate::files::file_path;

/// An app whose attachments live in a fresh folder: the app, its state, the folder.
pub(super) async fn files_app() -> (Router, AppState, PathBuf) {
    let mut config = test_config().await;
    let dir = std::env::temp_dir().join(format!(
        "passauth-attachments-{}",
        uuid::Uuid::new_v4().simple()
    ));
    config.attachments_dir = Some(dir.to_str().unwrap().to_owned());
    let state = App::new(config).await.unwrap();
    (crate::router(state.clone()), state, dir)
}

/// A request with a raw body: (status, headers, body).
pub(super) async fn raw(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, String)],
    body: Body,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

/// `PUT /api/attachments/{id}` with `bytes` (and their `Content-Length`).
pub(super) async fn upload(
    app: &Router,
    token: &str,
    id: &str,
    bytes: &[u8],
) -> (StatusCode, Value) {
    let (s, _, b) = raw(
        app,
        Method::PUT,
        &format!("/api/attachments/{id}"),
        Some(token),
        &[
            ("content-length", bytes.len().to_string()),
            ("content-type", "application/octet-stream".into()),
        ],
        Body::from(bytes.to_vec()),
    )
    .await;
    (s, json_of(&b))
}

pub(super) async fn download(
    app: &Router,
    token: &str,
    id: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    raw(
        app,
        Method::GET,
        &format!("/api/attachments/{id}"),
        Some(token),
        &[],
        Body::empty(),
    )
    .await
}

/// `POST /api/items/{item}/attachments` for a new id of `size` bytes.
pub(super) async fn pending(
    app: &Router,
    token: &str,
    item: &str,
    size: usize,
) -> (StatusCode, Value) {
    call(
        app,
        Method::POST,
        &format!("/api/items/{item}/attachments"),
        Some(token),
        json!({ "id": uuid::Uuid::new_v4().to_string(), "size": size }),
    )
    .await
}

/// A ready attachment of `item` holding `bytes`: its id.
pub(super) async fn attach(app: &Router, token: &str, item: &str, bytes: &[u8]) -> String {
    let (s, v) = pending(app, token, item, bytes.len()).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["attachment"]["id"].as_str().unwrap().to_owned();
    let (s, v) = upload(app, token, &id, bytes).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["attachment"]["state"], "ready", "{v}");
    id
}

/// A new item in the vault (id, key): its id.
pub(super) async fn item_in_vault(
    app: &Router,
    token: &str,
    vault: (&str, &SymmetricKey),
) -> String {
    let (id, body) = new_item(vault, "with files");
    ok(app, Method::POST, "/api/items", token, body).await;
    id
}

async fn rows(state: &AppState) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM attachments")
        .fetch_one(&state.db)
        .await
        .unwrap()
}

pub(super) async fn storage(app: &Router, token: &str) -> i64 {
    let (_, me) = call(app, Method::GET, "/api/account", Some(token), json!(null)).await;
    me["usage"]["storage_bytes"].as_i64().unwrap()
}

/// Make a file look `age` old.
fn age_file(path: &Path, age: Duration) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - age)
        .unwrap();
}

#[tokio::test]
async fn attachments_upload_list_download_and_retry_safely() {
    let (app, state, dir) = files_app().await;
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("attachments")),
        "{config}"
    );
    assert_eq!(config["limits"]["max_attachment_mb"], 100);

    let c = register(&app, "files@example.com", "pw-files-123").await;
    let t = token(&app, "files@example.com", "pw-files-123").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;
    let before = synced(&app, &t).await;
    let seq0 = seq_of(&before, &c.vault_id);
    let stored = item_in(&before, &item).unwrap().clone();

    // The app picks the id; any spelling of the UUID, answered in lowercase.
    let id = uuid::Uuid::new_v4().to_string();
    let bytes: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let path = format!("/api/items/{item}/attachments");
    let made = ok(
        &app,
        Method::POST,
        &path,
        &t,
        json!({ "id": id.to_uppercase(), "size": bytes.len() }),
    )
    .await;
    let a = &made["attachment"];
    assert_eq!(
        (
            &a["id"],
            &a["state"],
            &a["size"],
            &a["item_id"],
            &a["vault_id"]
        ),
        (
            &json!(id),
            &json!("pending"),
            &json!(bytes.len()),
            &json!(item),
            &json!(c.vault_id)
        )
    );
    assert_eq!(a["created_by"]["email"], "files@example.com");
    assert_eq!(made["vault_seq"], seq0 + 1);
    assert!(made["revision"].is_i64());
    // Nothing to download before the upload.
    assert_eq!(download(&app, &t, &id).await.0, StatusCode::NOT_FOUND);
    // A retried create gets the same attachment, and nothing is written.
    let again = ok(
        &app,
        Method::POST,
        &path,
        &t,
        json!({ "id": id, "size": bytes.len() }),
    )
    .await;
    assert_eq!(
        (&again["attachment"]["id"], &again["vault_seq"]),
        (&json!(id), &json!(seq0 + 1))
    );
    // The id for another size (or item) is someone else's.
    let (s, v) = call(
        &app,
        Method::POST,
        &path,
        Some(&t),
        json!({ "id": id, "size": 5 }),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("attachment_exists"))
    );
    for (body, status) in [
        (
            json!({ "id": "not-a-uuid", "size": 5 }),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({ "id": uuid::Uuid::new_v4().to_string(), "size": 0 }),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            call(&app, Method::POST, &path, Some(&t), body).await.0,
            status
        );
    }
    let unknown = format!("/api/items/{}/attachments", uuid::Uuid::new_v4());
    let body = json!({ "id": uuid::Uuid::new_v4().to_string(), "size": 5 });
    assert_eq!(
        call(&app, Method::POST, &unknown, Some(&t), body).await.0,
        StatusCode::NOT_FOUND
    );

    // A Content-Length other than the size is refused before reading anything.
    let put = format!("/api/attachments/{id}");
    let long = vec![0u8; bytes.len() + 1];
    let (s, _, b) = raw(
        &app,
        Method::PUT,
        &put,
        Some(&t),
        &[("content-length", long.len().to_string())],
        Body::from(long),
    )
    .await;
    assert_eq!(
        (s, json_of(&b)["error"].clone()),
        (StatusCode::PAYLOAD_TOO_LARGE, json!("too_large"))
    );

    let (s, up) = upload(&app, &t, &id.to_uppercase(), &bytes).await;
    assert_eq!(s, StatusCode::OK, "{up}");
    assert_eq!(up["attachment"]["state"], "ready");
    assert_eq!(up["vault_seq"], seq0 + 2);
    // Uploaded once: a retry is told so, and a retried create sees it ready.
    let (s, v) = upload(&app, &t, &id, &bytes).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("already_uploaded"))
    );
    let again = ok(
        &app,
        Method::POST,
        &path,
        &t,
        json!({ "id": id, "size": bytes.len() }),
    )
    .await;
    assert_eq!(
        (&again["attachment"]["state"], &again["vault_seq"]),
        (&json!("ready"), &json!(seq0 + 2))
    );

    // The file: exactly what was sent, saved as a file, never cached or run.
    let (s, h, got) = download(&app, &t, &id).await;
    assert_eq!(s, StatusCode::OK);
    assert!(got == bytes, "the same bytes come back");
    assert_eq!(h["content-type"], "application/octet-stream");
    assert_eq!(h["content-length"], bytes.len().to_string().as_str());
    assert_eq!(h["content-disposition"], "attachment");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["content-security-policy"], "default-src 'none'; sandbox");
    // On disk as sent, for the server's user only.
    let file = file_path(&dir, &id);
    assert!(std::fs::read(&file).unwrap() == bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
        assert_eq!(mode(&dir.join("tmp")), 0o700);
    }
    assert!(
        std::fs::read_dir(dir.join("tmp")).unwrap().next().is_none(),
        "no temp file left"
    );
    let list = ok(&app, Method::GET, &path, &t, json!(null)).await;
    let list = list["attachments"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (&list[0]["id"], &list[0]["state"]),
        (&json!(id), &json!("ready"))
    );

    // Other devices notice: the item comes back in a delta, unchanged.
    let changed = delta(&app, &t, &before["cursor"], "").await;
    let row = item_in(&changed, &item).expect("the item is in the delta");
    assert_eq!(
        (&row["revision"], &row["data"], &row["item_key"]),
        (&stored["revision"], &stored["data"], &stored["item_key"])
    );
    // Logged by id and size only.
    let events = stored_events(&state).await;
    let added = of_type(&events, "attachment.added");
    assert_eq!(added.len(), 1);
    assert_eq!(
        added[0]["data"],
        json!({ "attachment": id, "size": bytes.len() })
    );
    assert_eq!(
        (&added[0]["item_id"], &added[0]["vault_id"]),
        (&json!(item), &json!(c.vault_id))
    );

    // A chunked upload (no Content-Length) works as well.
    let (s, v) = pending(&app, &t, &item, 9).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let chunked = v["attachment"]["id"].as_str().unwrap().to_owned();
    let parts = futures_util::stream::iter(
        ["abc", "def", "ghi"].map(|p| Ok::<_, std::io::Error>(axum::body::Bytes::from(p))),
    );
    let (s, _, b) = raw(
        &app,
        Method::PUT,
        &format!("/api/attachments/{chunked}"),
        Some(&t),
        &[],
        Body::from_stream(parts),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", json_of(&b));
    assert_eq!(download(&app, &t, &chunked).await.2, b"abcdefghi");

    // Deleting: gone from the disk, the list and the downloads; logged.
    let gone = ok(&app, Method::DELETE, &put, &t, json!(null)).await;
    assert!(gone["vault_seq"].as_i64().unwrap() > seq0 + 2);
    assert!(!file.exists());
    assert_eq!(download(&app, &t, &id).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        call(&app, Method::DELETE, &put, Some(&t), json!(null))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let deleted = stored_events(&state).await;
    let deleted = of_type(&deleted, "attachment.deleted");
    assert_eq!(deleted.len(), 1);
    assert_eq!(
        deleted[0]["data"],
        json!({ "attachment": id, "size": bytes.len() })
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn attachments_follow_the_vault_roles() {
    let (app, _state, dir) = files_app().await;
    let alice = register(&app, "fa@example.com", "pw-alice-123").await;
    for email in [
        "fb@example.com",
        "fc@example.com",
        "fd@example.com",
        "fe@example.com",
    ] {
        register(&app, email, "pw-other-123").await;
    }
    let ta = token(&app, "fa@example.com", "pw-alice-123").await;
    let tb = token(&app, "fb@example.com", "pw-other-123").await;
    let tc = token(&app, "fc@example.com", "pw-other-123").await;
    let td = token(&app, "fd@example.com", "pw-other-123").await;
    let te = token(&app, "fe@example.com", "pw-other-123").await;
    // Bob reads Alice's vault, Carol writes in it, Dave is only invited, Erin is a stranger.
    for (email, role, t) in [
        ("fb@example.com", "read", &tb),
        ("fc@example.com", "write", &tc),
    ] {
        assert_eq!(
            share(&app, &alice, &ta, email, role).await.0,
            StatusCode::OK
        );
        accept(&app, t, &alice.vault_id).await;
    }
    assert_eq!(
        share(&app, &alice, &ta, "fd@example.com", "read").await.0,
        StatusCode::OK
    );
    let item = item_in_vault(&app, &ta, (&alice.vault_id, &alice.vault_key)).await;
    let id = attach(&app, &ta, &item, b"secret bytes").await;
    let list = format!("/api/items/{item}/attachments");

    // Readers download and list, but don't add, upload or delete.
    assert_eq!(download(&app, &tb, &id).await.2, b"secret bytes");
    assert_eq!(
        ok(&app, Method::GET, &list, &tb, json!(null)).await["attachments"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(pending(&app, &tb, &item, 5).await.0, StatusCode::FORBIDDEN);
    let (s, v) = pending(&app, &tc, &item, 5).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let carols = v["attachment"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        upload(&app, &tb, &carols, b"12345").await.0,
        StatusCode::FORBIDDEN
    );
    let path = format!("/api/attachments/{id}");
    assert_eq!(
        call(&app, Method::DELETE, &path, Some(&tb), json!(null))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Writers do.
    assert_eq!(upload(&app, &tc, &carols, b"12345").await.0, StatusCode::OK);
    assert_eq!(download(&app, &ta, &carols).await.2, b"12345");
    ok(
        &app,
        Method::DELETE,
        &format!("/api/attachments/{carols}"),
        &tc,
        json!(null),
    )
    .await;
    // An invitation not accepted yet, or no membership at all: nothing is there.
    let (s, v) = pending(&app, &ta, &item, 5).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let open = v["attachment"]["id"].as_str().unwrap().to_owned();
    for t in [&td, &te] {
        assert_eq!(download(&app, t, &id).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            call(&app, Method::GET, &list, Some(t), json!(null)).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(pending(&app, t, &item, 5).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            upload(&app, t, &open, b"12345").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&app, Method::DELETE, &path, Some(t), json!(null))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        call(&app, Method::GET, &path, None, json!(null)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn attachment_sizes_are_checked_before_and_while_uploading() {
    let (app, _state, dir) = files_app().await;
    let c = register(&app, "big@example.com", "pw-big-12345").await;
    let t = token(&app, "big@example.com", "pw-big-12345").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;

    // An attachment made while the limit was higher: once it is lowered, its upload
    // is refused too.
    assert_eq!(
        admin_set(&app, json!({ "max_attachment_mb": 2 })).await.0,
        StatusCode::OK
    );
    let (s, v) = pending(&app, &t, &item, 1536 * 1024).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let made_before = v["attachment"]["id"].as_str().unwrap().to_owned();

    // The admin's limit (1–4096 MB) applies to the size declared up front.
    for (mb, status) in [
        (0, StatusCode::BAD_REQUEST),
        (4097, StatusCode::BAD_REQUEST),
        (1, StatusCode::OK),
    ] {
        assert_eq!(
            admin_set(&app, json!({ "max_attachment_mb": mb })).await.0,
            status,
            "{mb}"
        );
    }
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert_eq!(config["limits"]["max_attachment_mb"], 1);
    let (s, v) = pending(&app, &t, &item, 1024 * 1024 + 1).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large"))
    );
    assert_eq!(
        pending(&app, &t, &item, 1024 * 1024).await.0,
        StatusCode::OK
    );
    let (s, v) = upload(&app, &t, &made_before, &vec![1u8; 1536 * 1024]).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, Some("too_large"))
    );

    // More than the size, while streaming: refused without reading on (an endless body).
    let (s, v) = pending(&app, &t, &item, 1000).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["attachment"]["id"].as_str().unwrap().to_owned();
    let put = format!("/api/attachments/{id}");
    let endless = futures_util::stream::repeat_with(|| {
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(&[7u8; 4096]))
    });
    let (s, _, b) = raw(
        &app,
        Method::PUT,
        &put,
        Some(&t),
        &[],
        Body::from_stream(endless),
    )
    .await;
    assert_eq!(
        (s, json_of(&b)["error"].clone()),
        (StatusCode::PAYLOAD_TOO_LARGE, json!("too_large"))
    );
    // Short of it: 400. Either way the attachment stays pending and nothing is left.
    let (s, _, b) = raw(
        &app,
        Method::PUT,
        &put,
        Some(&t),
        &[],
        Body::from(vec![1u8; 999]),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{}", json_of(&b));
    let (s, _, _) = raw(
        &app,
        Method::PUT,
        &put,
        Some(&t),
        &[("content-length", "999".into())],
        Body::from(vec![1u8; 999]),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(download(&app, &t, &id).await.0, StatusCode::NOT_FOUND);
    assert!(std::fs::read_dir(dir.join("tmp")).unwrap().next().is_none());
    assert!(!file_path(&dir, &id).exists());
    // The right size goes through.
    let (s, v) = upload(&app, &t, &id, &[9u8; 1000]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn attachments_count_toward_the_owners_storage() {
    let (app, state, dir) = files_app().await;
    let alice = register(&app, "qa@example.com", "pw-alice-123").await;
    let bob = register(&app, "qb@example.com", "pw-bobby-123").await;
    let ta = token(&app, "qa@example.com", "pw-alice-123").await;
    let tb = token(&app, "qb@example.com", "pw-bobby-123").await;
    assert_eq!(
        admin_set(&app, json!({ "max_storage_mb_per_user": 1 }))
            .await
            .0,
        StatusCode::OK
    );
    let item = item_in_vault(&app, &ta, (&alice.vault_id, &alice.vault_key)).await;
    let base = storage(&app, &ta).await;
    let kib600 = 600 * 1024;

    // Refused up front when the declared size doesn't fit; a pending upload counts at once.
    let (s, v) = pending(&app, &ta, &item, 2 * 1024 * 1024).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("quota_exceeded"))
    );
    let (s, v) = pending(&app, &ta, &item, kib600).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let first = v["attachment"]["id"].as_str().unwrap().to_owned();
    assert_eq!(storage(&app, &ta).await, base + kib600 as i64);
    let (s, v) = pending(&app, &ta, &item, kib600).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("quota_exceeded"))
    );
    let (_, users) = call(
        &app,
        Method::GET,
        "/api/admin/users",
        Some("test-admin"),
        json!(null),
    )
    .await;
    let me = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "qa@example.com")
        .unwrap()
        .clone();
    assert_eq!(me["storage_bytes"], base + kib600 as i64);
    // Uploading it changes nothing; deleting it frees the space.
    assert_eq!(
        upload(&app, &ta, &first, &vec![3u8; kib600]).await.0,
        StatusCode::OK
    );
    assert_eq!(storage(&app, &ta).await, base + kib600 as i64);
    ok(
        &app,
        Method::DELETE,
        &format!("/api/attachments/{first}"),
        &ta,
        json!(null),
    )
    .await;
    assert_eq!(storage(&app, &ta).await, base);
    let moving = attach(&app, &ta, &item, &vec![4u8; kib600]).await;

    // A move charges the new vault's owner for the item's attachments.
    assert_eq!(
        share(&app, &bob, &tb, "qa@example.com", "write").await.0,
        StatusCode::OK
    );
    accept(&app, &ta, &bob.vault_id).await;
    let bobs_item = item_in_vault(&app, &tb, (&bob.vault_id, &bob.vault_key)).await;
    let bobs = attach(&app, &tb, &bobs_item, &vec![5u8; kib600]).await;
    let to_bob = item_body(&item, (&bob.vault_id, &bob.vault_key), "moved");
    let (s, v) = call(
        &app,
        Method::PUT,
        &format!("/api/items/{item}"),
        Some(&ta),
        to_bob.clone(),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("quota_exceeded"))
    );
    ok(
        &app,
        Method::DELETE,
        &format!("/api/attachments/{bobs}"),
        &tb,
        json!(null),
    )
    .await;
    let bob_before = storage(&app, &tb).await;
    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{item}"),
        &ta,
        to_bob,
    )
    .await;
    assert!(storage(&app, &tb).await >= bob_before + kib600 as i64);
    assert!(
        storage(&app, &ta).await < base,
        "the item and its file left Alice's storage"
    );
    let vault: String = sqlx::query_scalar("SELECT vault_id FROM attachments WHERE id = $1")
        .bind(&moving)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(vault, bob.vault_id);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn attachment_files_go_with_their_item_vault_and_account() {
    let (app, state, dir) = files_app().await;
    let c = register(&app, "gone@example.com", "pw-gone-1234").await;
    let t = token(&app, "gone@example.com", "pw-gone-1234").await;
    let mine = (c.vault_id.as_str(), &c.vault_key);

    // The trash keeps them; deleting the item for good doesn't.
    let item = item_in_vault(&app, &t, mine).await;
    let a = attach(&app, &t, &item, b"in the trash").await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{item}"),
        &t,
        json!(null),
    )
    .await;
    assert_eq!(download(&app, &t, &a).await.2, b"in the trash");
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{item}/permanent"),
        &t,
        json!(null),
    )
    .await;
    assert!(!file_path(&dir, &a).exists());
    assert_eq!(rows(&state).await, 0);

    // The trash sweeper.
    let item = item_in_vault(&app, &t, mine).await;
    let b = attach(&app, &t, &item, b"swept").await;
    let kept_item = item_in_vault(&app, &t, mine).await;
    let kept = attach(&app, &t, &kept_item, b"kept").await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/items/{item}"),
        &t,
        json!(null),
    )
    .await;
    sqlx::query("UPDATE items SET deleted_at = $1 WHERE id = $2")
        .bind(crate::db::now() - 3 * 86_400)
        .bind(&item)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(
        admin_set(&app, json!({ "trash_days": 1 })).await.0,
        StatusCode::OK
    );
    assert_eq!(crate::vault::purge_trash(&state).await.unwrap(), 1);
    assert!(!file_path(&dir, &b).exists());
    assert!(file_path(&dir, &kept).exists());
    assert_eq!(rows(&state).await, 1);

    // Deleting a vault.
    let (second, key) = new_vault(&app, &c, &t).await;
    let item = item_in_vault(&app, &t, (&second, &key)).await;
    let d = attach(&app, &t, &item, b"in a vault").await;
    ok(
        &app,
        Method::DELETE,
        &format!("/api/vaults/{second}"),
        &t,
        json!(null),
    )
    .await;
    assert!(!file_path(&dir, &d).exists());
    assert_eq!(rows(&state).await, 1);

    // Deleting the account: its own vaults, so their files, go with it.
    let reauth = reauth_token(&app, "gone@example.com", "pw-gone-1234", &t).await;
    let (s, v) = call_with(
        &app,
        Method::DELETE,
        "/api/account",
        Some(&t),
        &[("x-reauth-token", &reauth)],
        json!(null),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!file_path(&dir, &kept).exists());
    assert_eq!(rows(&state).await, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn moving_an_item_takes_its_attachments_along() {
    let (app, _state, dir) = files_app().await;
    let alice = register(&app, "ma@example.com", "pw-alice-123").await;
    register(&app, "mb@example.com", "pw-bobby-123").await;
    let ta = token(&app, "ma@example.com", "pw-alice-123").await;
    let tb = token(&app, "mb@example.com", "pw-bobby-123").await;
    assert_eq!(
        share(&app, &alice, &ta, "mb@example.com", "read").await.0,
        StatusCode::OK
    );
    accept(&app, &tb, &alice.vault_id).await;
    let (private, key) = new_vault(&app, &alice, &ta).await;
    let item = item_in_vault(&app, &ta, (&alice.vault_id, &alice.vault_key)).await;
    let id = attach(&app, &ta, &item, b"travels along").await;
    assert_eq!(download(&app, &tb, &id).await.0, StatusCode::OK);
    let stamp = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.len(), m.modified().unwrap())
    };
    let before = stamp(&file_path(&dir, &id));

    ok(
        &app,
        Method::PUT,
        &format!("/api/items/{item}"),
        &ta,
        item_body(&item, (&private, &key), "moved"),
    )
    .await;
    let list = ok(
        &app,
        Method::GET,
        &format!("/api/items/{item}/attachments"),
        &ta,
        json!(null),
    )
    .await;
    assert_eq!(list["attachments"][0]["vault_id"], private);
    // The file stays as it was; who may read it follows the item.
    assert_eq!(stamp(&file_path(&dir, &id)), before);
    assert_eq!(download(&app, &ta, &id).await.2, b"travels along");
    assert_eq!(download(&app, &tb, &id).await.0, StatusCode::NOT_FOUND);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_sweeper_deletes_abandoned_uploads_and_files_without_an_attachment() {
    let (app, state, dir) = files_app().await;
    let c = register(&app, "sweep@example.com", "pw-sweep-123").await;
    let t = token(&app, "sweep@example.com", "pw-sweep-123").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;
    let ready = attach(&app, &t, &item, b"keep me").await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let (s, v) = pending(&app, &t, &item, 10).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        ids.push(v["attachment"]["id"].as_str().unwrap().to_owned());
    }
    let [stale, fresh, busy] = <[String; 3]>::try_from(ids).unwrap();
    let old = crate::db::now() - crate::vault::ATTACHMENT_PENDING_TTL - 60;
    for id in [&stale, &busy] {
        sqlx::query("UPDATE attachments SET updated_at = $1 WHERE id = $2")
            .bind(old)
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap();
    }
    let write = |path: PathBuf, age: Duration| {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"leftover").unwrap();
        age_file(&path, age);
        path
    };
    // A crash after the rename left the stale upload's file.
    let stale_file = write(file_path(&dir, &stale), Duration::ZERO);
    // A file without a row (a crash, or a database restored from an older backup),
    // an abandoned temp file, and the temp file of an upload that is running.
    let orphan = write(
        file_path(&dir, &uuid::Uuid::new_v4().to_string()),
        Duration::ZERO,
    );
    let old_temp = write(
        dir.join("tmp").join(format!("{}.x", uuid::Uuid::new_v4())),
        Duration::from_secs(7200),
    );
    let busy_temp = write(
        dir.join("tmp").join(format!("{busy}.x")),
        Duration::from_secs(7200),
    );
    let store = state.files.as_ref().unwrap();
    let running = store.begin_upload(&busy, "someone", 10, None).unwrap();

    let swept = crate::vault::sweep_attachments(&state, false)
        .await
        .unwrap();
    assert_eq!((swept.pending, swept.orphans), (1, 0));
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM attachments ORDER BY id")
        .fetch_all(&state.db)
        .await
        .unwrap();
    assert_eq!(
        sorted(left),
        sorted(vec![ready.clone(), fresh, busy.clone()])
    );
    assert!(!stale_file.exists());
    assert!(
        orphan.exists(),
        "files are checked only on the hourly round"
    );

    let swept = crate::vault::sweep_attachments(&state, true).await.unwrap();
    assert_eq!((swept.pending, swept.orphans), (0, 1));
    assert!(!orphan.exists() && !old_temp.exists());
    assert!(busy_temp.exists(), "a running upload's temp file stays");
    assert!(file_path(&dir, &ready).exists());
    // Once that upload stops, its old pending row goes too.
    drop(running);
    assert_eq!(
        crate::vault::sweep_attachments(&state, true)
            .await
            .unwrap()
            .pending,
        1
    );
    assert!(!busy_temp.exists());
    assert_eq!(download(&app, &t, &ready).await.2, b"keep me");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn attachments_can_be_turned_off_and_need_a_folder() {
    // Without a folder for them they aren't offered.
    let app = app().await;
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        !config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("attachments"))
    );
    let c = register(&app, "nofolder@example.com", "pw-nofolder-1").await;
    let t = token(&app, "nofolder@example.com", "pw-nofolder-1").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;
    let (s, v) = pending(&app, &t, &item, 5).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("attachments_disabled"))
    );

    // The admin's switch: no new files; the stored ones stay readable and deletable.
    let (app, _state, dir) = files_app().await;
    let c = register(&app, "off@example.com", "pw-off-12345").await;
    let t = token(&app, "off@example.com", "pw-off-12345").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;
    let kept = attach(&app, &t, &item, b"still here").await;
    let (_, v) = pending(&app, &t, &item, 5).await;
    let waiting = v["attachment"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        admin_set(&app, json!({ "attachments": false })).await.0,
        StatusCode::OK
    );
    let (_, config) = call(&app, Method::GET, "/api/config", None, json!(null)).await;
    assert!(
        !config["features"]
            .as_array()
            .unwrap()
            .contains(&json!("attachments"))
    );
    let (s, v) = pending(&app, &t, &item, 5).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("attachments_disabled"))
    );
    let (s, v) = upload(&app, &t, &waiting, b"12345").await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("attachments_disabled"))
    );
    assert_eq!(download(&app, &t, &kept).await.2, b"still here");
    ok(
        &app,
        Method::DELETE,
        &format!("/api/attachments/{kept}"),
        &t,
        json!(null),
    )
    .await;
    assert!(!file_path(&dir, &kept).exists());
    assert_eq!(
        admin_set(&app, json!({ "attachments": true })).await.0,
        StatusCode::OK
    );
    assert_eq!(upload(&app, &t, &waiting, b"12345").await.0, StatusCode::OK);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn backups_carry_the_files_of_ready_attachments() {
    if std::env::var("PASSAUTH_TEST_DATABASE_URL").is_ok() {
        return; // PostgreSQL is backed up with pg_dump.
    }
    let mut config = test_config().await;
    let dir = on_disk(&mut config);
    let files = dir.join("attachments");
    config.attachments_dir = Some(files.to_str().unwrap().to_owned());
    let url = config.database_url.clone();
    let app = crate::router(App::new(config).await.unwrap());
    let c = register(&app, "bk@example.com", "pw-backup-123").await;
    let t = token(&app, "bk@example.com", "pw-backup-123").await;
    let item = item_in_vault(&app, &t, (&c.vault_id, &c.vault_key)).await;
    let first = attach(&app, &t, &item, b"first file").await;
    let second = attach(&app, &t, &item, b"second file").await;
    assert_eq!(pending(&app, &t, &item, 5).await.0, StatusCode::OK);
    // A file deleted while the backup is made (after its copy of the database).
    std::fs::remove_file(file_path(&files, &second)).unwrap();

    let target = dir.join("backup.db");
    let done = crate::db::backup(&url, Some(&files), &target)
        .await
        .unwrap();
    let copy = done.attachments.expect("a folder of attachment files");
    assert_eq!(copy.dir, dir.join("backup.db.attachments"));
    assert_eq!((copy.files, copy.missing), (1, 1));
    assert_eq!(
        std::fs::read(file_path(&copy.dir, &first)).unwrap(),
        b"first file"
    );
    assert!(!file_path(&copy.dir, &second).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&copy.dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
    // The copy names exactly the files beside it: no pending upload, no missing file.
    let db = crate::db::connect(&format!("sqlite://{}", target.display()), 1)
        .await
        .unwrap();
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM attachments")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(ids, std::slice::from_ref(&first));
    db.close().await;
    // The live server is untouched.
    assert_eq!(download(&app, &t, &first).await.2, b"first file");
    // A folder that exists already is never written into; nothing is left behind.
    let again = dir.join("again.db");
    std::fs::create_dir(dir.join("again.db.attachments")).unwrap();
    let err = crate::db::backup(&url, Some(&files), &again)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("must not exist"), "{err:#}");
    assert!(!again.exists());
    let _ = std::fs::remove_dir_all(&dir);
}
