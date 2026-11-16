//! Attachment files between the webview and the server, on the same single network path as `api_fetch`: the connected
//! server only (origin pinned, no redirects), only the requests attachments need (`PUT /attachments/{id}`,
//! `GET /attachments/{id}`, `GET /emergency-access/{grant}/attachments/{id}`), only the webview's session and app-name
//! headers, and only `RESPONSE_HEADERS` back. The bytes are ciphertext: the webview encrypts and decrypts with the core
//! (`FileEncryptor` / `FileDecryptor`), as in the browser.
//!
//! Bytes cross the IPC raw (no JSON, no base64). An upload is handed over piece by piece (`upload_chunk`: a raw request
//! body of about 1 MiB) into a one-piece queue that the request body reads, so the webview never runs more than a piece
//! or two ahead of the network; its progress comes back through a `Channel`. A download is read the same way
//! (`download_read`: a raw response of up to about 1 MiB from a bounded queue the response is read into). Saving a
//! decrypted file: the native save dialog (suggesting a cleaned name), then pieces into a temporary file next to the
//! chosen one, marked as downloaded from the internet and renamed when whole. The webview names no file path and gets
//! no filesystem access.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body::{Frame, SizeHint};
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use serde::Serialize;
use tauri::async_runtime::JoinHandle;
use tauri::ipc::{Channel, InvokeBody, Request, Response};
use tauri::{AppHandle, State, Url};
use tauri_plugin_dialog::DialogExt;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio::time::{Sleep, timeout};

use crate::{
    API_TIMEOUT, ApiResponse, Server, api_url, blocking, describe, files, kept_headers,
    request_headers,
};

/// Largest file a transfer carries: the server's own ceiling for `max_attachment_mb` (4096 MB, encrypted size).
const MAX_TRANSFER_BYTES: u64 = 4096 * 1024 * 1024;
/// Largest piece the webview may hand over in one call (it sends 1 MiB).
const MAX_PIECE_BYTES: usize = 16 * 1024 * 1024;
/// About the most bytes one `download_read` returns (at least one piece, then what else has arrived up to this).
const READ_BATCH: usize = 1024 * 1024;
/// Pieces of a download the server sent and the webview hasn't read yet (hyper's are 8 to 400 KiB).
const DOWNLOAD_QUEUE: usize = 32;
/// Upload progress is reported at most every this many bytes (and at the end).
const PROGRESS_STEP: u64 = 256 * 1024;
/// No byte moving (to the server, from it, or from the webview) for this long ends a transfer. The server drops an
/// upload that stalls for a minute too.
const STALL: Duration = Duration::from_secs(60);
/// From the last byte of an upload to the server's answer (it stores the file before it answers).
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);
/// How often waits check whether the request ended or stalled meanwhile.
const TICK: Duration = Duration::from_secs(1);
/// An answer's text is read up to this size (the server's are small JSON).
const ANSWER_TEXT_MAX: usize = 1024 * 1024;
/// The IPC header naming the transfer a raw piece belongs to (the request body is the piece itself).
const TRANSFER_HEADER: &str = "passauth-transfer";
/// Bytes of the saved file's name that its temporary file repeats (whatever the user typed in the dialog, the
/// temporary name stays well below the 255 bytes file systems allow).
const TEMP_NAME_MAX: usize = 100;
/// Request headers the webview may set on a transfer: the session and the app's name (`X-PassAuth-Client`). Host,
/// length, encoding, cookies and the rest are the native client's business.
const REQUEST_HEADERS: [&str; 2] = ["authorization", "x-passauth-client"];
const CANCELLED: &str = "cancelled";

fn too_slow(host: &str) -> String {
    format!("{host} took too long to answer. Check your connection, then try again.")
}

fn too_large() -> String {
    "This file is larger than 4 GB, more than PassAuth can transfer.".into()
}

/// What the user can act on: a connection that broke off mid-file, else `describe`'s wording.
fn describe_transfer(error: &reqwest::Error, host: &str) -> String {
    if !error.is_timeout() && (error.is_body() || error.is_decode()) {
        return format!(
            "The connection to {host} broke off. Check your connection, then try again."
        );
    }
    describe(error, host)
}

// ------------------------------------------------------------------ checks

/// Which way a transfer goes: an upload may only `PUT` an attachment's file, a download may also read one through
/// emergency access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Upload,
    Download,
}

/// An id in a path: what the server's ids (UUIDs) look like, nothing that could change the path's meaning (`/`, `.`,
/// `%`, `?`, `#`).
fn is_id(segment: &str) -> bool {
    (1..=64).contains(&segment.len())
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `/attachments/{id}`, or (downloads) `/emergency-access/{grant}/attachments/{id}`.
fn check_path(path: &str, route: Route) -> Result<(), String> {
    let segments: Vec<&str> = path
        .strip_prefix('/')
        .ok_or("invalid path")?
        .split('/')
        .collect();
    let ok = match (route, segments.as_slice()) {
        (_, ["attachments", id]) => is_id(id),
        (Route::Download, ["emergency-access", grant, "attachments", id]) => {
            is_id(grant) && is_id(id)
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err("invalid path".into())
    }
}

/// The URL for `path` on the connected server (`api_url`: its origin, under `/api/`), and the server's host (for
/// messages).
fn connected(server: &Server, path: &str) -> Result<(Url, String), String> {
    let base = server.base.lock().unwrap().clone().ok_or("no server")?;
    let host = base.host_str().unwrap_or_default().to_string();
    Ok((api_url(&base, path)?, host))
}

/// An upload's announced size: at least a byte (as the server requires), at most `MAX_TRANSFER_BYTES`.
fn check_size(size: u64) -> Result<(), String> {
    match size {
        0 => Err("invalid size".into()),
        n if n > MAX_TRANSFER_BYTES => Err(too_large()),
        _ => Ok(()),
    }
}

/// `done` plus `more` bytes, when that stays within `limit`.
fn within(done: u64, more: usize, limit: u64) -> Option<u64> {
    done.checked_add(u64::try_from(more).ok()?)
        .filter(|total| *total <= limit)
}

/// The transfer a raw piece belongs to (`TRANSFER_HEADER`).
fn transfer_id(request: &Request<'_>) -> Result<u64, String> {
    request
        .headers()
        .get(TRANSFER_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "missing transfer id".into())
}

/// A piece's bytes: the raw request body, or a JSON array of numbers when the IPC fell back to `postMessage`.
fn piece(body: &InvokeBody) -> Result<Vec<u8>, String> {
    let bytes = match body {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(serde_json::Value::Array(values)) => values
            .iter()
            .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Option<Vec<u8>>>()
            .ok_or("invalid piece")?,
        InvokeBody::Json(_) => return Err("invalid piece".into()),
    };
    if bytes.is_empty() || bytes.len() > MAX_PIECE_BYTES {
        return Err("invalid piece".into());
    }
    Ok(bytes)
}

/// The status, kept headers and text (up to `ANSWER_TEXT_MAX`) of an answer, its text read within `deadline` in all
/// (`API_TIMEOUT` in the commands), so a server sending a byte now and then can't keep the call waiting.
async fn answer_of(
    mut response: reqwest::Response,
    host: &str,
    deadline: Duration,
) -> Result<ApiResponse, String> {
    let status = response.status().as_u16();
    let headers = kept_headers(response.headers());
    let read = async {
        let mut text = Vec::new();
        while text.len() < ANSWER_TEXT_MAX {
            let Some(chunk) = response.chunk().await? else {
                break;
            };
            let room = ANSWER_TEXT_MAX - text.len();
            text.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        Ok::<_, reqwest::Error>(text)
    };
    let text = timeout(deadline, read)
        .await
        .map_err(|_| too_slow(host))?
        .map_err(|e| describe_transfer(&e, host))?;
    Ok(ApiResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&text).into_owned(),
    })
}

// ------------------------------------------------------------------ state

/// Transfers in progress, by id (one sequence for uploads, downloads and saves).
pub struct Transfers {
    /// Like `Server::client` (no redirects, same TLS and proxy) but without the 30 s total timeout, which a large file
    /// would outlast: transfers time out when nothing moves instead (`STALL`, `ANSWER_TIMEOUT`, `API_TIMEOUT` to answer).
    client: reqwest::Client,
    next: AtomicU64,
    uploads: Mutex<HashMap<u64, Upload>>,
    downloads: Mutex<HashMap<u64, DownloadEntry>>,
    saves: Mutex<HashMap<u64, Arc<Mutex<Save>>>>,
}

impl Transfers {
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            next: AtomicU64::new(1),
            uploads: Mutex::default(),
            downloads: Mutex::default(),
            saves: Mutex::default(),
        }
    }

    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Stop transfer `id` (any kind) and drop what it holds: the connection, queued bytes, a partly written file.
    fn cancel(&self, id: u64) {
        let upload = self.uploads.lock().unwrap().remove(&id);
        if let Some(upload) = upload {
            upload.abort.abort();
        }
        let download = self.downloads.lock().unwrap().remove(&id);
        if let Some(download) = download {
            download.abort.abort();
        }
        let save = self.saves.lock().unwrap().remove(&id);
        if let Some(save) = save {
            discard(save);
        }
    }

    /// Stop every transfer: they belong to the connection (and the page) they started with.
    pub fn clear(&self) {
        let uploads = std::mem::take(&mut *self.uploads.lock().unwrap());
        uploads.values().for_each(|u| u.abort.abort());
        let downloads = std::mem::take(&mut *self.downloads.lock().unwrap());
        downloads.values().for_each(|d| d.abort.abort());
        let saves = std::mem::take(&mut *self.saves.lock().unwrap());
        saves.into_values().for_each(discard);
    }
}

#[tauri::command]
pub async fn transfer_cancel(transfers: State<'_, Transfers>, id: u64) -> Result<(), String> {
    transfers.cancel(id);
    Ok(())
}

// ------------------------------------------------------------------ upload

/// When an upload's body last moved, to tell a slow transfer from a stalled one.
struct Activity {
    start: Instant,
    /// Milliseconds after `start`.
    last: AtomicU64,
    /// The body has ended: the connection has every byte, the server's answer is next.
    done: AtomicBool,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
            done: AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(now, Ordering::Relaxed);
    }

    fn finish(&self) {
        self.done.store(true, Ordering::Relaxed);
        self.touch();
    }

    /// How long a wait for the answer may go on now: until the body stalls, or until the answer is late.
    fn overdue(&self) -> bool {
        let idle = self
            .start
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last.load(Ordering::Relaxed)));
        let limit = if self.done.load(Ordering::Relaxed) {
            ANSWER_TIMEOUT
        } else {
            STALL
        };
        idle >= limit
    }
}

/// The request body of an upload: the pieces the webview hands over, in order, `size` bytes in all (the length is sent
/// as `Content-Length`; hyper refuses a body that ends short or runs over).
struct UploadBody {
    queue: mpsc::Receiver<Vec<u8>>,
    size: u64,
    sent: u64,
    reported: u64,
    progress: Channel<u64>,
    activity: Arc<Activity>,
    /// The webview hasn't handed over the next piece for `STALL`: it has gone (a reload), end the request.
    idle: Pin<Box<Sleep>>,
}

impl UploadBody {
    fn new(
        queue: mpsc::Receiver<Vec<u8>>,
        size: u64,
        progress: Channel<u64>,
        activity: Arc<Activity>,
    ) -> Self {
        Self {
            queue,
            size,
            sent: 0,
            reported: 0,
            progress,
            activity,
            idle: Box::pin(tokio::time::sleep(STALL)),
        }
    }

    /// Tell the webview how much went out: what the connection took before it asked for the next piece.
    fn report(&mut self, end: bool) {
        if end || self.sent - self.reported >= PROGRESS_STEP {
            self.reported = self.sent;
            let _ = self.progress.send(self.sent);
        }
    }
}

impl http_body::Body for UploadBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        match this.queue.poll_recv(cx) {
            Poll::Ready(Some(piece)) => {
                this.report(false);
                this.sent += piece.len() as u64;
                this.activity.touch();
                this.idle
                    .as_mut()
                    .reset(tokio::time::Instant::now() + STALL);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(piece)))))
            }
            Poll::Ready(None) => {
                this.report(true);
                this.activity.finish();
                Poll::Ready(None)
            }
            Poll::Pending => match this.idle.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the app stopped handing over the file",
                )))),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.size - self.sent)
    }
}

struct Upload {
    /// Dropped by `upload_finish`: the end of the body.
    pieces: Option<mpsc::Sender<Vec<u8>>>,
    /// The request: the server's answer, or why there is none.
    answer: Option<JoinHandle<Result<ApiResponse, String>>>,
    abort: AbortHandle,
    size: u64,
    /// Bytes handed over so far.
    accepted: u64,
    activity: Arc<Activity>,
    host: String,
}

/// Start `PUT /api{path}` with a body of exactly `size` bytes, handed over with `upload_chunk`. `on_progress` hears how
/// many bytes went out. Resolves with the transfer's id.
#[tauri::command]
pub async fn upload_start(
    server: State<'_, Server>,
    transfers: State<'_, Transfers>,
    path: String,
    headers: HashMap<String, String>,
    size: u64,
    on_progress: Channel<u64>,
) -> Result<u64, String> {
    check_path(&path, Route::Upload)?;
    check_size(size)?;
    let (url, host) = connected(&server, &path)?;
    let mut headers = request_headers(&headers, &REQUEST_HEADERS)?;
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(CONTENT_LENGTH, HeaderValue::from(size));
    // One piece waits while the connection sends the one before: the webview stays at most two pieces ahead.
    let (pieces, queue) = mpsc::channel(1);
    let activity = Arc::new(Activity::new());
    let body = UploadBody::new(queue, size, on_progress, activity.clone());
    let request = transfers
        .client
        .put(url)
        .headers(headers)
        .body(reqwest::Body::wrap(body));
    let request_host = host.clone();
    let answer = tauri::async_runtime::spawn(async move {
        let response = request
            .send()
            .await
            .map_err(|e| describe_transfer(&e, &request_host))?;
        answer_of(response, &request_host, API_TIMEOUT).await
    });
    let id = transfers.next_id();
    transfers.uploads.lock().unwrap().insert(
        id,
        Upload {
            pieces: Some(pieces),
            abort: answer.inner().abort_handle(),
            answer: Some(answer),
            size,
            accepted: 0,
            activity,
            host,
        },
    );
    Ok(id)
}

/// Hand over the next piece of upload `id` (raw request body; the id in the `passauth-transfer` header). Resolves once
/// the body has room for it, `false` when the request has ended already: the server answered without reading on (an
/// error, or a session to renew), or the connection failed. `upload_finish` then has the answer.
#[tauri::command]
pub async fn upload_chunk(
    transfers: State<'_, Transfers>,
    request: Request<'_>,
) -> Result<bool, String> {
    let id = transfer_id(&request)?;
    let piece = piece(request.body())?;
    let (pieces, abort, host) = {
        let mut uploads = transfers.uploads.lock().unwrap();
        let upload = uploads.get_mut(&id).ok_or("unknown transfer")?;
        let pieces = upload.pieces.clone().ok_or("the upload has finished")?;
        upload.accepted = within(upload.accepted, piece.len(), upload.size)
            .ok_or("the app handed over more bytes than it announced")?;
        (pieces, upload.abort.clone(), upload.host.clone())
    };
    let started = Instant::now();
    loop {
        if abort.is_finished() {
            return Ok(false);
        }
        match timeout(TICK, pieces.reserve()).await {
            Ok(Ok(permit)) => {
                permit.send(piece);
                return Ok(true);
            }
            // The body is gone: the request has ended.
            Ok(Err(_)) => return Ok(false),
            Err(_) if started.elapsed() >= STALL => {
                transfers.cancel(id);
                return Err(too_slow(&host));
            }
            Err(_) => {}
        }
    }
}

/// Every piece of upload `id` is handed over: end the body and wait for the server's answer (`{status, headers, body}`
/// as `api_fetch` gives it).
#[tauri::command]
pub async fn upload_finish(
    transfers: State<'_, Transfers>,
    id: u64,
) -> Result<ApiResponse, String> {
    let (mut answer, activity, host) = {
        let mut uploads = transfers.uploads.lock().unwrap();
        let upload = uploads.get_mut(&id).ok_or("unknown transfer")?;
        // The request is ending by itself (it has, or the connection dropped the body: an early answer is on its way).
        let ending = upload.abort.is_finished()
            || upload.pieces.as_ref().is_none_or(mpsc::Sender::is_closed);
        if upload.accepted < upload.size && !ending {
            drop(uploads);
            transfers.cancel(id);
            return Err("The upload stopped before the whole file was sent. Try again.".into());
        }
        upload.pieces = None;
        let answer = upload.answer.take().ok_or("the upload has finished")?;
        (answer, upload.activity.clone(), upload.host.clone())
    };
    let result = loop {
        match timeout(TICK, &mut answer).await {
            // The request's outcome; a join error when `transfer_cancel` aborted it.
            Ok(joined) => break joined.unwrap_or_else(|_| Err(CANCELLED.into())),
            Err(_) if activity.overdue() => {
                transfers.cancel(id);
                break Err(too_slow(&host));
            }
            Err(_) => {}
        }
    };
    transfers.uploads.lock().unwrap().remove(&id);
    result
}

// ---------------------------------------------------------------- download

enum Piece {
    Data(Bytes),
    End,
    Failed(String),
}

/// A download's body as it arrives, read by the webview with `download_read`.
struct Download {
    queue: mpsc::Receiver<Piece>,
    /// How the body ended, when that came in behind data the last read returned.
    ended: Option<Result<(), String>>,
}

impl Download {
    /// At least one piece (waiting for it), then whatever else has arrived, up to about `READ_BATCH` bytes. `None` at
    /// the end of the body.
    async fn read(&mut self) -> Result<Option<Vec<u8>>, String> {
        if let Some(ended) = self.ended.take() {
            return ended.map(|()| None);
        }
        let mut out = match self.queue.recv().await {
            Some(Piece::Data(bytes)) => Vec::from(bytes),
            Some(Piece::End) => return Ok(None),
            Some(Piece::Failed(e)) => return Err(e),
            // The reader stopped without an end: cancelled.
            None => return Err(CANCELLED.into()),
        };
        while out.len() < READ_BATCH {
            match self.queue.try_recv() {
                Ok(Piece::Data(bytes)) => out.extend_from_slice(&bytes),
                Ok(Piece::End) => {
                    self.ended = Some(Ok(()));
                    break;
                }
                Ok(Piece::Failed(e)) => {
                    self.ended = Some(Err(e));
                    break;
                }
                // Nothing more yet (or cancelled: the next read says so).
                Err(_) => break,
            }
        }
        Ok(Some(out))
    }
}

struct DownloadEntry {
    abort: AbortHandle,
    body: Arc<tokio::sync::Mutex<Download>>,
}

/// What `download_start` found: a 2xx answer's body waits under `id`; other answers come with their text.
#[derive(Serialize)]
pub struct DownloadStart {
    id: Option<u64>,
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// Read a download's body into the queue the webview reads, at the webview's pace (the queue is bounded).
async fn read_body(mut response: reqwest::Response, queue: mpsc::Sender<Piece>, host: String) {
    let mut received = 0u64;
    loop {
        let piece = match timeout(STALL, response.chunk()).await {
            Err(_) => Piece::Failed(too_slow(&host)),
            Ok(Err(e)) => Piece::Failed(describe_transfer(&e, &host)),
            Ok(Ok(None)) => Piece::End,
            Ok(Ok(Some(bytes))) if bytes.is_empty() => continue,
            Ok(Ok(Some(bytes))) => match within(received, bytes.len(), MAX_TRANSFER_BYTES) {
                Some(total) => {
                    received = total;
                    Piece::Data(bytes)
                }
                None => Piece::Failed(too_large()),
            },
        };
        let last = !matches!(piece, Piece::Data(_));
        // A webview that stops reading for this long has gone (a reload): give up the connection.
        let delivered = matches!(timeout(STALL, queue.send(piece)).await, Ok(Ok(())));
        if last || !delivered {
            return;
        }
    }
}

/// `GET /api{path}`. A 2xx answer's body is then read with `download_read`; other answers (`404`, a session to renew…)
/// come back whole, with their text.
#[tauri::command]
pub async fn download_start(
    server: State<'_, Server>,
    transfers: State<'_, Transfers>,
    path: String,
    headers: HashMap<String, String>,
) -> Result<DownloadStart, String> {
    check_path(&path, Route::Download)?;
    let (url, host) = connected(&server, &path)?;
    let request = transfers
        .client
        .get(url)
        .headers(request_headers(&headers, &REQUEST_HEADERS)?);
    let response = timeout(API_TIMEOUT, request.send())
        .await
        .map_err(|_| too_slow(&host))?
        .map_err(|e| describe(&e, &host))?;
    if !response.status().is_success() {
        // Read here, before the webview has an id it could cancel: bounded by the answer's deadline.
        let answer = answer_of(response, &host, API_TIMEOUT).await?;
        return Ok(DownloadStart {
            id: None,
            status: answer.status,
            headers: answer.headers,
            body: answer.body,
        });
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_TRANSFER_BYTES)
    {
        return Err(too_large());
    }
    let status = response.status().as_u16();
    let headers = kept_headers(response.headers());
    let (pieces, queue) = mpsc::channel(DOWNLOAD_QUEUE);
    let reader = tauri::async_runtime::spawn(read_body(response, pieces, host));
    let id = transfers.next_id();
    transfers.downloads.lock().unwrap().insert(
        id,
        DownloadEntry {
            abort: reader.inner().abort_handle(),
            body: Arc::new(tokio::sync::Mutex::new(Download { queue, ended: None })),
        },
    );
    Ok(DownloadStart {
        id: Some(id),
        status,
        headers,
        body: String::new(),
    })
}

/// The next bytes of download `id` as a raw response; empty at the end of the body (the download is then gone).
#[tauri::command]
pub async fn download_read(transfers: State<'_, Transfers>, id: u64) -> Result<Response, String> {
    let body = transfers
        .downloads
        .lock()
        .unwrap()
        .get(&id)
        .map(|d| d.body.clone())
        .ok_or("unknown transfer")?;
    let read = body.lock().await.read().await;
    match read {
        Ok(Some(bytes)) => Ok(Response::new(bytes)),
        Ok(None) => {
            transfers.downloads.lock().unwrap().remove(&id);
            Ok(Response::new(Vec::new()))
        }
        Err(e) => {
            transfers.downloads.lock().unwrap().remove(&id);
            Err(e)
        }
    }
}

// -------------------------------------------------------------------- save

/// A file being saved: written to `temp` next to `target`, renamed to it when whole.
struct Save {
    file: Option<File>,
    temp: PathBuf,
    target: PathBuf,
    written: u64,
}

/// A hidden file in the folder the user picked, named after the file (its first `TEMP_NAME_MAX` bytes) and the
/// transfer (never an existing file).
fn temp_path(target: &Path, id: u64) -> Result<PathBuf, String> {
    let name = target
        .file_name()
        .ok_or("invalid file name")?
        .to_string_lossy();
    let mut end = name.len().min(TEMP_NAME_MAX);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    Ok(target.with_file_name(format!(
        ".{}.{}-{id}.part",
        &name[..end],
        std::process::id()
    )))
}

/// Close a save that won't finish and delete its temporary file.
fn discard(save: Arc<Mutex<Save>>) {
    tauri::async_runtime::spawn_blocking(move || {
        let mut save = save.lock().unwrap();
        save.file = None;
        let _ = std::fs::remove_file(&save.temp);
    });
}

/// Ask where to save `filename` (the system save dialog, suggesting `files::safe_file_name`) and open it for
/// `save_chunk`. `null` when the user cancels.
#[tauri::command]
pub async fn save_start(
    app: AppHandle,
    transfers: State<'_, Transfers>,
    filename: String,
) -> Result<Option<u64>, String> {
    let dialog = app
        .dialog()
        .file()
        .set_file_name(files::safe_file_name(&filename));
    let picked = tauri::async_runtime::spawn_blocking(move || dialog.blocking_save_file())
        .await
        .map_err(|e| e.to_string())?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let target = picked.into_path().map_err(|e| e.to_string())?;
    let id = transfers.next_id();
    let temp = temp_path(&target, id)?;
    let open = temp.clone();
    let file = blocking(move || {
        File::options()
            .write(true)
            .create_new(true)
            .open(open)
            .map_err(|e| e.to_string())
    })
    .await?;
    transfers.saves.lock().unwrap().insert(
        id,
        Arc::new(Mutex::new(Save {
            file: Some(file),
            temp,
            target,
            written: 0,
        })),
    );
    Ok(Some(id))
}

/// Write the next piece of save `id` (raw request body; the id in the `passauth-transfer` header).
#[tauri::command]
pub async fn save_chunk(
    transfers: State<'_, Transfers>,
    request: Request<'_>,
) -> Result<(), String> {
    let id = transfer_id(&request)?;
    let piece = piece(request.body())?;
    let save = transfers
        .saves
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or("unknown transfer")?;
    blocking(move || {
        let mut save = save.lock().unwrap();
        save.written =
            within(save.written, piece.len(), MAX_TRANSFER_BYTES).ok_or_else(too_large)?;
        let file = save.file.as_mut().ok_or("the save has finished")?;
        file.write_all(&piece).map_err(|e| e.to_string())
    })
    .await
}

/// Flush a whole save to disk, mark it as downloaded from the internet (`files::mark_downloaded`) and put it where the
/// user chose (replacing a file they agreed to replace). The mark goes on before the rename (the mark moves with the
/// file), so the file never sits under its name without it. Without the mark (a file system that has none) the file is
/// still saved; the failure is logged. Any other failure deletes the temporary file.
fn finish_save(save: &mut Save) -> io::Result<()> {
    let file = save
        .file
        .take()
        .ok_or_else(|| io::Error::other("the save has finished"))?;
    let synced = file.sync_all();
    drop(file);
    let done = synced.and_then(|()| {
        if let Err(e) = files::mark_downloaded(&save.temp) {
            eprintln!("couldn't mark a saved attachment as downloaded from the internet: {e}");
        }
        std::fs::rename(&save.temp, &save.target)
    });
    if done.is_err() {
        let _ = std::fs::remove_file(&save.temp);
    }
    done
}

/// Save `id` is whole: see `finish_save`.
#[tauri::command]
pub async fn save_finish(transfers: State<'_, Transfers>, id: u64) -> Result<(), String> {
    let save = transfers
        .saves
        .lock()
        .unwrap()
        .remove(&id)
        .ok_or("unknown transfer")?;
    blocking(move || finish_save(&mut save.lock().unwrap()).map_err(|e| e.to_string())).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::TempFile;
    use crate::tests::{one_request_server, test_client};
    use http_body::Body as _;
    use std::future::poll_fn;
    use tauri::ipc::InvokeResponseBody;

    #[test]
    fn only_attachment_paths_are_carried() {
        let id = "0b5d9d6e-2c2a-4f6e-9a51-6f1f0c6d8e21";
        let ok = format!("/attachments/{id}");
        let emergency = format!("/emergency-access/{id}/attachments/{id}");
        assert_eq!(check_path(&ok, Route::Upload), Ok(()));
        assert_eq!(check_path(&ok, Route::Download), Ok(()));
        assert_eq!(check_path(&emergency, Route::Download), Ok(()));
        // An upload goes to the attachment's own address only.
        assert!(check_path(&emergency, Route::Upload).is_err());
        for bad in [
            "",
            "attachments/x",
            "/attachments",
            "/attachments/",
            "/attachments/x/",
            "/attachments/x/y",
            "/attachments/..",
            "/attachments/%2e%2e",
            "/attachments/x?download=1",
            "/attachments/x#y",
            "/attachments/a.b",
            "//evil.example/attachments/x",
            "/items/x/attachments",
            "/emergency-access/g/vault",
            "/emergency-access/../attachments/x",
            "/emergency-access/g/attachments/x/extra",
            "/sync",
        ] {
            assert!(check_path(bad, Route::Download).is_err(), "{bad}");
            assert!(check_path(bad, Route::Upload).is_err(), "{bad}");
        }
        assert!(!is_id(&"a".repeat(65)));
        assert!(is_id(&"a".repeat(64)));
    }

    #[test]
    fn transfers_stay_on_the_connected_server() {
        let base = Url::parse("https://vault.example.com/").unwrap();
        let url = api_url(&base, "/attachments/abc").unwrap();
        assert_eq!(
            url.as_str(),
            "https://vault.example.com/api/attachments/abc"
        );
        let local = Url::parse("http://localhost:8091/").unwrap();
        assert_eq!(
            api_url(&local, "/attachments/abc").unwrap().as_str(),
            "http://localhost:8091/api/attachments/abc"
        );
        for bad in [
            "attachments/abc",
            "/x://evil.example",
            "https://evil.example/api",
            // Out of /api once normalised.
            "/../admin",
            "/%2e%2e/admin",
            "/attachments/../../x",
            r"/..\..\x",
        ] {
            assert!(api_url(&base, bad).is_err(), "{bad}");
        }
        // As `run()` does before building a client.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = Server {
            base: Mutex::new(None),
            client: reqwest::Client::new(),
        };
        assert_eq!(
            connected(&server, "/attachments/abc").unwrap_err(),
            "no server"
        );
        *server.base.lock().unwrap() = Some(base);
        let (url, host) = connected(&server, "/attachments/abc").unwrap();
        assert_eq!(url.host_str(), Some("vault.example.com"));
        assert_eq!(host, "vault.example.com");
    }

    #[test]
    fn the_webview_sets_only_its_session_and_app_name() {
        let headers = HashMap::from([
            ("Authorization".to_string(), "Bearer abc".to_string()),
            ("X-PassAuth-Client".to_string(), "desktop/0.7.0".to_string()),
        ]);
        let map = request_headers(&headers, &REQUEST_HEADERS).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map["authorization"], "Bearer abc");
        assert_eq!(map["x-passauth-client"], "desktop/0.7.0");
        assert!(
            request_headers(&HashMap::new(), &REQUEST_HEADERS)
                .unwrap()
                .is_empty()
        );
        for name in [
            "host",
            "content-length",
            "Transfer-Encoding",
            "cookie",
            "content-type",
            "x-forwarded-for",
            "connection",
        ] {
            let headers = HashMap::from([(name.to_string(), "1".to_string())]);
            assert!(
                request_headers(&headers, &REQUEST_HEADERS).is_err(),
                "{name}"
            );
        }
        let split = HashMap::from([("authorization".to_string(), "a\r\nhost: evil".to_string())]);
        assert!(request_headers(&split, &REQUEST_HEADERS).is_err());
    }

    #[test]
    fn sizes_stay_within_the_limits() {
        assert!(check_size(0).is_err());
        assert_eq!(check_size(1), Ok(()));
        assert_eq!(check_size(MAX_TRANSFER_BYTES), Ok(()));
        assert_eq!(check_size(MAX_TRANSFER_BYTES + 1), Err(too_large()));
        assert_eq!(within(10, 5, 15), Some(15));
        assert_eq!(within(10, 6, 15), None);
        assert_eq!(within(u64::MAX, 1, u64::MAX), None);
        assert_eq!(within(0, 0, 0), Some(0));
    }

    #[test]
    fn pieces_arrive_raw_or_as_the_fallback_json() {
        assert_eq!(
            piece(&InvokeBody::Raw(vec![1, 2, 3])).unwrap(),
            vec![1, 2, 3]
        );
        let json = InvokeBody::Json(serde_json::json!([0, 255, 7]));
        assert_eq!(piece(&json).unwrap(), vec![0, 255, 7]);
        assert!(piece(&InvokeBody::Json(serde_json::json!([256]))).is_err());
        assert!(piece(&InvokeBody::Json(serde_json::json!([-1]))).is_err());
        assert!(piece(&InvokeBody::Json(serde_json::json!({"id": 1}))).is_err());
        assert!(piece(&InvokeBody::Raw(Vec::new())).is_err());
        assert!(piece(&InvokeBody::Raw(vec![0; MAX_PIECE_BYTES])).is_ok());
        assert!(piece(&InvokeBody::Raw(vec![0; MAX_PIECE_BYTES + 1])).is_err());
    }

    #[test]
    fn a_save_writes_beside_the_chosen_file() {
        let temp = temp_path(Path::new("/home/me/Documents/scan.pdf"), 7).unwrap();
        assert_eq!(temp.parent(), Some(Path::new("/home/me/Documents")));
        let name = temp.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with(".scan.pdf.") && name.ends_with("-7.part"),
            "{name}"
        );
        assert!(temp_path(Path::new("/"), 7).is_err());
        // A long name (the user may type one in the dialog) is cut, at a character, for the temporary file only.
        let long = format!("{}.pdf", "é".repeat(120));
        let temp = temp_path(&Path::new("/home/me").join(&long), 7).unwrap();
        let name = temp.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.len() < 130, "{name}");
        assert!(name.starts_with(&format!(".{}.", "é".repeat(50))), "{name}");
    }

    #[test]
    fn a_finished_save_is_renamed_and_marked_as_downloaded() {
        let target = TempFile::new("save-target");
        let temp = TempFile(temp_path(&target.0, 9).unwrap());
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&temp.0)
            .unwrap();
        file.write_all(b"decrypted bytes").unwrap();
        let mut save = Save {
            file: Some(file),
            temp: temp.0.clone(),
            target: target.0.clone(),
            written: 15,
        };
        finish_save(&mut save).unwrap();
        assert_eq!(std::fs::read(&target.0).unwrap(), b"decrypted bytes");
        assert!(!temp.0.exists());
        // The mark was set on the temporary file and moved with it.
        #[cfg(target_os = "macos")]
        crate::files::tests::assert_marked_now(
            &crate::files::tests::quarantine_of(&target.0).unwrap(),
        );
        // Finishing twice is refused, and touches nothing.
        assert!(finish_save(&mut save).is_err());
        assert!(target.0.exists());
    }

    /// Sends `head`, then one byte of its body every `every` until the client goes away.
    fn trickle_server(head: &'static [u8], every: Duration) -> Url {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64 * 1024];
            let mut seen = Vec::new();
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buf).unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            stream.write_all(head).unwrap();
            while stream.write_all(b"x").is_ok() {
                std::thread::sleep(every);
            }
        });
        base
    }

    #[test]
    fn an_answer_is_read_within_one_deadline() {
        // A byte every 50 ms: no single wait is long, but the answer never ends.
        let head = b"HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: 1000000\r\nconnection: close\r\n\r\n";
        let base = trickle_server(head, Duration::from_millis(50));
        tauri::async_runtime::block_on(async {
            let response = test_client()
                .get(api_url(&base, "/attachments/a1").unwrap())
                .send()
                .await
                .unwrap();
            let started = Instant::now();
            let answer = answer_of(response, "vault.example.com", Duration::from_millis(400)).await;
            assert_eq!(answer.err(), Some(too_slow("vault.example.com")));
            assert!(started.elapsed() < Duration::from_secs(3));
        });
    }

    #[test]
    fn a_read_returns_what_has_arrived_and_the_end_after_it() {
        tauri::async_runtime::block_on(async {
            let (tx, queue) = mpsc::channel(DOWNLOAD_QUEUE);
            let mut download = Download { queue, ended: None };
            tx.send(Piece::Data(Bytes::from_static(b"abc")))
                .await
                .unwrap();
            tx.send(Piece::Data(Bytes::from_static(b"def")))
                .await
                .unwrap();
            tx.send(Piece::End).await.unwrap();
            assert_eq!(download.read().await, Ok(Some(b"abcdef".to_vec())));
            assert_eq!(download.read().await, Ok(None));

            // A failure behind data: the data first, then the failure.
            let (tx, queue) = mpsc::channel(DOWNLOAD_QUEUE);
            let mut download = Download { queue, ended: None };
            tx.send(Piece::Data(Bytes::from_static(b"x")))
                .await
                .unwrap();
            tx.send(Piece::Failed("broke off".into())).await.unwrap();
            assert_eq!(download.read().await, Ok(Some(b"x".to_vec())));
            assert_eq!(download.read().await, Err("broke off".to_string()));

            // A batch stops at about READ_BATCH; the rest comes with the next read.
            let (tx, queue) = mpsc::channel(DOWNLOAD_QUEUE);
            let mut download = Download { queue, ended: None };
            let half = Bytes::from(vec![1u8; READ_BATCH / 2]);
            for _ in 0..3 {
                tx.send(Piece::Data(half.clone())).await.unwrap();
            }
            assert_eq!(download.read().await.unwrap().unwrap().len(), READ_BATCH);
            assert_eq!(
                download.read().await.unwrap().unwrap().len(),
                READ_BATCH / 2
            );

            // The reader went away without an end: cancelled, never a short "end".
            drop(tx);
            assert_eq!(download.read().await, Err(CANCELLED.to_string()));
        });
    }

    #[test]
    fn an_upload_goes_out_with_its_length_and_every_piece() {
        let reply = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-request-id: r1\r\nset-cookie: a=b\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
        let (base, server) = one_request_server(reply.to_vec());
        let pieces = [vec![1u8; 1024], vec![2u8; 2048], vec![3u8; 5]];
        let size = 3077;
        tauri::async_runtime::block_on(async {
            let (tx, queue) = mpsc::channel(1);
            let body = UploadBody::new(
                queue,
                size,
                Channel::new(|_| Ok(())),
                Arc::new(Activity::new()),
            );
            let request = test_client()
                .put(api_url(&base, "/attachments/a1").unwrap())
                .header(CONTENT_LENGTH, size)
                .body(reqwest::Body::wrap(body));
            let sending = tauri::async_runtime::spawn(async move {
                answer_of(request.send().await.unwrap(), "localhost", API_TIMEOUT).await
            });
            for piece in pieces.clone() {
                tx.send(piece).await.unwrap();
            }
            drop(tx);
            let answer = sending.await.unwrap().unwrap();
            assert_eq!(answer.status, 200);
            assert_eq!(answer.body, "{}");
            assert_eq!(answer.headers.len(), 2, "{:?}", answer.headers);
            assert_eq!(answer.headers["x-request-id"], "r1");
        });
        let (head, body) = server.join().unwrap();
        assert!(
            head.starts_with("put /api/attachments/a1 http/1.1"),
            "{head}"
        );
        assert!(head.contains("content-length: 3077\r\n"), "{head}");
        assert!(!head.contains("transfer-encoding"), "{head}");
        assert_eq!(body, pieces.concat());
    }

    #[test]
    fn a_download_is_read_whole_in_batches() {
        let content: Vec<u8> = (0..3 * READ_BATCH + 17).map(|i| (i % 251) as u8).collect();
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            content.len()
        )
        .into_bytes();
        reply.extend_from_slice(&content);
        let (base, server) = one_request_server(reply);
        tauri::async_runtime::block_on(async {
            let response = test_client()
                .get(api_url(&base, "/attachments/a1").unwrap())
                .send()
                .await
                .unwrap();
            let (tx, queue) = mpsc::channel(DOWNLOAD_QUEUE);
            tauri::async_runtime::spawn(read_body(response, tx, "localhost".into()));
            let mut download = Download { queue, ended: None };
            let mut got = Vec::new();
            while let Some(bytes) = download.read().await.unwrap() {
                assert!(!bytes.is_empty());
                got.extend_from_slice(&bytes);
            }
            assert_eq!(got, content);
        });
        server.join().unwrap();
    }

    #[test]
    fn an_upload_body_sends_the_pieces_and_reports_progress() {
        tauri::async_runtime::block_on(async {
            let reported = Arc::new(Mutex::new(Vec::<u64>::new()));
            let seen = reported.clone();
            let progress = Channel::new(move |body| {
                if let InvokeResponseBody::Json(json) = body {
                    seen.lock().unwrap().push(json.parse().unwrap());
                }
                Ok(())
            });
            let (tx, queue) = mpsc::channel(1);
            let activity = Arc::new(Activity::new());
            let size = PROGRESS_STEP * 2 + 5;
            let mut body = UploadBody::new(queue, size, progress, activity.clone());
            assert_eq!(http_body::Body::size_hint(&body).exact(), Some(size));

            let mut frames = Vec::new();
            for len in [PROGRESS_STEP, PROGRESS_STEP, 5] {
                tx.send(vec![9u8; len as usize]).await.unwrap();
                let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
                frames.push(frame.unwrap().unwrap().into_data().unwrap().len() as u64);
            }
            assert_eq!(frames, [PROGRESS_STEP, PROGRESS_STEP, 5]);
            assert_eq!(http_body::Body::size_hint(&body).exact(), Some(0));
            assert!(!activity.done.load(Ordering::Relaxed));
            drop(tx);
            assert!(
                poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                    .await
                    .is_none()
            );
            assert!(activity.done.load(Ordering::Relaxed));
            // What the connection had taken when it asked for more (every PROGRESS_STEP), and everything at the end.
            assert_eq!(
                *reported.lock().unwrap(),
                [PROGRESS_STEP, PROGRESS_STEP * 2, size]
            );
        });
    }

    /// The commands as `desktop/src/transfers.ts` calls them (camelCase arguments, raw pieces with the transfer's id
    /// in a header, the progress channel), through Tauri's IPC on its mock runtime, against a loopback server.
    mod ipc {
        use super::*;
        use reqwest::header::HeaderMap;
        use serde_json::{Value, json};
        use tauri::ipc::CallbackFn;
        use tauri::test::{
            INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets,
        };
        use tauri::webview::InvokeRequest;
        use tauri::{WebviewWindow, WebviewWindowBuilder};

        const ID: &str = "0b5d9d6e-2c2a-4f6e-9a51-6f1f0c6d8e21";

        fn app() -> (tauri::App<MockRuntime>, WebviewWindow<MockRuntime>) {
            let app = mock_builder()
                .manage(Server {
                    base: Mutex::new(None),
                    client: test_client(),
                })
                .manage(Transfers::new(test_client()))
                .invoke_handler(tauri::generate_handler![
                    crate::set_server,
                    crate::api_fetch,
                    upload_start,
                    upload_chunk,
                    upload_finish,
                    download_start,
                    download_read,
                    transfer_cancel
                ])
                .build(mock_context(noop_assets()))
                .unwrap();
            let webview = WebviewWindowBuilder::new(&app, "main", Default::default())
                .build()
                .unwrap();
            (app, webview)
        }

        fn call(
            webview: &WebviewWindow<MockRuntime>,
            cmd: &str,
            body: InvokeBody,
            transfer: Option<u64>,
        ) -> Result<InvokeResponseBody, Value> {
            let mut headers = HeaderMap::new();
            if let Some(id) = transfer {
                headers.insert(TRANSFER_HEADER, HeaderValue::from(id));
            }
            let origin = if cfg!(windows) {
                "http://tauri.localhost"
            } else {
                "tauri://localhost"
            };
            get_ipc_response(
                webview,
                InvokeRequest {
                    cmd: cmd.into(),
                    callback: CallbackFn(0),
                    error: CallbackFn(1),
                    url: origin.parse().unwrap(),
                    body,
                    headers,
                    invoke_key: INVOKE_KEY.into(),
                },
            )
        }

        fn args(value: Value) -> InvokeBody {
            InvokeBody::Json(value)
        }

        #[test]
        fn a_file_goes_up_and_comes_back_through_the_commands() {
            let (_app, webview) = app();
            let session =
                json!({ "Authorization": "Bearer t1", "X-PassAuth-Client": "desktop/0.7.0" });

            // Upload: two raw pieces, then the server's answer.
            let reply = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
            let (base, server) = one_request_server(reply.to_vec());
            call(
                &webview,
                "set_server",
                args(json!({ "base": base.as_str() })),
                None,
            )
            .unwrap();
            let start = json!({ "path": format!("/attachments/{ID}"), "headers": session, "size": 6, "onProgress": "__CHANNEL__:7" });
            let id: u64 = call(&webview, "upload_start", args(start), None)
                .unwrap()
                .deserialize()
                .unwrap();
            for piece in [b"abc", b"def"] {
                let taken = call(
                    &webview,
                    "upload_chunk",
                    InvokeBody::Raw(piece.to_vec()),
                    Some(id),
                );
                assert!(taken.unwrap().deserialize::<bool>().unwrap());
            }
            // Past the announced size, or without the transfer's id: refused.
            assert!(
                call(
                    &webview,
                    "upload_chunk",
                    InvokeBody::Raw(b"x".to_vec()),
                    Some(id)
                )
                .is_err()
            );
            assert!(
                call(
                    &webview,
                    "upload_chunk",
                    InvokeBody::Raw(b"x".to_vec()),
                    None
                )
                .is_err()
            );
            let answer: Value = call(&webview, "upload_finish", args(json!({ "id": id })), None)
                .unwrap()
                .deserialize()
                .unwrap();
            assert_eq!(answer["status"], 200);
            assert_eq!(answer["body"], "{}");
            assert_eq!(answer["headers"]["content-type"], "application/json");
            let (head, body) = server.join().unwrap();
            assert!(
                head.starts_with(&format!("put /api/attachments/{ID} ")),
                "{head}"
            );
            for line in [
                "authorization: bearer t1",
                "x-passauth-client: desktop/0.7.0",
                "content-type: application/octet-stream",
                "content-length: 6",
            ] {
                assert!(head.contains(line), "{line} in {head}");
            }
            assert_eq!(body, b"abcdef");

            // Download through emergency access: raw reads to an empty one, then the transfer is gone.
            let content: Vec<u8> = (0..READ_BATCH + 100).map(|i| (i % 251) as u8).collect();
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                content.len()
            )
            .into_bytes();
            reply.extend_from_slice(&content);
            let (base, server) = one_request_server(reply);
            call(
                &webview,
                "set_server",
                args(json!({ "base": base.as_str() })),
                None,
            )
            .unwrap();
            let path = format!("/emergency-access/{ID}/attachments/{ID}");
            let started: Value = call(
                &webview,
                "download_start",
                args(json!({ "path": path, "headers": session })),
                None,
            )
            .unwrap()
            .deserialize()
            .unwrap();
            assert_eq!(started["status"], 200);
            let id = started["id"].as_u64().unwrap();
            let mut got = Vec::new();
            loop {
                let read =
                    call(&webview, "download_read", args(json!({ "id": id })), None).unwrap();
                let InvokeResponseBody::Raw(bytes) = read else {
                    panic!("download_read answered JSON");
                };
                if bytes.is_empty() {
                    break;
                }
                got.extend_from_slice(&bytes);
            }
            assert_eq!(got, content);
            assert!(call(&webview, "download_read", args(json!({ "id": id })), None).is_err());
            server.join().unwrap();
        }

        /// A server that answers as soon as it has the request's head (as PassAuth does for an expired session), then
        /// reads and drops whatever else comes until the client closes.
        fn early_answer_server(reply: &'static [u8]) -> (Url, std::thread::JoinHandle<()>) {
            use std::io::Read;
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut seen = Vec::new();
                let mut buf = [0u8; 64 * 1024];
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).unwrap();
                    seen.extend_from_slice(&buf[..n]);
                }
                stream.write_all(reply).unwrap();
                while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
            });
            (base, server)
        }

        #[test]
        fn an_early_answer_ends_the_upload_with_that_answer() {
            let (_app, webview) = app();
            let reply = b"HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: 24\r\nconnection: close\r\n\r\n{\"error\":\"unauthorized\"}";
            let (base, server) = early_answer_server(reply);
            call(
                &webview,
                "set_server",
                args(json!({ "base": base.as_str() })),
                None,
            )
            .unwrap();
            let size = 8 * 1024 * 1024;
            let start = json!({ "path": format!("/attachments/{ID}"), "headers": {}, "size": size, "onProgress": "__CHANNEL__:7" });
            let id: u64 = call(&webview, "upload_start", args(start), None)
                .unwrap()
                .deserialize()
                .unwrap();
            // The webview hands pieces over until it hears the request has ended.
            let mut handed = 0;
            let ended = loop {
                let taken = call(
                    &webview,
                    "upload_chunk",
                    InvokeBody::Raw(vec![0; 1024 * 1024]),
                    Some(id),
                )
                .unwrap()
                .deserialize::<bool>()
                .unwrap();
                if !taken {
                    break true;
                }
                handed += 1;
                if handed == 8 {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(100));
            };
            assert!(ended, "every piece was taken after the server had answered");
            let answer: Value = call(&webview, "upload_finish", args(json!({ "id": id })), None)
                .unwrap()
                .deserialize()
                .unwrap();
            assert_eq!(answer["status"], 401);
            assert_eq!(answer["body"], r#"{"error":"unauthorized"}"#);
            server.join().unwrap();
        }

        #[test]
        fn requests_outside_the_attachment_routes_are_refused() {
            let (_app, webview) = app();
            let headers = json!({ "authorization": "Bearer t1" });
            // No server yet.
            let early = json!({ "path": format!("/attachments/{ID}"), "headers": headers });
            assert!(call(&webview, "download_start", args(early), None).is_err());
            call(
                &webview,
                "set_server",
                args(json!({ "base": "http://127.0.0.1:9/" })),
                None,
            )
            .unwrap();
            for path in [
                "/sync",
                "/attachments/../sync",
                "/admin/users",
                "//evil.example/x",
            ] {
                let download = json!({ "path": path, "headers": headers });
                assert!(
                    call(&webview, "download_start", args(download), None).is_err(),
                    "{path}"
                );
                let upload = json!({ "path": path, "headers": headers, "size": 1, "onProgress": "__CHANNEL__:1" });
                assert!(
                    call(&webview, "upload_start", args(upload), None).is_err(),
                    "{path}"
                );
            }
            let cookie =
                json!({ "path": format!("/attachments/{ID}"), "headers": { "cookie": "a=b" } });
            assert!(call(&webview, "download_start", args(cookie), None).is_err());
            let huge = json!({ "path": format!("/attachments/{ID}"), "headers": headers, "size": MAX_TRANSFER_BYTES + 1, "onProgress": "__CHANNEL__:1" });
            assert!(call(&webview, "upload_start", args(huge), None).is_err());
            // Cancelling something that doesn't exist (any more) is fine.
            call(&webview, "transfer_cancel", args(json!({ "id": 42 })), None).unwrap();
        }

        /// `api_fetch` (lib.rs) as `desktop/src/server.ts` calls it, on the same mock runtime.
        #[test]
        fn api_fetch_sends_only_what_the_web_vault_sends() {
            let (_app, webview) = app();
            let reply = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nset-cookie: a=b\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
            let (base, server) = one_request_server(reply.to_vec());
            call(
                &webview,
                "set_server",
                args(json!({ "base": base.as_str() })),
                None,
            )
            .unwrap();
            let fetch = |path: &str, method: &str, headers: Value| {
                let body = json!({ "path": path, "method": method, "headers": headers, "body": "{\"a\":1}" });
                call(&webview, "api_fetch", args(body), None)
            };
            // Refused before anything goes out: a header the web vault doesn't send, a method it doesn't use, a path
            // outside /api.
            assert!(fetch("/sync", "POST", json!({ "host": "evil.example" })).is_err());
            assert!(fetch("/sync", "POST", json!({ "cookie": "a=b" })).is_err());
            assert!(fetch("/sync", "TRACE", json!({})).is_err());
            assert!(fetch("/../admin", "POST", json!({})).is_err());

            let session = json!({ "authorization": "Bearer t1", "content-type": "application/json", "x-passauth-client": "desktop/0.7.0", "x-reauth-token": "r1" });
            let answer: Value = fetch("/account/keys/finish", "post", session)
                .unwrap()
                .deserialize()
                .unwrap();
            assert_eq!(answer["status"], 200);
            assert_eq!(answer["body"], "{}");
            assert_eq!(
                answer["headers"],
                json!({ "content-type": "application/json" })
            );
            let (head, body) = server.join().unwrap();
            assert!(
                head.starts_with("post /api/account/keys/finish http/1.1"),
                "{head}"
            );
            for line in [
                "authorization: bearer t1",
                "content-type: application/json",
                "x-passauth-client: desktop/0.7.0",
                "x-reauth-token: r1",
            ] {
                assert!(head.contains(line), "{line} in {head}");
            }
            assert_eq!(body, br#"{"a":1}"#);

            // An answer announced as larger than API_BODY_MAX is refused unread.
            let huge = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                crate::API_BODY_MAX + 1
            );
            let (base, server) = one_request_server(huge.into_bytes());
            call(
                &webview,
                "set_server",
                args(json!({ "base": base.as_str() })),
                None,
            )
            .unwrap();
            let refused = fetch("/sync", "GET", json!({})).unwrap_err();
            assert!(
                refused
                    .as_str()
                    .is_some_and(|e| e.contains("larger than 128 MB")),
                "{refused}"
            );
            server.join().unwrap();
        }
    }
}
