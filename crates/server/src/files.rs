//! Attachment files on disk (`vault/attachments.rs` keeps their rows). Each file is
//! the ciphertext an app uploaded, named by the attachment's id (a lowercase UUID)
//! in a subfolder named by the id's first two characters, so no folder grows past a
//! few thousand entries. An upload is written to `tmp/`, flushed to disk and renamed
//! into place, so a file under its id is always complete; the server never reads
//! a file for anything but sending it back, and never changes one in place (a new
//! upload replaces it with a new file). Folders are 0700 and files 0600, owned by
//! the server's user: it switched to PUID:PGID before starting (`privileges.rs`).

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Uploads running at once on the whole server.
const UPLOADS: usize = 32;
/// Uploads one user may run at once.
const UPLOADS_PER_USER: usize = 4;
/// An upload that sends nothing for this long is dropped.
const IDLE: Duration = Duration::from_secs(60);
/// Every upload must also be complete within this long…
const UPLOAD_GRACE: Duration = Duration::from_secs(60);
/// …plus the time its size takes at this many bytes per second, so trickling a
/// byte now and then can't hold an upload slot for ever.
const UPLOAD_MIN_RATE: u64 = 32 * 1024;

/// How long an upload of `size` bytes may take in all.
pub fn upload_deadline(size: u64) -> Duration {
    UPLOAD_GRACE + Duration::from_secs(size / UPLOAD_MIN_RATE)
}
/// Temp files older than this that no upload is writing are leftovers (a crash).
const TEMP_TTL: Duration = Duration::from_secs(3600);
/// Bytes read from a file per chunk of a download.
const CHUNK: u64 = 64 * 1024;
/// Subfolder for uploads being written.
const TMP: &str = "tmp";

/// An attachment id as stored and used as a file name: the UUID in lowercase
/// hyphenated form (any spelling of one UUID is the same attachment); `None` for
/// anything that isn't a UUID.
pub fn canonical_id(id: &str) -> Option<String> {
    uuid::Uuid::parse_str(id)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

/// Where the file of attachment `id` (canonical) lives below `dir`.
pub fn file_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(&id[..2]).join(id)
}

/// Create a folder (and its parents) only the server's user may open.
fn make_dir(dir: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Open a new file (never an existing one, never through a link) only the server's
/// user may read.
fn new_file_options() -> std::fs::OpenOptions {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o
}

/// Flush a folder's entries (a rename into it) to disk; best effort, as some
/// systems can't sync a folder.
fn sync_dir(dir: &Path) {
    if let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        tracing::debug!(dir = %dir.display(), error = %e, "syncing a folder failed");
    }
}

/// Why an upload wasn't stored.
#[derive(Debug)]
pub enum UploadError {
    /// More bytes than the attachment's size.
    TooLong,
    /// The body ended early (this many bytes arrived).
    TooShort(u64),
    /// Nothing arrived for [`IDLE`].
    Stalled,
    /// Still not complete at its deadline ([`upload_deadline`], in seconds).
    TooSlow(u64),
    /// The connection broke.
    Interrupted,
    Io(io::Error),
}

impl From<io::Error> for UploadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Why an upload couldn't start.
#[derive(Debug, PartialEq, Eq)]
pub enum Busy {
    /// This attachment is being uploaded already.
    Attachment,
    /// The user runs [`UPLOADS_PER_USER`] uploads already.
    User,
    /// The server runs [`UPLOADS`] uploads already.
    Server,
    /// The disk has no room for it above the admin's free-space reserve, counting
    /// the uploads running now (`disk.rs`).
    Disk,
}

pub struct FileStore {
    dir: PathBuf,
    /// The uploads running now. The sweeper leaves their rows and temp files alone.
    running: Mutex<Running>,
    slots: Arc<Semaphore>,
}

/// The uploads running now, changed under one lock so the per-user count can't be
/// passed by uploads starting at the same moment.
#[derive(Default)]
struct Running {
    /// Attachment id → (uploader's user id, size).
    uploads: HashMap<String, (String, u64)>,
    /// Uploads per uploader.
    per_user: HashMap<String, usize>,
    /// The sizes of all of them together (the free-disk check counts them as written).
    bytes: u64,
}

/// An upload in progress; dropping it ends it.
pub struct Upload<'a> {
    store: &'a FileStore,
    id: String,
    /// When it started: its deadline counts from here.
    started: Instant,
    _slot: OwnedSemaphorePermit,
}

impl Drop for Upload<'_> {
    fn drop(&mut self) {
        let mut running = self.store.running.lock().expect("uploads lock");
        if let Some((user, size)) = running.uploads.remove(&self.id) {
            running.bytes = running.bytes.saturating_sub(size);
            if let Some(n) = running.per_user.get_mut(&user) {
                *n -= 1;
                if *n == 0 {
                    running.per_user.remove(&user);
                }
            }
        }
    }
}

impl FileStore {
    /// Use `dir` (created if needed) for attachment files, after checking the
    /// server can write there.
    pub fn open(dir: &str) -> io::Result<Self> {
        let dir = PathBuf::from(dir);
        make_dir(&dir.join(TMP))?;
        let probe = dir
            .join(TMP)
            .join(format!(".probe-{}", uuid::Uuid::new_v4().simple()));
        new_file_options().open(&probe)?;
        std::fs::remove_file(&probe)?;
        Ok(Self {
            dir,
            running: Mutex::new(Running::default()),
            slots: Arc::new(Semaphore::new(UPLOADS)),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where the file of attachment `id` (canonical) lives.
    pub fn path(&self, id: &str) -> PathBuf {
        file_path(&self.dir, id)
    }

    /// Whether attachment `id` is being uploaded right now.
    pub fn is_uploading(&self, id: &str) -> bool {
        self.running
            .lock()
            .expect("uploads lock")
            .uploads
            .contains_key(id)
    }

    /// The sizes of the uploads running now, together.
    pub fn bytes_in_flight(&self) -> u64 {
        self.running.lock().expect("uploads lock").bytes
    }

    /// Start uploading attachment `id` (`size` bytes) for `user`: one upload per
    /// attachment at a time, a few per user, a bounded number on the server, and
    /// together no more than `room` bytes (the disk's room above the admin's
    /// reserve, `None` = no limit), all checked and taken under one lock.
    pub fn begin_upload(
        &self,
        id: &str,
        user: &str,
        size: u64,
        room: Option<u64>,
    ) -> Result<Upload<'_>, Busy> {
        let mut running = self.running.lock().expect("uploads lock");
        if running.uploads.contains_key(id) {
            return Err(Busy::Attachment);
        }
        if running.per_user.get(user).copied().unwrap_or(0) >= UPLOADS_PER_USER {
            return Err(Busy::User);
        }
        if room.is_some_and(|room| running.bytes.saturating_add(size) > room) {
            return Err(Busy::Disk);
        }
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| Busy::Server)?;
        running
            .uploads
            .insert(id.to_owned(), (user.to_owned(), size));
        *running.per_user.entry(user.to_owned()).or_default() += 1;
        running.bytes = running.bytes.saturating_add(size);
        Ok(Upload {
            store: self,
            id: id.to_owned(),
            started: Instant::now(),
            _slot: slot,
        })
    }

    /// Write the request body of `upload` to a new temp file, refusing it as soon as
    /// it passes `size` bytes (the body is never held in memory), when it ends
    /// short, and when it isn't complete by its deadline ([`upload_deadline`]); the
    /// file is on disk when this returns. Returns the temp file, which
    /// [`Self::place`] renames into place; on error nothing is left behind.
    pub async fn receive(
        &self,
        upload: &Upload<'_>,
        size: u64,
        body: Body,
    ) -> Result<PathBuf, UploadError> {
        let temp =
            self.dir
                .join(TMP)
                .join(format!("{}.{}", upload.id, uuid::Uuid::new_v4().simple()));
        let deadline = upload.started + upload_deadline(size);
        let written = write_temp(&temp, size, body, deadline).await;
        if written.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
        }
        written.map(|()| temp)
    }

    /// Rename a received temp file to attachment `id`'s place (replacing an older
    /// file there) and flush the folder, so the file survives a crash once the row
    /// says it's ready.
    pub async fn place(&self, temp: &Path, id: &str) -> io::Result<()> {
        let path = self.path(id);
        let shard = path.parent().expect("a file in a subfolder").to_owned();
        let temp = temp.to_owned();
        tokio::task::spawn_blocking(move || {
            make_dir(&shard)?;
            std::fs::rename(&temp, &path)?;
            sync_dir(&shard);
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Delete these attachments' files (best effort: a file left behind has no row,
    /// so the sweeper deletes it later).
    pub async fn remove(&self, ids: &[String]) {
        for id in ids {
            match tokio::fs::remove_file(self.path(id)).await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    attachment = %id,
                    error = %e,
                    "deleting an attachment file failed; the sweeper tries again"
                ),
            }
        }
    }

    /// Attachment `id`'s file as a response body of exactly `size` bytes, read in
    /// chunks. An error when it is missing or has another size.
    pub async fn read(&self, id: &str, size: u64) -> io::Result<Body> {
        let file = tokio::fs::File::open(self.path(id)).await?;
        let len = file.metadata().await?.len();
        if len != size {
            return Err(io::Error::other(format!(
                "the file is {len} bytes, its row says {size}"
            )));
        }
        let chunks =
            futures_util::stream::try_unfold((file, size), |(mut file, left)| async move {
                if left == 0 {
                    return Ok::<_, io::Error>(None);
                }
                let mut buf = vec![0u8; left.min(CHUNK) as usize];
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                buf.truncate(n);
                Ok(Some((Bytes::from(buf), (file, left - n as u64))))
            });
        Ok(Body::from_stream(chunks))
    }

    /// The ids of every attachment file in the store (names that aren't attachment
    /// ids are left alone), and leftover temp files deleted.
    pub async fn scan(&self) -> io::Result<Vec<String>> {
        let dir = self.dir.clone();
        let busy: Vec<String> = self
            .running
            .lock()
            .expect("uploads lock")
            .uploads
            .keys()
            .cloned()
            .collect();
        tokio::task::spawn_blocking(move || {
            sweep_temp(&dir.join(TMP), &busy);
            stored_ids(&dir)
        })
        .await
        .map_err(io::Error::other)?
    }
}

async fn write_temp(
    temp: &Path,
    size: u64,
    body: Body,
    deadline: Instant,
) -> Result<(), UploadError> {
    let options = new_file_options();
    let file = tokio::task::spawn_blocking({
        let temp = temp.to_owned();
        move || options.open(temp)
    })
    .await
    .map_err(io::Error::other)??;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;
    let too_slow = || UploadError::TooSlow(upload_deadline(size).as_secs());
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(too_slow());
        }
        let chunk = match tokio::time::timeout_at((now + IDLE).min(deadline), stream.next()).await {
            Err(_) if Instant::now() >= deadline => return Err(too_slow()),
            Err(_) => return Err(UploadError::Stalled),
            Ok(None) => break,
            Ok(Some(Err(_))) => return Err(UploadError::Interrupted),
            Ok(Some(Ok(chunk))) => chunk,
        };
        written += chunk.len() as u64;
        if written > size {
            return Err(UploadError::TooLong);
        }
        file.write_all(&chunk).await?;
    }
    if written < size {
        return Err(UploadError::TooShort(written));
    }
    file.flush().await?;
    file.sync_all().await?;
    Ok(())
}

/// Delete temp files older than [`TEMP_TTL`] that no running upload writes.
fn sweep_temp(tmp: &Path, busy: &[String]) {
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let id = name.split('.').next().unwrap_or_default();
        if busy.iter().any(|b| b == id) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= TEMP_TTL);
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Every attachment id with a file below `dir` (`<2 characters>/<id>`).
fn stored_ids(dir: &Path) -> io::Result<Vec<String>> {
    let mut ids = Vec::new();
    for shard in std::fs::read_dir(dir)? {
        let shard = shard?;
        let prefix = shard.file_name().to_string_lossy().into_owned();
        if prefix.len() != 2 || !shard.file_type()?.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(shard.path())? {
            let file = file?;
            let name = file.file_name().to_string_lossy().into_owned();
            if canonical_id(&name).as_deref() == Some(name.as_str())
                && name.starts_with(&prefix)
                && file.file_type()?.is_file()
            {
                ids.push(name);
            }
        }
    }
    Ok(ids)
}

/// Copy the files of attachments `ids` from the store `dir` into the new folder
/// `target` (same layout): hard links where possible (files never change in place,
/// so a link keeps the content of the moment), else copies. Returns the ids whose
/// file was missing. Blocking.
pub fn copy_into(dir: &Path, ids: &[String], target: &Path) -> io::Result<Vec<String>> {
    let mut missing = Vec::new();
    for id in ids {
        let from = file_path(dir, id);
        let to = file_path(target, id);
        make_dir(to.parent().expect("a file in a subfolder"))?;
        match std::fs::hard_link(&from, &to) {
            Ok(()) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(id.clone());
                continue;
            }
            // Another file system, or links not allowed: copy it.
            Err(_) => {}
        }
        let mut source = match std::fs::File::open(&from) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                missing.push(id.clone());
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut copy = new_file_options().open(&to)?;
        io::copy(&mut source, &mut copy)?;
        copy.sync_all()?;
    }
    Ok(missing)
}

/// Create the new folder `target` for [`copy_into`] (it must not exist yet).
pub fn new_folder(target: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_canonical_uuids_and_name_their_file() {
        let id = "8C6F2B8E-7A51-4C1E-9D55-2F1F5C2B7A10";
        let c = canonical_id(id).unwrap();
        assert_eq!(c, "8c6f2b8e-7a51-4c1e-9d55-2f1f5c2b7a10");
        assert_eq!(
            canonical_id("8c6f2b8e7a514c1e9d552f1f5c2b7a10").as_deref(),
            Some(c.as_str())
        );
        for bad in [
            "",
            "../../etc/passwd",
            "8c6f2b8e",
            "tmp",
            "8c6f2b8e-7a51-4c1e-9d55-2f1f5c2b7a1",
        ] {
            assert_eq!(canonical_id(bad), None, "{bad}");
        }
        assert_eq!(
            file_path(Path::new("/files"), &c),
            Path::new("/files/8c/8c6f2b8e-7a51-4c1e-9d55-2f1f5c2b7a10")
        );
    }

    fn new_store() -> (FileStore, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("passauth-files-{}", uuid::Uuid::new_v4().simple()));
        (FileStore::open(dir.to_str().unwrap()).unwrap(), dir)
    }

    #[test]
    fn one_upload_per_attachment_and_a_few_per_user() {
        let (store, dir) = new_store();
        let a = store.begin_upload("a", "u1", 10, None).unwrap();
        assert_eq!(
            store.begin_upload("a", "u2", 10, None).err(),
            Some(Busy::Attachment)
        );
        assert!(store.is_uploading("a"));
        let more: Vec<_> = ["b", "c", "d"]
            .iter()
            .map(|id| store.begin_upload(id, "u1", 5, None).unwrap())
            .collect();
        assert_eq!(store.bytes_in_flight(), 25);
        assert_eq!(
            store.begin_upload("e", "u1", 5, None).err(),
            Some(Busy::User)
        );
        // The disk's room counts the uploads running.
        assert_eq!(
            store.begin_upload("e", "u2", 7, Some(31)).err(),
            Some(Busy::Disk)
        );
        let other = store.begin_upload("e", "u2", 7, Some(32));
        assert!(other.is_ok(), "other users still can");
        drop(other);
        drop(a);
        assert!(!store.is_uploading("a"));
        assert_eq!(store.bytes_in_flight(), 15);
        assert!(
            store.begin_upload("e", "u1", 5, None).is_ok(),
            "a slot came free"
        );
        drop(more);
        assert_eq!(store.bytes_in_flight(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uploads_starting_at_once_never_pass_the_per_user_count() {
        let (store, dir) = new_store();
        let started = std::sync::Mutex::new(Vec::new());
        let barrier = std::sync::Barrier::new(16);
        std::thread::scope(|s| {
            for n in 0..16 {
                let (store, started, barrier) = (&store, &started, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    if let Ok(u) = store.begin_upload(&format!("id-{n}"), "u1", 1, None) {
                        started.lock().unwrap().push(u);
                    }
                });
            }
        });
        assert_eq!(started.lock().unwrap().len(), UPLOADS_PER_USER);
        drop(started);
        assert_eq!(store.bytes_in_flight(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_trickled_upload_ends_at_its_deadline() {
        assert_eq!(upload_deadline(0), Duration::from_secs(60));
        assert_eq!(
            upload_deadline(100 * 1024 * 1024),
            Duration::from_secs(60 + 3200)
        );
        let (store, dir) = new_store();
        // One byte every 20 ms: never idle for a minute, but far too slow.
        let trickle = futures_util::stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((Ok::<_, io::Error>(Bytes::from_static(b"x")), ()))
        });
        let temp = dir.join(TMP).join("trickle");
        let deadline = Instant::now() + Duration::from_millis(300);
        let started = Instant::now();
        let done = write_temp(&temp, 1_000_000, Body::from_stream(trickle), deadline).await;
        assert!(matches!(done, Err(UploadError::TooSlow(_))), "{done:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        // A body that arrives in time is stored.
        let quick = dir.join(TMP).join("quick");
        let deadline = Instant::now() + Duration::from_secs(5);
        write_temp(&quick, 3, Body::from("abc"), deadline)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&quick).unwrap(), b"abc");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
