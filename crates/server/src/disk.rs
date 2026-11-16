//! Free disk space. New data is refused with 507 `insufficient_storage` once the
//! disk holding the SQLite database or the attachment files would have less free
//! space than the admin's reserve (`min_free_disk_mb`, default 1024; 0 turns the
//! check off). So a full disk never takes the server down: signing in, syncing,
//! reading and deleting go on, and SQLite keeps room to commit them. Checked
//! before new or changed items, imports, attachments (their declared size, plus
//! the uploads running at that moment) and Sends.
//!
//! With PostgreSQL only the attachments folder is checked (the database's disk is
//! the database server's). The space is measured with `statvfs` (space available
//! to the server's own user) at most once a second; a folder that can't be
//! measured is left out rather than blocking writes.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{ApiError, ApiResult};
use crate::settings::Num;
use crate::state::App;

/// A measurement is reused for this long.
const FRESH: Duration = Duration::from_secs(1);

pub struct Disk {
    /// Folders whose file systems hold PassAuth's data.
    dirs: Vec<PathBuf>,
    /// The last measurement: when, and the least free space among `dirs`.
    last: Mutex<Option<(Instant, Option<u64>)>>,
    /// Free space tests pretend to have (`u64::MAX` = measure for real). Plenty
    /// until a test says otherwise, so no test depends on the machine's disk.
    #[cfg(test)]
    fake: std::sync::atomic::AtomicU64,
}

impl Disk {
    /// The database's folder (SQLite on disk) and the attachments folder, when
    /// there are such.
    pub fn new(database_url: &str, attachments: Option<&Path>) -> Self {
        let mut dirs: Vec<PathBuf> = crate::config::sqlite_dir(database_url)
            .map(PathBuf::from)
            .into_iter()
            .chain(attachments.map(Path::to_path_buf))
            .collect();
        dirs.dedup();
        Self {
            dirs,
            last: Mutex::new(None),
            #[cfg(test)]
            fake: std::sync::atomic::AtomicU64::new(1 << 50),
        }
    }

    /// The least free space (bytes) among the data folders' file systems; `None`
    /// when there is nothing to measure.
    pub async fn free(&self) -> Option<u64> {
        #[cfg(test)]
        {
            let fake = self.fake.load(std::sync::atomic::Ordering::Relaxed);
            if fake != u64::MAX {
                return Some(fake);
            }
        }
        if self.dirs.is_empty() {
            return None;
        }
        if let Some((at, free)) = *self.last.lock().expect("disk lock")
            && at.elapsed() < FRESH
        {
            return free;
        }
        let dirs = self.dirs.clone();
        let free = tokio::task::spawn_blocking(move || {
            dirs.iter()
                .filter_map(|dir| match free_bytes(dir) {
                    Ok(n) => Some(n),
                    Err(e) => {
                        tracing::debug!(dir = %dir.display(), error = %e, "measuring free disk space failed");
                        None
                    }
                })
                .min()
        })
        .await
        .ok()
        .flatten();
        *self.last.lock().expect("disk lock") = Some((Instant::now(), free));
        free
    }

    /// Pretend the disks have `bytes` free (`None`: measure them again).
    #[cfg(test)]
    pub fn pretend_free(&self, bytes: Option<u64>) {
        self.fake.store(
            bytes.unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Bytes that may still be written before the data disks are down to the admin's
/// reserve; `None` when there is no limit (the check is off, or there is nothing
/// to measure).
pub async fn room(state: &App) -> Option<u64> {
    let reserve_mb = state.num(Num::MinFreeDiskMb);
    if reserve_mb <= 0 {
        return None;
    }
    let free = state.disk.free().await?;
    Some(free.saturating_sub(reserve_mb as u64 * 1024 * 1024))
}

/// 507 `insufficient_storage` unless the data disks keep the admin's reserve once
/// `bytes` more (and the attachment uploads running now) are written.
pub async fn ensure_room(state: &App, bytes: u64) -> ApiResult<()> {
    let Some(room) = room(state).await else {
        return Ok(());
    };
    let uploading = state.files.as_ref().map_or(0, |f| f.bytes_in_flight());
    if room >= bytes.saturating_add(uploading) {
        return Ok(());
    }
    Err(full(state))
}

/// The answer once the reserve is reached (logged, so the admin finds out why).
pub fn full(state: &App) -> ApiError {
    tracing::warn!(
        reserve_mb = state.num(Num::MinFreeDiskMb),
        "refused a write: the disk is down to the free-space reserve (admin page: min_free_disk_mb)"
    );
    ApiError::insufficient_storage()
}

/// Bytes available to this process's user on the file system holding `dir`.
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // the field types differ between systems
fn free_bytes(dir: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `path` is NUL-terminated and `stats` is writable memory of the type
    // statvfs fills in; it reads nothing else.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs succeeded, so it filled the struct in.
    let stats = unsafe { stats.assume_init() };
    Ok((stats.f_bavail as u64).saturating_mul(stats.f_frsize as u64))
}

#[cfg(not(unix))]
fn free_bytes(_dir: &Path) -> io::Result<u64> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn measures_the_data_folders() {
        let dir = std::env::temp_dir();
        assert!(free_bytes(&dir).unwrap() > 0);
        assert!(free_bytes(Path::new("/no/such/folder/passauth")).is_err());
        let real = |disk: Disk| {
            disk.pretend_free(None);
            disk
        };
        let disk = real(Disk::new(
            "sqlite::memory:",
            Some(Path::new("/no/such/folder/passauth")),
        ));
        assert_eq!(disk.free().await, None, "unmeasurable folders don't block");
        let disk = real(Disk::new("sqlite::memory:", None));
        assert_eq!(disk.free().await, None, "nothing to measure");
        let disk = real(Disk::new(
            &format!("sqlite://{}/x.db", dir.display()),
            Some(&dir),
        ));
        assert_eq!(disk.dirs.len(), 1, "one file system is measured once");
        assert!(disk.free().await.unwrap() > 0);
        disk.pretend_free(Some(5));
        assert_eq!(disk.free().await, Some(5));
    }
}
