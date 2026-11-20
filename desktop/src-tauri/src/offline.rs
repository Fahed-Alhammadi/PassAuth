//! Offline changes (ARCHITECTURE "Offline changes"): each account's change list, kept for the web vault in the app's
//! data directory, one file per server and account. The web vault seals the list with the account key before it gets
//! here, so this only stores opaque text: written whole to a temporary file, flushed, then renamed over the old one.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tauri::{AppHandle, Manager};

/// Longest sealed list accepted: the core seals at most 8 MiB of JSON, which is about 10.7 MiB as base64url.
pub const MAX_LEN: usize = 12 * 1024 * 1024;
/// Longest name (`<server host>|<account id>`).
const MAX_NAME: usize = 512;
const DIR: &str = "offline-changes";

fn file_name(name: &str) -> Result<String, String> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err("invalid name".into());
    }
    // Hex of the name: any host or id maps to one plain file name, and two names never share one.
    let hex: String = name.bytes().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{hex}.sealed"))
}

pub fn read_at(dir: &Path, name: &str) -> Result<Option<String>, String> {
    let path = dir.join(file_name(name)?);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    // The size is checked before anything is read, and the read stops just past the limit in case the file grows.
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    if len > MAX_LEN as u64 {
        return Err("too large".into());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_LEN {
        return Err("too large".into());
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "unreadable".into())
}

/// A temporary file name of its own for each write (two writes never share one).
fn temp_path(path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}-{n}-{nanos}.tmp", std::process::id()));
    path.with_file_name(name)
}

pub fn write_at(dir: &Path, name: &str, value: Option<&str>) -> Result<(), String> {
    let path = dir.join(file_name(name)?);
    let Some(value) = value else {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    };
    if value.len() > MAX_LEN {
        return Err("too large".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let tmp = temp_path(&path);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| e.to_string())
}

fn dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|d| d.join(DIR))
        .map_err(|_| "no data directory".to_string())
}

#[tauri::command]
pub async fn offline_changes_get(app: AppHandle, name: String) -> Result<Option<String>, String> {
    let dir = dir(&app)?;
    crate::blocking(move || read_at(&dir, &name)).await
}

#[tauri::command]
pub async fn offline_changes_set(
    app: AppHandle,
    name: String,
    value: Option<String>,
) -> Result<(), String> {
    let dir = dir(&app)?;
    crate::blocking(move || write_at(&dir, &name, value.as_deref())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "passauth-offline-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn keeps_replaces_and_deletes_a_list() {
        let dir = scratch("roundtrip");
        assert_eq!(read_at(&dir, "host|acct").unwrap(), None);
        write_at(&dir, "host|acct", Some("sealed-1")).unwrap();
        write_at(&dir, "host|other", Some("sealed-2")).unwrap();
        assert_eq!(
            read_at(&dir, "host|acct").unwrap().as_deref(),
            Some("sealed-1")
        );
        write_at(&dir, "host|acct", Some("sealed-3")).unwrap();
        assert_eq!(
            read_at(&dir, "host|acct").unwrap().as_deref(),
            Some("sealed-3")
        );
        write_at(&dir, "host|acct", None).unwrap();
        write_at(&dir, "host|acct", None).unwrap();
        assert_eq!(read_at(&dir, "host|acct").unwrap(), None);
        assert_eq!(
            read_at(&dir, "host|other").unwrap().as_deref(),
            Some("sealed-2")
        );
        // No temporary file is left behind.
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn names_map_to_plain_distinct_files_and_odd_names_are_refused() {
        let a = file_name("../../etc|x").unwrap();
        let stem = a.strip_suffix(".sealed").unwrap();
        assert!(stem.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(file_name("a|b").unwrap(), file_name("a|c").unwrap());
        assert!(file_name("").is_err());
        assert!(file_name(&"x".repeat(MAX_NAME + 1)).is_err());
        let dir = scratch("limits");
        assert!(write_at(&dir, "n", Some(&"x".repeat(MAX_LEN + 1))).is_err());
        // A file over the limit (written by something else) is refused before it is read.
        std::fs::create_dir_all(&dir).unwrap();
        let big = std::fs::File::create(dir.join(file_name("n").unwrap())).unwrap();
        big.set_len(MAX_LEN as u64 + 1).unwrap();
        assert_eq!(read_at(&dir, "n").unwrap_err(), "too large");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn each_write_has_its_own_temporary_file() {
        let path = Path::new("/x/abc.sealed");
        let (a, b) = (temp_path(path), temp_path(path));
        assert_ne!(a, b);
        assert_eq!(a.parent(), path.parent());
        assert!(
            a.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("abc.sealed.")
        );
    }
}
