//! The container starts as root only to prepare PassAuth's own folders, then
//! runs as `PUID:PGID` (default 1000:1000) with no capabilities left. Started
//! as any other user (for example with compose `user:`), it changes nothing.

use anyhow::Result;

/// Run before any thread is started. `prepare_folders` creates the database
/// and icon folders and gives them to `PUID:PGID` (only `serve` needs that).
pub fn drop_root(prepare_folders: bool) -> Result<()> {
    imp::drop_root(prepare_folders)
}

#[cfg(not(target_os = "linux"))]
mod imp {
    pub fn drop_root(_prepare_folders: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::os::unix::fs::{MetadataExt, lchown};
    use std::path::Path;

    use anyhow::{Context, Result, bail};

    const CAPS: &str =
        "the container needs `cap_add: [CHOWN, SETUID, SETGID]` (see docker-compose.yml)";

    pub fn drop_root(prepare_folders: bool) -> Result<()> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        let uid = id("PUID")?;
        let gid = id("PGID")?;
        if uid == 0 {
            bail!(
                "PUID=0 would run PassAuth as root, which it never does: set PUID and PGID in .env to the owner of your data folder (`id -u` and `id -g`)"
            );
        }
        if prepare_folders {
            for dir in crate::config::data_dirs()? {
                own(Path::new(&dir), uid, gid)?;
            }
        }
        switch_user(uid, gid)
    }

    fn id(name: &str) -> Result<u32> {
        match std::env::var(name) {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse()
                .with_context(|| format!("{name} must be a number, got {v:?}")),
            _ => Ok(1000),
        }
    }

    /// Create `dir` if root may, and give it (and everything in it) to `uid:gid`, unless
    /// it already belongs to them. Root has no `DAC_OVERRIDE`, so it can't create a
    /// folder inside one owned by someone else (e.g. `/data/icons`); the server creates
    /// that one itself after switching user.
    fn own(dir: &Path, uid: u32, gid: u32) -> Result<()> {
        if !dir.exists() && std::fs::create_dir_all(dir).is_err() {
            return Ok(());
        }
        let meta = std::fs::metadata(dir).with_context(|| format!("reading {}", dir.display()))?;
        if meta.uid() == uid && meta.gid() == gid {
            return Ok(());
        }
        eprintln!(
            "passauth: giving {} to PUID:PGID {uid}:{gid}",
            dir.display()
        );
        chown_tree(dir, uid, gid).with_context(|| {
            format!(
                "could not give {} to PUID:PGID {uid}:{gid}: {CAPS}, or run `sudo chown -R {uid}:{gid}` on that folder on the host",
                dir.display()
            )
        })
    }

    /// Children first, so a folder only root may read is emptied before it changes hands.
    /// Symbolic links are changed themselves, never followed.
    fn chown_tree(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                chown_tree(&entry?.path(), uid, gid)?;
            }
        }
        if meta.uid() != uid || meta.gid() != gid {
            lchown(path, Some(uid), Some(gid))?;
        }
        Ok(())
    }

    fn switch_user(uid: u32, gid: u32) -> Result<()> {
        let fail = |call: &str| {
            let e = std::io::Error::last_os_error();
            anyhow::anyhow!("cannot switch to PUID:PGID {uid}:{gid} ({call}: {e}): {CAPS}")
        };
        // SAFETY: plain syscalls with integer arguments and a pointer to one live gid;
        // no other thread exists yet, so the whole process changes user.
        unsafe {
            if libc::setgroups(1, &gid) != 0 {
                return Err(fail("setgroups"));
            }
            if libc::setgid(gid) != 0 {
                return Err(fail("setgid"));
            }
            if libc::setuid(uid) != 0 {
                return Err(fail("setuid"));
            }
            if libc::setuid(0) == 0 {
                bail!("could still become root after switching to {uid}:{gid}");
            }
        }
        // Leaving root clears every capability; make sure of it.
        let status =
            std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
        for line in status.lines() {
            if let Some((key, value)) = line.split_once(':')
                && matches!(key, "CapPrm" | "CapEff" | "CapAmb")
                && u64::from_str_radix(value.trim(), 16).unwrap_or(u64::MAX) != 0
            {
                bail!("capabilities left after switching to {uid}:{gid}: {line}");
            }
        }
        Ok(())
    }
}
