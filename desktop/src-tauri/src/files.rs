//! Files the app saves for the user. A suggested name is cleaned before the save dialog shows it, so it can't hide
//! what the file is or point outside the folder the user picks. A saved attachment gets the system's "downloaded from
//! the internet" mark, so opening it gets the checks a browser download gets: Gatekeeper on macOS, SmartScreen and
//! Office Protected View on Windows. Linux has no standard mark, so nothing is set there.

use std::io;
use std::path::{Path, PathBuf};

/// Longest suggested name, in UTF-8 bytes (file systems allow 255).
const NAME_MAX: usize = 200;
/// A short extension (with its dot) survives when a long name is shortened.
const EXTENSION_MAX: usize = 16;
/// The name to suggest when nothing usable is left.
const FALLBACK_NAME: &str = "attachment";

/// Unicode's format characters (general category Cf, Unicode 18): bidi embeddings, overrides and isolates,
/// directional marks, zero-width characters, the byte order mark, tags. They are invisible but change how a name
/// reads: "invoice\u{202E}fdp.exe" is shown as "invoiceexe.pdf".
const FORMAT_CHARS: [(char, char); 21] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// Device names Windows reserves, with or without an extension ("NUL.txt" and "nul.tar.gz" are NUL).
const WINDOWS_DEVICES: [&str; 32] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT0", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

fn is_format(c: char) -> bool {
    FORMAT_CHARS
        .iter()
        .any(|&(first, last)| (first..=last).contains(&c))
}

/// `name` in at most `max` bytes, cut at a character boundary. A short extension is kept.
fn shorten(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_owned();
    }
    let extension = name.rfind('.').map_or("", |at| &name[at..]);
    let extension = if extension.len() <= EXTENSION_MAX {
        extension
    } else {
        ""
    };
    let mut end = max - extension.len();
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{extension}", &name[..end])
}

/// Dots and spaces at either end: leading dots hide a file, Windows drops trailing ones ("a.exe." is saved as "a.exe").
fn is_edge(c: char) -> bool {
    c == '.' || c == ' '
}

/// The name the save dialog suggests for `name`: one file name that shows what the file is.
/// - Control characters (Cc), format characters (Cf, such as bidi overrides) and line or paragraph separators are
///   removed.
/// - Path separators, and the other characters Windows refuses, become `_`. A colon would name an NTFS stream.
/// - Any white space becomes one space, because a long run could push the real extension out of view.
/// - Dots and spaces at either end are removed (`is_edge`).
/// - A Windows device name gets a `_` in front.
/// - The result is at most `NAME_MAX` bytes, never empty, and cleaning it again changes nothing.
pub fn safe_file_name(name: &str) -> String {
    let mut clean = String::with_capacity(name.len());
    for c in name.chars() {
        let c = match c {
            c if c.is_control() || is_format(c) || matches!(c, '\u{2028}' | '\u{2029}') => continue,
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_whitespace() => ' ',
            c => c,
        };
        if c == ' ' && clean.ends_with(' ') {
            continue;
        }
        clean.push(c);
    }
    let name = clean.trim_matches(is_edge);
    if name.is_empty() {
        return FALLBACK_NAME.into();
    }
    let device = name.split('.').next().unwrap_or_default().trim_end();
    let name = if WINDOWS_DEVICES
        .iter()
        .any(|d| device.eq_ignore_ascii_case(d))
    {
        format!("_{name}")
    } else {
        name.to_owned()
    };
    // A cut can leave a dot or a space at the end.
    shorten(&name, NAME_MAX)
        .trim_end_matches(is_edge)
        .to_owned()
}

/// Windows: the zone a browser writes on a download (3 = Internet), in the file's `Zone.Identifier` stream. Chrome
/// writes the same lines when it marks a file itself.
const ZONE_IDENTIFIER: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

/// The NTFS stream `path:Zone.Identifier`.
fn zone_identifier_stream(path: &Path) -> PathBuf {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    stream.into()
}

/// macOS: the quarantine value LaunchServices writes for a download by an app that isn't sandboxed (what
/// `NSURLQuarantinePropertiesKey`, used by browsers, leaves on the file): flags `0081` (downloaded, not yet approved
/// by the user), the time in hexadecimal seconds, and the agent's name. The event id stays empty, because nothing is
/// added to the system's download log.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn quarantine_value(unix_seconds: u64) -> String {
    format!("0081;{unix_seconds:08x};PassAuth;")
}

/// Mark a saved attachment as downloaded from the internet. Fails on a file system without the mark (FAT, some
/// network shares); the caller keeps the file then.
pub fn mark_downloaded(path: &Path) -> io::Result<()> {
    if cfg!(windows) {
        return std::fs::write(zone_identifier_stream(path), ZONE_IDENTIFIER);
    }
    set_quarantine(path)
}

#[cfg(target_os = "macos")]
fn set_quarantine(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let path = CString::new(path.as_os_str().as_bytes())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let value = quarantine_value(now);
    // SAFETY: `path` and the attribute's name are NUL-terminated and outlive the call, which reads `value.len()`
    // bytes of `value`. XATTR_NOFOLLOW: a symbolic link put in the file's place is not followed.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            c"com.apple.quarantine".as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Linux has no standard mark; Windows uses the zone stream above.
#[cfg(not(target_os = "macos"))]
fn set_quarantine(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `safe_file_name(name)`, checked to be stable: cleaning a clean name (the web vault cleans first) changes nothing.
    fn clean(name: &str) -> String {
        let once = safe_file_name(name);
        assert_eq!(safe_file_name(&once), once, "cleaning {name:?} twice");
        assert!(!once.is_empty() && once.len() <= NAME_MAX, "{once:?}");
        once
    }

    #[test]
    fn names_keep_what_they_say() {
        for name in [
            "scan.pdf",
            "Scan 2026-11-15 (final).pdf",
            "Résumé.docx",
            "日本語のファイル.txt",
            "photo 👍🏽.png",
            "archive.tar.gz",
            "CONsole.txt",
            "a.b.c",
        ] {
            assert_eq!(clean(name), name);
        }
    }

    #[test]
    fn invisible_characters_are_removed() {
        // Right-to-left override: shown as "invoiceexe.pdf".
        assert_eq!(clean("invoice\u{202E}fdp.exe"), "invoicefdp.exe");
        assert_eq!(
            clean("a\u{2066}b\u{2069}c\u{200E}d\u{200F}e\u{FEFF}f\u{00AD}g\u{200B}h.txt"),
            "abcdefgh.txt"
        );
        assert_eq!(clean("tag\u{E0041}\u{E007F}.pdf"), "tag.pdf");
        assert_eq!(clean("x\u{1343F}y\u{0890}z"), "xyz");
        assert_eq!(clean("line\nbreak\u{2028}\u{2029}\t.pdf"), "linebreak.pdf");
        assert_eq!(clean("nul\0byte\u{7F}\u{9B}.bin"), "nulbyte.bin");
    }

    #[test]
    fn a_name_is_never_a_path() {
        assert_eq!(
            clean("../../.ssh/authorized_keys"),
            "_.._.ssh_authorized_keys"
        );
        assert_eq!(clean(r"..\..\Startup\run.bat"), r"_.._Startup_run.bat");
        assert_eq!(clean("/etc/passwd"), "_etc_passwd");
        assert_eq!(clean("C:evil.exe"), "C_evil.exe");
        assert_eq!(
            clean("file.txt:Zone.Identifier"),
            "file.txt_Zone.Identifier"
        );
        assert_eq!(clean(r#"a*b?c"d<e>f|g"#), "a_b_c_d_e_f_g");
    }

    #[test]
    fn edges_that_hide_or_vanish_are_trimmed() {
        assert_eq!(clean("run.exe."), "run.exe");
        assert_eq!(clean("run.exe . . "), "run.exe");
        assert_eq!(clean("  report.pdf  "), "report.pdf");
        assert_eq!(clean(".hidden"), "hidden");
        assert_eq!(
            clean("\u{3000}\u{00A0}wide\u{2003}space.txt"),
            "wide space.txt"
        );
        // A run of spaces can't push the real extension out of view.
        let padded = format!("report.pdf{}.exe", " ".repeat(80));
        assert_eq!(clean(&padded), "report.pdf .exe");
        for empty in ["", "   ", "...", ". .", "\u{202E}", "\u{200B}\u{FEFF}"] {
            assert_eq!(clean(empty), FALLBACK_NAME, "{empty:?}");
        }
    }

    #[test]
    fn windows_device_names_get_a_prefix() {
        for (name, safe) in [
            ("CON", "_CON"),
            ("con.txt", "_con.txt"),
            ("NUL.tar.gz", "_NUL.tar.gz"),
            ("Com1.log", "_Com1.log"),
            ("LPT9", "_LPT9"),
            ("COM¹.txt", "_COM¹.txt"),
            ("conin$", "_conin$"),
            ("aux .txt", "_aux .txt"),
            ("PRN\u{202E}", "_PRN"),
        ] {
            assert_eq!(clean(name), safe, "{name}");
        }
        for name in [
            "CONSOLE",
            "COM10.txt",
            "LPT",
            "nul_file.txt",
            "prn-list.csv",
        ] {
            assert_eq!(clean(name), name);
        }
    }

    #[test]
    fn long_names_are_shortened_at_a_character_and_keep_their_extension() {
        let long = format!("{}.pdf", "a".repeat(300));
        let safe = clean(&long);
        assert_eq!(safe.len(), NAME_MAX);
        assert!(safe.ends_with("a.pdf"), "{safe}");

        let wide = "é".repeat(150);
        let safe = clean(&wide);
        assert!(safe.len() <= NAME_MAX && safe.chars().all(|c| c == 'é'));

        // An "extension" too long to be one isn't kept whole.
        let odd = format!("x.{}", "b".repeat(300));
        assert_eq!(clean(&odd).len(), NAME_MAX);
        // A device name keeps its prefix through the cut; a cut never leaves a dot or space at the end.
        let device = format!("CON.{}", "x".repeat(300));
        let safe = clean(&device);
        assert!(
            safe.starts_with("_CON.x") && safe.len() == NAME_MAX,
            "{safe}"
        );
        let spaced = format!("{} {}", "y".repeat(NAME_MAX - 1), "z".repeat(50));
        assert_eq!(clean(&spaced), "y".repeat(NAME_MAX - 1));
        // Exactly at the limit: unchanged.
        let fits = format!("{}.txt", "c".repeat(NAME_MAX - 4));
        assert_eq!(clean(&fits), fits);
    }

    #[test]
    fn the_marks_have_the_formats_the_systems_read() {
        assert_eq!(quarantine_value(0x6afa_0db5), "0081;6afa0db5;PassAuth;");
        assert_eq!(quarantine_value(1), "0081;00000001;PassAuth;");
        assert_eq!(
            zone_identifier_stream(Path::new(r"C:\Users\me\Downloads\.scan.pdf.42-7.part")),
            PathBuf::from(r"C:\Users\me\Downloads\.scan.pdf.42-7.part:Zone.Identifier")
        );
        assert_eq!(ZONE_IDENTIFIER, b"[ZoneTransfer]\r\nZoneId=3\r\n");
    }

    /// A file in the system's temporary folder, deleted when dropped.
    pub(crate) struct TempFile(pub PathBuf);

    impl TempFile {
        pub(crate) fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "passauth-test-{label}-{}-{nanos}",
                std::process::id()
            )))
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The file's `com.apple.quarantine` attribute as `xattr -p` prints it.
    #[cfg(target_os = "macos")]
    pub(crate) fn quarantine_of(path: &Path) -> Option<String> {
        let out = std::process::Command::new("xattr")
            .args(["-p", "com.apple.quarantine"])
            .arg(path)
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8(out.stdout).unwrap().trim_end().to_owned())
    }

    /// `value` is a quarantine value written by this app within the last minute.
    #[cfg(target_os = "macos")]
    pub(crate) fn assert_marked_now(value: &str) {
        let fields: Vec<&str> = value.split(';').collect();
        assert_eq!(fields.len(), 4, "{value}");
        assert_eq!(fields[0], "0081", "{value}");
        assert_eq!(fields[2], "PassAuth", "{value}");
        assert_eq!(fields[3], "", "{value}");
        let stamped = u64::from_str_radix(fields[1], 16).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(stamped) <= 60, "{value}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_marked_file_carries_the_quarantine_attribute() {
        let file = TempFile::new("quarantine");
        std::fs::write(&file.0, b"attachment").unwrap();
        assert_eq!(quarantine_of(&file.0), None);
        mark_downloaded(&file.0).unwrap();
        assert_marked_now(&quarantine_of(&file.0).unwrap());
        // A file that isn't there: an error for the caller to log.
        assert!(mark_downloaded(&file.0.with_extension("missing")).is_err());
    }
}
