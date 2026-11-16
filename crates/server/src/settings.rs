//! Limits, lifetimes, switches and account policies the admin sets on the admin
//! page (`GET/PUT /admin/settings`). Each is saved as a `server_settings` row under
//! its name and applies at once, without a restart. Until the admin changes one it
//! has its default: the value the server used before it became a setting. None of
//! them has an env variable: `.env` is only for identity, the admin sign-in and
//! infrastructure.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use anyhow::Result;
use serde_json::{Map, Value, json};

use passauth_core::kdf;

use crate::db::{self, Db};

/// A number the admin can change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Num {
    TrashDays,
    TombstoneDays,
    SessionDays,
    RefreshDays,
    RememberDeviceDays,
    SigninAttemptsPerMinute,
    TwoStepAttemptsPerHour,
    MaxImportItems,
    MaxItemKib,
    WebsocketPingSeconds,
    MaxItemsPerUser,
    MaxStorageMbPerUser,
    EventDays,
    ItemVersionsKept,
    SendMaxDays,
    MinKdfMemoryMib,
    MinKdfIterations,
    MasterPasswordMinLength,
    MaxVaultTimeoutMinutes,
    MaxAttachmentMb,
    MaxAttachmentStorageMbPerUser,
    MinFreeDiskMb,
}

/// Name (setting row and JSON key), default and accepted range of a [`Num`].
pub struct Spec {
    pub name: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
    /// What it is, for error messages.
    pub label: &'static str,
}

impl Num {
    /// Every setting, in declaration order (the index of [`Numbers`]).
    pub const ALL: [Num; 22] = [
        Num::TrashDays,
        Num::TombstoneDays,
        Num::SessionDays,
        Num::RefreshDays,
        Num::RememberDeviceDays,
        Num::SigninAttemptsPerMinute,
        Num::TwoStepAttemptsPerHour,
        Num::MaxImportItems,
        Num::MaxItemKib,
        Num::WebsocketPingSeconds,
        Num::MaxItemsPerUser,
        Num::MaxStorageMbPerUser,
        Num::EventDays,
        Num::ItemVersionsKept,
        Num::SendMaxDays,
        Num::MinKdfMemoryMib,
        Num::MinKdfIterations,
        Num::MasterPasswordMinLength,
        Num::MaxVaultTimeoutMinutes,
        Num::MaxAttachmentMb,
        Num::MaxAttachmentStorageMbPerUser,
        Num::MinFreeDiskMb,
    ];

    pub const fn spec(self) -> Spec {
        let (name, default, min, max, label) = match self {
            Num::TrashDays => ("trash_days", 0, 0, 3650, "Days in the trash (0 = forever)"),
            Num::TombstoneDays => (
                "tombstone_days",
                90,
                7,
                3650,
                "Days deletions are kept for apps that sync changes only",
            ),
            Num::SessionDays => ("session_days", 90, 1, 365, "Session lifetime in days"),
            Num::RefreshDays => (
                "refresh_days",
                30,
                1,
                365,
                "Days a signed-in device may stay offline",
            ),
            Num::RememberDeviceDays => (
                "remember_device_days",
                30,
                1,
                365,
                "Days a device skips two-step login",
            ),
            Num::SigninAttemptsPerMinute => (
                "signin_attempts_per_minute",
                30,
                5,
                600,
                "Sign-in attempts per address per minute",
            ),
            Num::TwoStepAttemptsPerHour => (
                "two_step_attempts_per_hour",
                10,
                3,
                100,
                "Wrong two-step codes per account per hour",
            ),
            Num::MaxImportItems => (
                "max_import_items",
                10_000,
                500,
                50_000,
                "Items per import request",
            ),
            Num::MaxItemKib => ("max_item_kib", 2048, 64, 4096, "Largest item in KiB"),
            Num::WebsocketPingSeconds => (
                "websocket_ping_seconds",
                30,
                10,
                300,
                "Seconds between live-sync connection checks",
            ),
            Num::MaxItemsPerUser => (
                "max_items_per_user",
                0,
                0,
                10_000_000,
                "Items per user (0 = no limit)",
            ),
            Num::MaxStorageMbPerUser => (
                "max_storage_mb_per_user",
                0,
                0,
                1_048_576,
                "Storage per user in MB (0 = no limit)",
            ),
            Num::EventDays => ("event_days", 365, 30, 3650, "Days the activity log is kept"),
            Num::ItemVersionsKept => (
                "item_versions_kept",
                10,
                0,
                100,
                "Earlier versions kept per item (0 = no history)",
            ),
            Num::SendMaxDays => (
                "send_max_days",
                30,
                1,
                365,
                "Longest time before a Send is deleted, in days",
            ),
            // Policies: the core's floors are the lowest values (every client
            // enforces them anyway), its ceilings the highest.
            Num::MinKdfMemoryMib => (
                "min_kdf_memory_mib",
                KDF_FLOOR_MEMORY_MIB,
                KDF_FLOOR_MEMORY_MIB,
                kdf::MAX_MEMORY_KIB as i64 / 1024,
                "Least memory for deriving keys from the master password, in MiB",
            ),
            Num::MinKdfIterations => (
                "min_kdf_iterations",
                KDF_FLOOR_ITERATIONS,
                KDF_FLOOR_ITERATIONS,
                kdf::MAX_ITERATIONS as i64,
                "Least passes for deriving keys from the master password",
            ),
            // The apps' own minimum is 10 characters; the policy can only raise it.
            Num::MasterPasswordMinLength => (
                "master_password_min_length",
                10,
                10,
                128,
                "Shortest master password the apps accept, in characters",
            ),
            Num::MaxVaultTimeoutMinutes => (
                "max_vault_timeout_minutes",
                0,
                0,
                43_200,
                "Longest vault timeout the apps offer, in minutes (0 = no limit)",
            ),
            // Encrypted size (what the app uploads), checked before the upload starts.
            Num::MaxAttachmentMb => (
                "max_attachment_mb",
                100,
                1,
                4096,
                "Largest attachment in MB",
            ),
            // Attachments are new, so a default limit changes nothing for existing
            // installs; it bounds what one account can put on the disk. Counted like
            // the storage quota's attachment part: ready files in the vaults the
            // user owns plus uploads they started that haven't finished.
            Num::MaxAttachmentStorageMbPerUser => (
                "max_attachment_storage_mb_per_user",
                1024,
                0,
                1_048_576,
                "Attachment storage per user in MB (0 = no limit)",
            ),
            // `disk.rs`: below this much free space, new data is refused (507).
            Num::MinFreeDiskMb => (
                "min_free_disk_mb",
                1024,
                0,
                1_048_576,
                "Free disk space kept in reserve, in MB: new data is refused below it (0 = no check)",
            ),
        };
        Spec {
            name,
            default,
            min,
            max,
            label,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.spec().name == name)
    }
}

/// The core's key-derivation floors (every client enforces them): the lowest
/// value of the KDF policies, at which they add nothing.
pub const KDF_FLOOR_MEMORY_MIB: i64 = kdf::MIN_MEMORY_KIB as i64 / 1024;
pub const KDF_FLOOR_ITERATIONS: i64 = kdf::MIN_ITERATIONS as i64;

/// A switch the admin can turn on or off (saved as `1` / `0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    /// Send: users can share text through an encrypted link (`sends.rs`).
    Sends,
    /// Every account must have a two-step login method (`policies.rs`).
    RequireTwoStep,
    /// New and changed account keys must use a Secret Key (`policies.rs`).
    RequireSecretKey,
    /// Apps don't offer exporting the vault (advisory: export happens on the device).
    DisableExport,
    /// Users can add encrypted files to items (`vault/attachments.rs`). Off: no new
    /// uploads; files already stored can still be downloaded and deleted.
    Attachments,
    /// Users can name a trusted contact who may ask to view their vaults after a
    /// waiting period (`emergency.rs`).
    EmergencyAccess,
    /// A new device can sign in when one of the user's signed-in devices approves
    /// it (`auth_requests.rs`). Off: no new requests, and none is listed, answered
    /// or exchanged.
    LoginWithDevice,
}

/// Name (setting row and JSON key), default and description of a [`Flag`].
pub struct FlagSpec {
    pub name: &'static str,
    pub default: bool,
    /// What it is, for error messages.
    pub label: &'static str,
}

impl Flag {
    /// Every switch, in declaration order (the index of [`Numbers`]' flags).
    pub const ALL: [Flag; 7] = [
        Flag::Sends,
        Flag::RequireTwoStep,
        Flag::RequireSecretKey,
        Flag::DisableExport,
        Flag::Attachments,
        Flag::EmergencyAccess,
        Flag::LoginWithDevice,
    ];

    pub const fn spec(self) -> FlagSpec {
        let (name, default, label) = match self {
            Flag::Sends => ("sends", true, "Send (share text through an encrypted link)"),
            Flag::RequireTwoStep => (
                "require_two_step",
                false,
                "Every account must use two-step login",
            ),
            Flag::RequireSecretKey => (
                "require_secret_key",
                false,
                "Every account must use a Secret Key",
            ),
            Flag::DisableExport => ("disable_export", false, "The apps don't offer vault export"),
            Flag::Attachments => (
                "attachments",
                true,
                "Attachments (encrypted files in items)",
            ),
            Flag::EmergencyAccess => (
                "emergency_access",
                true,
                "Emergency access (a trusted contact may ask to view a user's vaults)",
            ),
            Flag::LoginWithDevice => (
                "login_with_device",
                true,
                "Sign in on a new device by approving it on a signed-in one",
            ),
        };
        FlagSpec {
            name,
            default,
            label,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.spec().name == name)
    }
}

/// Current values of every [`Num`] and [`Flag`], plus the breach-check and
/// IP-address switches.
pub struct Numbers {
    values: [AtomicI64; Num::ALL.len()],
    flags: [AtomicBool; Flag::ALL.len()],
    /// The web vault may ask Have I Been Pwned's range API (k-anonymity) whether a
    /// password appeared in a breach (`breach_check`, default on).
    breach_check: AtomicBool,
    /// The activity log keeps the IP address of each event (`event_ip`, default on).
    event_ip: AtomicBool,
}

/// `server_settings` row of the breach-check switch.
pub const BREACH_CHECK: &str = "breach_check";
/// `server_settings` row of the activity log's IP-address switch.
pub const EVENT_IP: &str = "event_ip";

impl Numbers {
    /// Defaults for all.
    pub fn defaults() -> Self {
        Self {
            values: Num::ALL.map(|n| AtomicI64::new(n.spec().default)),
            flags: Flag::ALL.map(|f| AtomicBool::new(f.spec().default)),
            breach_check: AtomicBool::new(true),
            event_ip: AtomicBool::new(true),
        }
    }

    /// The saved values (a value out of range is clamped, an unreadable one
    /// falls back to the default).
    pub async fn load(db: &Db) -> Result<Self> {
        let numbers = Self::defaults();
        for n in Num::ALL {
            let spec = n.spec();
            let Some(saved) = db::setting(db, spec.name).await? else {
                continue;
            };
            match saved.trim().parse::<i64>() {
                Ok(v) => numbers.set(n, v.clamp(spec.min, spec.max)),
                Err(_) => tracing::warn!(
                    setting = spec.name,
                    value = %saved,
                    "unreadable saved setting; using its default"
                ),
            }
        }
        for f in Flag::ALL {
            if let Some(v) = db::setting(db, f.spec().name).await? {
                numbers.set_flag(f, v == "1");
            }
        }
        if let Some(v) = db::setting(db, BREACH_CHECK).await? {
            numbers.set_breach_check(v == "1");
        }
        if let Some(v) = db::setting(db, EVENT_IP).await? {
            numbers.set_event_ip(v == "1");
        }
        Ok(numbers)
    }

    pub fn get(&self, n: Num) -> i64 {
        self.values[n as usize].load(Ordering::Relaxed)
    }

    pub fn set(&self, n: Num, value: i64) {
        self.values[n as usize].store(value, Ordering::Relaxed);
    }

    pub fn flag(&self, f: Flag) -> bool {
        self.flags[f as usize].load(Ordering::Relaxed)
    }

    pub fn set_flag(&self, f: Flag, on: bool) {
        self.flags[f as usize].store(on, Ordering::Relaxed);
    }

    pub fn breach_check(&self) -> bool {
        self.breach_check.load(Ordering::Relaxed)
    }

    pub fn set_breach_check(&self, on: bool) {
        self.breach_check.store(on, Ordering::Relaxed);
    }

    pub fn event_ip(&self) -> bool {
        self.event_ip.load(Ordering::Relaxed)
    }

    pub fn set_event_ip(&self, on: bool) {
        self.event_ip.store(on, Ordering::Relaxed);
    }

    /// Every number and switch by name, for `GET /admin/settings`.
    pub fn values_json(&self) -> Map<String, Value> {
        let numbers = Num::ALL
            .into_iter()
            .map(|n| (n.spec().name.to_owned(), self.get(n).into()));
        let flags = Flag::ALL
            .into_iter()
            .map(|f| (f.spec().name.to_owned(), self.flag(f).into()));
        numbers.chain(flags).collect()
    }
}

/// Range and default of every number, for the admin page's fields.
pub fn ranges_json() -> Value {
    Value::Object(
        Num::ALL
            .into_iter()
            .map(|n| {
                let s = n.spec();
                (
                    s.name.to_owned(),
                    json!({ "min": s.min, "max": s.max, "default": s.default }),
                )
            })
            .collect(),
    )
}

/// Default of every switch, for the admin page (`switches` in `GET /admin/settings`).
pub fn switches_json() -> Value {
    Value::Object(
        Flag::ALL
            .into_iter()
            .map(|f| {
                let s = f.spec();
                (s.name.to_owned(), json!({ "default": s.default }))
            })
            .collect(),
    )
}

/// Check a value sent for the switch `f`.
pub fn validate_flag(f: Flag, value: &Value) -> Result<bool, String> {
    let s = f.spec();
    value
        .as_bool()
        .ok_or_else(|| format!("{} ({}) must be true or false", s.label, s.name))
}

/// Check a value sent for `n`; the error message names the setting and its range.
pub fn validate(n: Num, value: &Value) -> Result<i64, String> {
    let s = n.spec();
    value
        .as_i64()
        .filter(|v| (s.min..=s.max).contains(v))
        .ok_or_else(|| {
            format!(
                "{} ({}) must be a whole number from {} to {}",
                s.label, s.name, s.min, s.max
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_has_its_own_slot_and_a_sane_default() {
        for (i, n) in Num::ALL.into_iter().enumerate() {
            assert_eq!(n as usize, i, "ALL is in declaration order");
            let s = n.spec();
            assert!(s.min <= s.default && s.default <= s.max, "{}", s.name);
            assert_eq!(Num::from_name(s.name), Some(n));
        }
        for (i, f) in Flag::ALL.into_iter().enumerate() {
            assert_eq!(f as usize, i, "ALL is in declaration order");
            assert_eq!(Flag::from_name(f.spec().name), Some(f));
            assert_eq!(Num::from_name(f.spec().name), None, "names are unique");
        }
        assert_eq!(validate_flag(Flag::Sends, &json!(false)), Ok(false));
        assert!(validate_flag(Flag::Sends, &json!("off")).is_err());
        assert_eq!(validate(Num::SessionDays, &json!(30)), Ok(30));
        assert!(validate(Num::SessionDays, &json!(0)).is_err());
        assert!(validate(Num::SessionDays, &json!("30")).is_err());
        assert!(validate(Num::SessionDays, &json!(1.5)).is_err());
    }
}
