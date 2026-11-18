//! Kotlin and Swift bindings (UniFFI) for the native PassAuth apps.
//!
//! Mirrors `passauth-core-wasm`: keys stay in Rust objects (`MasterKeys`,
//! `Account`, `VaultKey`, `EmergencyKey`) and the apps only hold handles (send and
//! attachment keys are base64url strings: they go into a link and into the
//! encrypted item anyway). Items, bundles and
//! KDF parameters cross the boundary as JSON in the same shape as the server
//! API and the web vault, so all clients read and write the same data.

use std::sync::{Arc, Mutex};

use passauth_core::crypto::{KeyPair, SymmetricKey, fingerprint as key_fingerprint, random_bytes};
use passauth_core::file::{self, FileKey};
use passauth_core::item::{EncryptedItem as CoreEncrypted, Item, b64, unb64};
use passauth_core::kdf::{KdfParams, MasterKeys as CoreMaster};
use passauth_core::keys::{
    self, AccountBundle, EmergencyKey as CoreEmergencyKey, NewAccount as CoreNew, UnlockedAccount,
};
use passauth_core::send::{self, SendContentKey, SendField, SendKey};
use passauth_core::{
    Error, device_login, export, generator, import, manifest, opaque, passkey, site, totp,
};

uniffi::setup_scaffolding!();

mod sharing;
pub use sharing::*;

/// The core's errors. Each variant's message is its code in snake_case (`decrypt_failed`,
/// `weak_kdf`…), the same string the WASM build throws; `Invalid` carries a description.
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    /// Wrong key, wrong master password / Secret Key, or tampered data.
    DecryptFailed,
    /// The import file is password protected.
    PasswordRequired,
    /// KDF parameters below the core's floor (a server asking for a cheap key).
    WeakKdf,
    /// KDF parameters above the core's ceiling, or a Send salt above the visitor ceiling.
    KdfTooStrong,
    /// Sign-in from another device: the picked words aren't the request key's own.
    PhraseMismatch,
    /// Sign-in from another device: not the approving app's code.
    WrongCode,
    /// Sign-in from another device: three wrong codes; start a new request.
    TooManyWrongCodes,
    /// Sign-in from another device: the code hasn't been confirmed yet.
    NotConfirmed,
    /// Signed sharing: a signature (identity, share or member roster) doesn't verify.
    BadSignature,
    /// Signed sharing: the server lists a signing identity that isn't this account's.
    IdentityMismatch,
    /// Signed sharing: older than what this device already trusted (roster, key pins).
    Rollback,
    /// Signed sharing: two different member rosters with the same version.
    RosterForked,
    /// Signed sharing: a member roster signed by someone who may not change it.
    RosterUnauthorized,
    /// Key pins over their size limit, or a roster chain too long (refused, never trimmed).
    TooLarge,
    /// Signed sharing: the member list to sign isn't the one reviewed.
    ReviewMismatch,
    Invalid(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DecryptFailed => "decrypt_failed",
            Self::PasswordRequired => "password_required",
            Self::WeakKdf => "weak_kdf",
            Self::KdfTooStrong => "kdf_too_strong",
            Self::PhraseMismatch => "phrase_mismatch",
            Self::WrongCode => "wrong_code",
            Self::TooManyWrongCodes => "too_many_wrong_codes",
            Self::NotConfirmed => "not_confirmed",
            Self::BadSignature => "bad_signature",
            Self::IdentityMismatch => "identity_mismatch",
            Self::Rollback => "rollback",
            Self::RosterForked => "roster_forked",
            Self::RosterUnauthorized => "roster_unauthorized",
            Self::TooLarge => "too_large",
            Self::ReviewMismatch => "review_mismatch",
            Self::Invalid(m) => m,
        })
    }
}

impl std::error::Error for CoreError {}

impl From<Error> for CoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::Decrypt => Self::DecryptFailed,
            Error::PasswordRequired => Self::PasswordRequired,
            Error::WeakKdf => Self::WeakKdf,
            Error::KdfTooStrong => Self::KdfTooStrong,
            Error::PhraseMismatch => Self::PhraseMismatch,
            Error::WrongCode => Self::WrongCode,
            Error::TooManyWrongCodes => Self::TooManyWrongCodes,
            Error::NotConfirmed => Self::NotConfirmed,
            Error::BadSignature => Self::BadSignature,
            Error::IdentityMismatch => Self::IdentityMismatch,
            Error::Rollback => Self::Rollback,
            Error::RosterForked => Self::RosterForked,
            Error::RosterUnauthorized => Self::RosterUnauthorized,
            Error::TooLarge => Self::TooLarge,
            Error::ReviewMismatch => Self::ReviewMismatch,
            other => Self::Invalid(other.to_string()),
        }
    }
}

type R<T> = Result<T, CoreError>;

fn json_in<T: serde::de::DeserializeOwned>(s: &str) -> R<T> {
    serde_json::from_str(s).map_err(|e| CoreError::Invalid(format!("invalid input: {e}")))
}

fn json_out<T: serde::Serialize>(v: &T) -> R<String> {
    serde_json::to_string(v).map_err(|e| CoreError::Invalid(e.to_string()))
}

// ------------------------------------------------------------------ handles

#[derive(uniffi::Object)]
pub struct MasterKeys(CoreMaster);

#[uniffi::export]
impl MasterKeys {
    /// Decrypt the account bundle (JSON) returned by the server after sign-in.
    pub fn unlock(&self, bundle_json: String) -> R<Arc<Account>> {
        let bundle: AccountBundle = json_in(&bundle_json)?;
        Ok(Arc::new(Account(bundle.unlock(&self.0.auk)?)))
    }
}

#[derive(uniffi::Object)]
pub struct Account(UnlockedAccount);

#[uniffi::export]
impl Account {
    pub fn public_key(&self) -> String {
        b64(&self.0.keypair.public_bytes())
    }

    pub fn fingerprint(&self) -> String {
        key_fingerprint(&self.0.keypair.public_bytes())
    }

    pub fn new_vault_key(&self, vault_id: String) -> R<NewVaultKey> {
        let (key, wrapped) = self.0.new_vault_key(&vault_id)?;
        Ok(NewVaultKey {
            key: Arc::new(VaultKey(key)),
            wrapped,
        })
    }

    /// A new vault key and its epoch-bound v2 `account` wrap at `key_epoch` (0 for a new
    /// vault): when `/sync` `user.account_wraps_v2` is true; else `new_vault_key` (v1).
    pub fn new_vault_key_bound(&self, vault_id: String, key_epoch: u64) -> R<NewVaultKey> {
        let (key, wrapped) = self.0.new_vault_key_bound(&vault_id, key_epoch)?;
        Ok(NewVaultKey {
            key: Arc::new(VaultKey(key)),
            wrapped,
        })
    }

    /// `kind` is the membership's `key_kind`: "account" (own vault) or "sealed" (shared to
    /// us). `key_epoch` = the row's `key_epoch`: an epoch-bound v2 `account` wrap opens
    /// only for it; a v1 wrap only with `legacy_allowed` (`pins_legacy_wrap_allowed(pins,
    /// vault_id, key_epoch)`). Both are ignored for "sealed". After a v2 wrap opened
    /// (`account_wrap_is_bound(wrapped)`), observe the row with `bound_wrap: true`.
    pub fn open_vault_key(
        &self,
        vault_id: String,
        wrapped: String,
        kind: String,
        key_epoch: u64,
        legacy_allowed: bool,
    ) -> R<Arc<VaultKey>> {
        let key = match kind.as_str() {
            "sealed" => self.0.open_shared_vault_key(&vault_id, &wrapped)?,
            _ => self
                .0
                .open_vault_key(&vault_id, key_epoch, &wrapped, legacy_allowed)?,
        };
        Ok(Arc::new(VaultKey(key)))
    }

    /// The unlocked keys (64 bytes) so the app can keep them protected by the
    /// Android Keystore / iOS Keychain (biometric unlock). Never store them unprotected.
    pub fn to_session_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(self.0.account_key.as_bytes());
        out.extend_from_slice(&self.0.keypair.secret_bytes());
        out
    }

    /// Whether `bundle_json` (the server's account bundle) is this account's own: its
    /// `account_id` is this account's and its private-key blob opens under this Account
    /// Key (associated data bound to that id) to this account's private key. Only the
    /// Account Key's holder can make that, so `true` authenticates the bundle's account id.
    /// After `account_from_session_bytes(stored bundle's account_id, bytes)` refuse the
    /// session (ask for the master password) unless this is true; never store a `/sync`
    /// or background-refresh bundle for which it is false. Malformed bundles are false.
    pub fn matches_bundle(&self, bundle_json: String) -> bool {
        json_in::<AccountBundle>(&bundle_json).is_ok_and(|b| self.0.matches_bundle(&b))
    }

    /// New master password and/or Secret Key setting (see the web vault).
    pub fn rewrap(
        &self,
        bundle_json: String,
        new_password: String,
        with_secret_key: bool,
        existing_secret_key: Option<String>,
    ) -> R<NewAccount> {
        let bundle: AccountBundle = json_in(&bundle_json)?;
        NewAccount::try_from(bundle.rewrap(
            &self.0,
            &new_password,
            with_secret_key,
            existing_secret_key.as_deref(),
        )?)
    }

    /// `rewrap` following a server's KDF policy: memory = max(128 MiB,
    /// `min_memory_mib`), passes = max(3, `min_iterations`) — the policy's
    /// `min_kdf_memory_mib` / `min_kdf_iterations`, or `None`. A minimum outside
    /// 64–1024 MiB or 3–20 passes fails. Also fixes a `kdf` policy violation.
    pub fn rewrap_with_kdf(
        &self,
        bundle_json: String,
        new_password: String,
        with_secret_key: bool,
        existing_secret_key: Option<String>,
        min_memory_mib: Option<u32>,
        min_iterations: Option<u32>,
    ) -> R<NewAccount> {
        let bundle: AccountBundle = json_in(&bundle_json)?;
        let kdf = KdfParams::with_minimums(min_memory_mib, min_iterations)?;
        NewAccount::try_from(bundle.rewrap_with_kdf(
            &self.0,
            &new_password,
            with_secret_key,
            existing_secret_key.as_deref(),
            kdf,
        )?)
    }

    /// Wrap a Send's key (from `send_new_key`) for this account: the Send's `owner_key`.
    pub fn wrap_send_key(&self, key: String) -> R<String> {
        Ok(self.0.wrap_send_key(&SendKey::from_b64(&key)?)?)
    }

    /// The send key (base64url, for the link's fragment) from a Send's `owner_key`.
    pub fn unwrap_send_key(&self, wrapped: String) -> R<String> {
        Ok(self.0.unwrap_send_key(&wrapped)?.to_b64())
    }

    /// Wrap a v2 Send's content key (`send_password_keys(…).content_key`) for this
    /// account: the Send's `owner_content_key`.
    pub fn wrap_send_content_key(&self, content_key: String) -> R<String> {
        Ok(self
            .0
            .wrap_send_content_key(&SendContentKey::from_b64(&content_key)?)?)
    }

    /// A v2 Send's content key (base64url, for `send_encrypt_v2` / `send_open`) from its
    /// `owner_content_key`.
    pub fn unwrap_send_content_key(&self, wrapped: String) -> R<String> {
        Ok(self.0.unwrap_send_content_key(&wrapped)?.to_b64())
    }

    /// Emergency access, the grantor's side, when confirming contact `grant_id` (the
    /// access's id): a new emergency key and it wrapped with this account's key
    /// (`wrapped`, the access's `grantor_key`).
    pub fn new_emergency_key(&self, grant_id: String) -> R<NewEmergencyKey> {
        let new = self.0.new_emergency_key(&grant_id)?;
        Ok(NewEmergencyKey {
            key: Arc::new(EmergencyKey(new.key)),
            wrapped: new.wrapped,
        })
    }

    /// The emergency key of this account's access `grant_id` again, from its
    /// `grantor_key`. `DecryptFailed` for another account's or access's key.
    pub fn open_emergency_key(&self, grant_id: String, wrapped: String) -> R<Arc<EmergencyKey>> {
        Ok(Arc::new(EmergencyKey(
            self.0.open_emergency_key(&grant_id, &wrapped)?,
        )))
    }

    /// Emergency access: seal this account's roster of emergency contacts (JSON of the
    /// app's own) with its key: the server keeps it but can neither read nor change it.
    pub fn seal_emergency_roster(&self, json: String) -> R<String> {
        Ok(self.0.seal_emergency_roster(&json)?)
    }

    /// The roster's JSON from what `seal_emergency_roster` made. `DecryptFailed` for
    /// another account's roster or a changed one.
    pub fn open_emergency_roster(&self, sealed: String) -> R<String> {
        Ok(self.0.open_emergency_roster(&sealed)?)
    }

    /// Seal the account's profile picture (image bytes, ≤ 256 KiB; the apps send a
    /// small square JPEG) with its key, for `PUT /api/account/avatar`.
    pub fn seal_avatar(&self, image: Vec<u8>) -> R<String> {
        Ok(self.0.seal_avatar(&image)?)
    }

    /// The image bytes from what `seal_avatar` made. `DecryptFailed` for another
    /// account's picture or a changed one.
    pub fn open_avatar(&self, sealed: String) -> R<Vec<u8>> {
        Ok(self.0.open_avatar(&sealed)?)
    }

    /// Emergency access, the contact's side: open the `sealed_key` that account
    /// `grantor_id` (the access's `grantor.id`) sealed to this account for access
    /// `grant_id`. `DecryptFailed` if it isn't for this account, that grantor or that
    /// access.
    pub fn open_sealed_emergency_key(
        &self,
        grantor_id: String,
        grant_id: String,
        sealed: String,
    ) -> R<Arc<EmergencyKey>> {
        Ok(Arc::new(EmergencyKey(self.0.open_sealed_emergency_key(
            &grantor_id,
            &grant_id,
            &sealed,
        )?)))
    }

    /// Approve a sign-in request from another device, after the user picked, among
    /// `login_phrase_choices(requester_public_key, n)`, `chosen_phrase` as the words the
    /// new device shows. `sealed` is the request's `sealed_key` (this account's key, and the
    /// Secret Key when `secret_key` is given, sealed to the request's public key); show
    /// `code` (6 digits) for the user to enter on the new device. `PhraseMismatch` unless
    /// `chosen_phrase` is exactly `login_phrase(requester_public_key)`; fails for a
    /// malformed or low-order key.
    pub fn approve_login_request(
        &self,
        requester_public_key: String,
        request_id: String,
        chosen_phrase: String,
        secret_key: Option<String>,
    ) -> R<LoginApproval> {
        let approval = self.0.approve_login_request(
            &requester_public_key,
            &request_id,
            &chosen_phrase,
            secret_key.as_deref(),
        )?;
        Ok(LoginApproval {
            sealed: approval.sealed,
            code: approval.code,
        })
    }

    /// The `proof` for approving request `request_id`: its `challenge`, opened with this
    /// account's private key (base64url).
    pub fn open_login_challenge(&self, challenge: String, request_id: String) -> R<String> {
        Ok(self.0.open_login_challenge(&challenge, &request_id)?)
    }
}

/// A new device's key pair for one sign-in request (its private half never leaves Rust).
#[derive(uniffi::Object)]
pub struct LoginRequestKey(device_login::LoginRequestKey);

#[uniffi::export]
impl LoginRequestKey {
    #[uniffi::constructor]
    pub fn generate() -> R<Arc<Self>> {
        Ok(Arc::new(Self(device_login::LoginRequestKey::generate()?)))
    }

    /// The request's `public_key` (base64url).
    pub fn public_key(&self) -> String {
        self.0.public_key()
    }

    /// The words this device shows (`login_phrase` of its own public key).
    pub fn phrase(&self) -> String {
        self.0.phrase()
    }

    /// Open the approved request's `sealed_key` for account `account_id` (the sign-in's
    /// `user_id`). Fails if it was sealed to another key, account or request, or changed.
    /// What opens is usable only after `confirm(code)`.
    pub fn open(
        &self,
        sealed: String,
        account_id: String,
        request_id: String,
    ) -> R<Arc<ApprovedLogin>> {
        let approved = self.0.open(&sealed, &account_id, &request_id)?;
        Ok(Arc::new(ApprovedLogin {
            account_id,
            state: Mutex::new(approved),
        }))
    }
}

/// `Account.approve_login_request`'s answer.
#[derive(uniffi::Record)]
pub struct LoginApproval {
    /// The request's `sealed_key` (base64url) for the server.
    pub sealed: String,
    /// The 6-digit code to show: the new device can't use the approval without it.
    pub code: String,
}

/// An approved sign-in: the Account Key (it stays in Rust) and maybe the Secret Key, both
/// held back until `confirm` accepted the code the approving app shows.
#[derive(uniffi::Object)]
pub struct ApprovedLogin {
    account_id: String,
    /// `confirm` changes it (a counter, then confirmed or refused).
    state: Mutex<device_login::ApprovedLogin>,
}

impl ApprovedLogin {
    fn state(&self) -> R<std::sync::MutexGuard<'_, device_login::ApprovedLogin>> {
        self.state
            .lock()
            .map_err(|_| CoreError::Invalid("sign-in unusable after a panic".into()))
    }
}

#[uniffi::export]
impl ApprovedLogin {
    pub fn account_id(&self) -> String {
        self.account_id.clone()
    }

    /// Check the code the approving app shows (6 digits; spaces and hyphens are ignored).
    /// `WrongCode` (see `attempts_left`), `TooManyWrongCodes` on the third wrong code and
    /// for good after it (start a new request), `Invalid` for anything but 6 digits (not
    /// counted).
    pub fn confirm(&self, code: String) -> R<()> {
        Ok(self.state()?.confirm(&code)?)
    }

    /// Whether `confirm` accepted the code.
    pub fn is_confirmed(&self) -> bool {
        self.state.lock().is_ok_and(|s| s.is_confirmed())
    }

    /// Wrong codes `confirm` still takes (0 once refused).
    pub fn attempts_left(&self) -> u32 {
        self.state.lock().map_or(0, |s| s.attempts_left())
    }

    /// The Secret Key (`PA1-…`) when the approving app included it; keep it like one the
    /// user typed, for unlocking with the master password later. `NotConfirmed` until
    /// `confirm` accepted the code.
    pub fn secret_key(&self) -> R<Option<String>> {
        Ok(self.state()?.secret_key()?)
    }

    /// Unlock the account bundle (JSON) the sign-in returned, without the master password.
    /// `NotConfirmed` until `confirm` accepted the code.
    pub fn unlock(&self, bundle_json: String) -> R<Arc<Account>> {
        let bundle: AccountBundle = json_in(&bundle_json)?;
        Ok(Arc::new(Account(self.state()?.unlock(&bundle)?)))
    }
}

/// Emergency access: the key of one access (one emergency contact). It opens only
/// the personal vault keys the grantor wrapped with it; the key itself never leaves
/// Rust. The sealed box the contact gets is anonymous, so a server could hand out one
/// of its own making: show what it opens read-only and never autofill it.
#[derive(uniffi::Object)]
pub struct EmergencyKey(CoreEmergencyKey);

#[uniffi::export]
impl EmergencyKey {
    pub fn grantor_id(&self) -> String {
        self.0.grantor_id().to_owned()
    }

    /// The access this key belongs to.
    pub fn grant_id(&self) -> String {
        self.0.grant_id().to_owned()
    }

    /// Seal this key to the contact's public key (check their fingerprint first): the
    /// access's `sealed_key`. Only a key from `Account.new_emergency_key` can be sealed;
    /// fails for a malformed or low-order key, and for a `grantor_id` or `grant_id`
    /// other than the key's own.
    pub fn seal_for(
        &self,
        contact_public_key: String,
        grantor_id: String,
        grant_id: String,
    ) -> R<String> {
        Ok(self
            .0
            .seal_for(&contact_public_key, &grantor_id, &grant_id)?)
    }

    /// Wrap personal vault `vault_id`'s key for this key's access.
    pub fn wrap_vault_key(&self, vault_key: Arc<VaultKey>, vault_id: String) -> R<String> {
        Ok(self.0.wrap_vault_key(&vault_key.0, &vault_id)?)
    }

    /// Open a vault key wrapped for vault `vault_id` and this key's access.
    pub fn open_vault_key(&self, vault_id: String, wrapped: String) -> R<Arc<VaultKey>> {
        Ok(Arc::new(VaultKey(
            self.0.open_vault_key(&vault_id, &wrapped)?,
        )))
    }
}

fn stream_lock<T>(m: &Mutex<T>) -> R<std::sync::MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| CoreError::Invalid("file stream unusable after a panic".into()))
}

/// Encrypts one attachment file in pieces. The file is every output of `push` and
/// `finish`, concatenated in order.
#[derive(uniffi::Object)]
pub struct FileEncryptor(Mutex<file::FileEncryptor>);

#[uniffi::export]
impl FileEncryptor {
    /// `key` from `file_new_key`; the item's id and the attachment's id as stored.
    #[uniffi::constructor]
    pub fn new(key: String, item_id: String, attachment_id: String) -> R<Arc<Self>> {
        let key = FileKey::from_b64(&key)?;
        let enc = file::FileEncryptor::new(&key, &item_id, &attachment_id)?;
        Ok(Arc::new(Self(Mutex::new(enc))))
    }

    /// More plaintext (any size). Returns the ciphertext ready so far (may be empty).
    pub fn push(&self, chunk: Vec<u8>) -> R<Vec<u8>> {
        Ok(stream_lock(&self.0)?.push(&chunk)?)
    }

    /// The rest of the ciphertext. The encryptor can't be used afterwards.
    pub fn finish(&self) -> R<Vec<u8>> {
        Ok(stream_lock(&self.0)?.finish()?)
    }
}

/// Decrypts one attachment file in pieces. Each output of `push` is authenticated
/// plaintext, in order; only a successful `finish` means the file is complete: on
/// any error (`DecryptFailed`), discard everything written so far.
#[derive(uniffi::Object)]
pub struct FileDecryptor(Mutex<file::FileDecryptor>);

#[uniffi::export]
impl FileDecryptor {
    #[uniffi::constructor]
    pub fn new(key: String, item_id: String, attachment_id: String) -> R<Arc<Self>> {
        let key = FileKey::from_b64(&key)?;
        let dec = file::FileDecryptor::new(&key, &item_id, &attachment_id)?;
        Ok(Arc::new(Self(Mutex::new(dec))))
    }

    /// More ciphertext (any size). Returns the plaintext ready so far (may be empty).
    pub fn push(&self, chunk: Vec<u8>) -> R<Vec<u8>> {
        Ok(stream_lock(&self.0)?.push(&chunk)?)
    }

    /// The last piece of plaintext; `DecryptFailed` if the file was cut short.
    pub fn finish(&self) -> R<Vec<u8>> {
        Ok(stream_lock(&self.0)?.finish()?)
    }
}

#[derive(uniffi::Object)]
pub struct VaultKey(SymmetricKey);

#[uniffi::export]
impl VaultKey {
    pub fn encrypt_item(
        &self,
        item_json: String,
        id: String,
        vault_id: String,
    ) -> R<EncryptedItem> {
        let item: Item = json_in(&item_json)?;
        Ok(CoreEncrypted::encrypt(&item, &id, &vault_id, &self.0)?.into())
    }

    /// Re-encrypt an edited item, keeping its Item Key. Its edit counter (`rev`) becomes
    /// one more than the higher of the stored item's and the given item's (restoring an
    /// earlier version counts up from the current one). `encrypt_item` writes the given
    /// item's `rev` + 1 (1 for a new item; pass the decrypted item, with its `rev`, when
    /// moving or re-keying).
    pub fn update_item(&self, encrypted: EncryptedItem, item_json: String) -> R<EncryptedItem> {
        let item: Item = json_in(&item_json)?;
        Ok(CoreEncrypted::from(encrypted)
            .update(&item, &self.0)?
            .into())
    }

    /// Item JSON (upgraded to the current item format).
    pub fn decrypt_item(&self, encrypted: EncryptedItem) -> R<String> {
        json_out(&CoreEncrypted::from(encrypted).decrypt(&self.0)?)
    }

    pub fn encrypt_meta(&self, vault_id: String, meta_json: String) -> R<String> {
        let v: serde_json::Value = json_in(&meta_json)?;
        let bytes = serde_json::to_vec(&v).map_err(|e| CoreError::Invalid(e.to_string()))?;
        Ok(keys::encrypt_vault_meta(&self.0, &vault_id, &bytes)?)
    }

    pub fn decrypt_meta(&self, vault_id: String, meta: String) -> R<String> {
        let bytes = keys::decrypt_vault_meta(&self.0, &vault_id, &meta)?;
        String::from_utf8(bytes)
            .map_err(|_| CoreError::Invalid("vault metadata is not UTF-8".into()))
    }

    /// Check this vault against its manifest after applying a sync answer. `status`:
    /// "none" (no manifest, none seen before), "ok" (remember `version` and `link`),
    /// "rollback" (a lower version than remembered, or none after one was seen),
    /// "mismatch" (the manifest doesn't open, the items aren't what it records, or it
    /// isn't on the history this device saw), "incomplete" (an item has neither `data`
    /// nor `data_sha256`: fetch the vault in full once) or "need_log" (fetch the vault's
    /// manifest log after the remembered version and call again with it as `log_json`).
    /// `manifest_seq`, `prev` and `sealed` are the vault row's `manifest_seq`,
    /// `manifest_prev` and `manifest` (0 / nil = none); `remembered_version` and
    /// `remembered_link` what this device stored for the vault (both or neither;
    /// a link of 32 zero bytes is no memory and throws); `log_json` a JSON array of the
    /// log's entries (`seq`, `prev`, `digest`) as the server sent them, nil when none
    /// was fetched (an entry that isn't such an object is skipped, it never makes the
    /// call throw; text that is no JSON array does); `items_json` a JSON array of every
    /// item row of the vault as synced (`id`, `deleted_at`, `data` or `data_sha256`;
    /// other fields are ignored). "need_log" only comes for a manifest two or more
    /// versions ahead of the remembered one.
    #[allow(clippy::too_many_arguments)]
    pub fn manifest_verify(
        &self,
        vault_id: String,
        key_epoch: u64,
        manifest_seq: u64,
        prev: Option<String>,
        sealed: Option<String>,
        remembered_version: Option<u64>,
        remembered_link: Option<String>,
        log_json: Option<String>,
        items_json: String,
    ) -> R<ManifestCheck> {
        let items: Vec<manifest::Entry> = json_in(&items_json)?;
        let log: Option<Vec<manifest::LogEntry>> = log_json.as_deref().map(json_in).transpose()?;
        let remembered = match (remembered_version, remembered_link) {
            (None, None) => None,
            (Some(version), Some(link)) => Some(manifest::Seen::parse(version, &link)?),
            _ => {
                return Err(CoreError::Invalid(
                    "invalid input: a remembered manifest is a version and a link".into(),
                ));
            }
        };
        let check = manifest::verify(
            &self.0,
            &vault_id,
            key_epoch,
            manifest::Row {
                seq: manifest_seq,
                prev: prev.as_deref(),
                sealed: sealed.as_deref(),
            },
            remembered.as_ref(),
            log.as_deref(),
            &items,
        )?;
        ManifestCheck::from_core(check)
    }

    /// The check behind "Use the server's copy": this vault as the sync answer shows it
    /// (`manifest_seq`, `prev`, `sealed` = the row's `manifest_seq`, `manifest_prev`,
    /// `manifest`; `items_json` every item row of the vault), judged with nothing
    /// remembered. "ok" = the served manifest records exactly these items: on the
    /// user's confirmation replace this device's memory for the vault with `version`
    /// and `link`, whatever it held; "none" = the server shows no manifest: forget the
    /// vault's memory (`version` 0, `link` nil); "mismatch" / "incomplete" = nothing may
    /// be remembered (a member who can write stores a baseline: `manifest_start` one
    /// version above the row, naming `manifest_link` of it).
    pub fn manifest_accept(
        &self,
        vault_id: String,
        key_epoch: u64,
        manifest_seq: u64,
        prev: Option<String>,
        sealed: Option<String>,
        items_json: String,
    ) -> R<ManifestCheck> {
        let items: Vec<manifest::Entry> = json_in(&items_json)?;
        let check = manifest::accept(
            &self.0,
            &vault_id,
            key_epoch,
            manifest::Row {
                seq: manifest_seq,
                prev: prev.as_deref(),
                sealed: sealed.as_deref(),
            },
            &items,
        )?;
        ManifestCheck::from_core(check)
    }

    /// A manifest of `version` for exactly the items in `items_json` (every item row of
    /// the vault, each with `data` or `data_sha256`), replacing the manifest whose link
    /// is `prev`: nil for a vault's first manifest; for a new baseline and for the one
    /// a key replacement carries (called on the new key with the new `key_epoch` and
    /// the re-encrypted items), `manifest_link` of the vault row's current manifest,
    /// with `version` = the row's `manifest_seq` + 1 (the server takes nothing else).
    pub fn manifest_start(
        &self,
        vault_id: String,
        key_epoch: u64,
        version: u64,
        prev: Option<String>,
        items_json: String,
    ) -> R<ManifestWrite> {
        let items: Vec<manifest::Entry> = json_in(&items_json)?;
        Ok(manifest::start(
            &self.0,
            &vault_id,
            key_epoch,
            version,
            prev.as_deref(),
            &items,
        )?
        .into())
    }

    /// What to send with a write into this vault: the manifest after it, one version
    /// above the row's `manifest_seq` / `manifest_prev` (`prev`) / `manifest` (`sealed`)
    /// and naming it as its predecessor. `removed_json`: the items as they were before
    /// the write (edited, trashed, restored, deleted, moved out); `added_json`: as they
    /// are after it (new, edited, trashed, restored, moved in). Only for a vault whose
    /// last `manifest_verify` was "ok".
    #[allow(clippy::too_many_arguments)]
    pub fn manifest_next(
        &self,
        vault_id: String,
        key_epoch: u64,
        manifest_seq: u64,
        prev: String,
        sealed: String,
        removed_json: String,
        added_json: String,
    ) -> R<ManifestWrite> {
        let removed: Vec<manifest::Entry> = json_in(&removed_json)?;
        let added: Vec<manifest::Entry> = json_in(&added_json)?;
        Ok(manifest::advance(
            &self.0,
            &vault_id,
            key_epoch,
            manifest::Row {
                seq: manifest_seq,
                prev: Some(&prev),
                sealed: Some(&sealed),
            },
            &removed,
            &added,
        )?
        .into())
    }
}

/// `VaultKey::manifest_verify`'s verdict, and `manifest_accept`'s.
#[derive(uniffi::Record)]
pub struct ManifestCheck {
    /// "none" | "ok" | "rollback" | "mismatch" | "incomplete" | "need_log".
    pub status: String,
    /// The version to remember from now on (0 = none): the served one for "ok",
    /// otherwise the remembered one unchanged.
    pub version: u64,
    /// The link to remember with it (nil = none).
    pub link: Option<String>,
    /// The manifest's counts when it opened (0 otherwise).
    pub live: u64,
    pub trashed: u64,
}

impl ManifestCheck {
    fn from_core(check: manifest::Check) -> R<Self> {
        Ok(Self {
            status: sharing::enum_name(&check.status)?,
            version: check.version,
            link: check.link,
            live: check.live,
            trashed: check.trashed,
        })
    }
}

/// `VaultKey::manifest_next`'s and `manifest_start`'s result: `seq`, `prev` and
/// `sealed` go into the request; `seq` and `link` are what the device remembers once
/// the server stored it.
#[derive(uniffi::Record)]
pub struct ManifestWrite {
    pub seq: u64,
    pub prev: String,
    pub sealed: String,
    pub link: String,
}

impl From<manifest::Written> for ManifestWrite {
    fn from(w: manifest::Written) -> Self {
        Self {
            seq: w.seq,
            prev: w.prev,
            sealed: w.sealed,
            link: w.link,
        }
    }
}

/// The link (base64url) of a vault row's manifest (`manifest_seq`, `manifest_prev`,
/// `manifest`): what a new baseline or a key replacement's manifest names as `prev`.
/// Nothing is opened or checked.
#[uniffi::export]
pub fn manifest_link(manifest_seq: u64, prev: String, sealed: String) -> R<String> {
    Ok(manifest::row_link(manifest_seq, &prev, &sealed)?)
}

/// base64url SHA-256 of an item's `data` string as stored: what the server sends as
/// `data_sha256` for a row without `data`. Keep it when dropping a trashed row's data.
#[uniffi::export]
pub fn manifest_data_hash(data: String) -> String {
    b64(&manifest::data_hash(&data))
}

/// An encrypted item as the server API sends and receives it.
#[derive(uniffi::Record)]
pub struct EncryptedItem {
    pub id: String,
    pub vault_id: String,
    /// Item Key wrapped by the Vault Key.
    pub key: String,
    pub data: String,
}

impl From<CoreEncrypted> for EncryptedItem {
    fn from(e: CoreEncrypted) -> Self {
        Self {
            id: e.id,
            vault_id: e.vault_id,
            key: e.key,
            data: e.data,
        }
    }
}

impl From<EncryptedItem> for CoreEncrypted {
    fn from(e: EncryptedItem) -> Self {
        Self {
            id: e.id,
            vault_id: e.vault_id,
            key: e.key,
            data: e.data,
        }
    }
}

#[derive(uniffi::Record)]
pub struct NewVaultKey {
    pub key: Arc<VaultKey>,
    pub wrapped: String,
}

/// `Account.new_emergency_key`'s answer: the key, and it wrapped with the account's
/// key (the access's `grantor_key`).
#[derive(uniffi::Record)]
pub struct NewEmergencyKey {
    pub key: Arc<EmergencyKey>,
    pub wrapped: String,
}

#[derive(uniffi::Record)]
pub struct NewAccount {
    pub bundle_json: String,
    /// Show once (Emergency Kit); `None` when the account has no Secret Key.
    pub secret_key: Option<String>,
    pub account: Arc<Account>,
    pub master: Arc<MasterKeys>,
}

impl TryFrom<CoreNew> for NewAccount {
    type Error = CoreError;
    fn try_from(n: CoreNew) -> R<Self> {
        Ok(Self {
            bundle_json: json_out(&n.bundle)?,
            secret_key: n.secret_key,
            account: Arc::new(Account(n.unlocked)),
            master: Arc::new(MasterKeys(n.master)),
        })
    }
}

#[derive(uniffi::Record)]
pub struct OpaqueStart {
    pub state: Vec<u8>,
    pub message: String,
}

#[derive(uniffi::Record)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

#[derive(uniffi::Record)]
pub struct NewPasskey {
    pub credential_id: Vec<u8>,
    /// PKCS#8 DER; store base64url-encoded as the passkey's `private_key`.
    pub private_key_pkcs8: Vec<u8>,
    pub public_key_spki: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct PasskeyAssertion {
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature.
    pub signature: Vec<u8>,
}

// --------------------------------------------------------------- functions

/// The words both screens show for a sign-in request's public key (base64url): five
/// words of the EFF large wordlist. Work it out from the key you hold, never take the
/// server's `fingerprint_phrase`.
#[uniffi::export]
pub fn login_phrase(public_key: String) -> R<String> {
    Ok(device_login::login_phrase(&public_key)?)
}

/// `count` (2–5) phrases for the approving app to offer, in random order: exactly one is
/// `login_phrase(public_key)`, the others are decoys sharing no word with it at the same
/// position. Offer them with "none of these"; pass the one the user picks to
/// `Account.approve_login_request`.
#[uniffi::export]
pub fn login_phrase_choices(public_key: String, count: u32) -> R<Vec<String>> {
    Ok(device_login::login_phrase_choices(
        &public_key,
        count as usize,
    )?)
}

/// Restore an unlocked account from [`Account::to_session_bytes`].
#[uniffi::export]
pub fn account_from_session_bytes(account_id: String, bytes: Vec<u8>) -> R<Arc<Account>> {
    if bytes.len() != 64 {
        return Err(CoreError::Invalid("invalid session data".into()));
    }
    let account_key = SymmetricKey::from_slice(&bytes[..32])?;
    let secret: [u8; 32] = bytes[32..].try_into().expect("checked length");
    Ok(Arc::new(Account(UnlockedAccount {
        account_id,
        account_key,
        keypair: KeyPair::from_secret_bytes(secret),
    })))
}

#[uniffi::export]
pub fn create_account(
    account_id: String,
    password: String,
    with_secret_key: bool,
) -> R<NewAccount> {
    NewAccount::try_from(AccountBundle::create(
        &account_id,
        &password,
        with_secret_key,
    )?)
}

/// `create_account` following a server's KDF policy: memory = max(128 MiB,
/// `min_memory_mib`), passes = max(3, `min_iterations`) — `/api/config`
/// `policies.min_kdf_memory_mib` / `min_kdf_iterations`, or `None`. A minimum
/// outside 64–1024 MiB or 3–20 passes fails.
#[uniffi::export]
pub fn create_account_with_kdf(
    account_id: String,
    password: String,
    with_secret_key: bool,
    min_memory_mib: Option<u32>,
    min_iterations: Option<u32>,
) -> R<NewAccount> {
    let kdf = KdfParams::with_minimums(min_memory_mib, min_iterations)?;
    NewAccount::try_from(AccountBundle::create_with_kdf(
        &account_id,
        &password,
        with_secret_key,
        kdf,
    )?)
}

/// A new random send key: base64url of 32 bytes, for the link's fragment
/// (`/send/<id>#<key>`). Keep it only there and wrapped (`Account.wrap_send_key`).
#[uniffi::export]
pub fn send_new_key() -> R<String> {
    Ok(SendKey::generate()?.to_b64())
}

/// Encrypt a Send's `field` ("name" or "data"); returns the string the API takes.
#[uniffi::export]
pub fn send_encrypt(key: String, field: String, plaintext: String) -> R<String> {
    let key = SendKey::from_b64(&key)?;
    Ok(key.encrypt(SendField::parse(&field)?, plaintext.as_bytes())?)
}

/// Decrypt a Send's `field`; needs no account. `DecryptFailed` for a wrong key,
/// the other field or tampered data.
#[uniffi::export]
pub fn send_decrypt(key: String, field: String, ciphertext: String) -> R<String> {
    let key = SendKey::from_b64(&key)?;
    let bytes = key.decrypt(SendField::parse(&field)?, &ciphertext)?;
    String::from_utf8(bytes).map_err(|_| CoreError::Invalid("send text is not UTF-8".into()))
}

/// Encrypt a v2 Send's `field` ("name" or "data") with its content key
/// (`send_password_keys(…).content_key` or `Account.unwrap_send_content_key`): for Sends
/// with a password on servers with `send_v2`.
#[uniffi::export]
pub fn send_encrypt_v2(content_key: String, field: String, plaintext: String) -> R<String> {
    let key = SendContentKey::from_b64(&content_key)?;
    Ok(key.encrypt(SendField::parse(&field)?, plaintext.as_bytes())?)
}

/// Decrypt a Send's `field` of either format: v1 with the link's send `key`, v2 with
/// `content_key` (`PasswordRequired` when it is a v2 field and `content_key` is nil).
#[uniffi::export]
pub fn send_open(
    key: String,
    content_key: Option<String>,
    field: String,
    ciphertext: String,
) -> R<String> {
    let key = SendKey::from_b64(&key)?;
    let content = content_key
        .map(|c| SendContentKey::from_b64(&c))
        .transpose()?;
    let bytes = send::open_field(
        &key,
        content.as_ref(),
        SendField::parse(&field)?,
        &ciphertext,
    )?;
    String::from_utf8(bytes).map_err(|_| CoreError::Invalid("send text is not UTF-8".into()))
}

/// 1 or 2: the format of a Send's `name` or `data` (2 = encrypted with the password too).
#[uniffi::export]
pub fn send_field_version(ciphertext: String) -> R<u8> {
    Ok(send::field_version(&ciphertext)?)
}

/// What a Send password gives (one Argon2id run, same bounds as `send_password_verifier`).
#[derive(uniffi::Record)]
pub struct SendPasswordKeys {
    /// `access_verifier` (also of v1 Sends).
    pub verifier: String,
    /// Opens a v2 Send's fields (`send_open`) and encrypts them (`send_encrypt_v2`).
    /// Memory only.
    pub content_key: String,
}

/// `{verifier, content_key}` for `password`, a Send's `access_salt` and the link's send
/// `key`.
#[uniffi::export]
pub fn send_password_keys(password: String, salt: String, key: String) -> R<SendPasswordKeys> {
    let key = SendKey::from_b64(&key)?;
    let secrets = send::password_secrets(&password, &salt)?;
    Ok(SendPasswordKeys {
        content_key: key.content_key(&secrets).to_b64(),
        verifier: secrets.verifier.clone(),
    })
}

/// "new" | "same" | "newer" | "rollback": an item's edit counter (`rev` of the decrypted
/// item the server sent now) against the highest this device remembers for it (nil:
/// none). Remember `served` for "new"/"newer"; "rollback" = the server sent an older
/// version of the item (keep the newer copy, warn, never remember the lower number).
#[uniffi::export]
pub fn item_rev_check(remembered: Option<u64>, served: u64) -> R<String> {
    sharing::enum_name(&passauth_core::item::item_rev_check(remembered, served))
}

/// Whether an `account` wrap is the epoch-bound v2 format (`0x02` first): after it opened,
/// observe the vault row with `bound_wrap: true`.
#[uniffi::export]
pub fn account_wrap_is_bound(wrapped: String) -> bool {
    keys::wrap_is_bound(&wrapped)
}

/// A new `access_salt` for a Send's password (Argon2id parameters + random salt).
#[uniffi::export]
pub fn send_password_salt() -> R<String> {
    Ok(send::new_password_salt()?)
}

/// The `access_verifier` for `password` and a Send's `access_salt` (owner when
/// setting the password, visitor when opening). Runs Argon2id (128 MiB by default);
/// `WeakKdf` / `KdfTooStrong` for a salt outside 64–256 MiB, 3–6 passes, 1–4 lanes.
#[uniffi::export]
pub fn send_password_verifier(password: String, salt: String) -> R<String> {
    Ok(send::password_verifier(&password, &salt)?)
}

/// A new random attachment key (base64url of 32 bytes) for the item's attachment list.
#[uniffi::export]
pub fn file_new_key() -> R<String> {
    Ok(FileKey::generate()?.to_b64())
}

/// The encrypted size of a file of `plain_length` bytes: the `size` for
/// `POST /items/{id}/attachments` and for the server's attachment size limit.
#[uniffi::export]
pub fn file_encrypted_size(plain_length: u64) -> R<u64> {
    Ok(file::encrypted_size(plain_length)?)
}

/// The file size behind an encrypted size (fails for a size no file encrypts to).
#[uniffi::export]
pub fn file_plain_size(encrypted_length: u64) -> R<u64> {
    Ok(file::plain_size(encrypted_length)?)
}

/// Encrypt a whole (small) file at once; use `FileEncryptor` for large ones.
#[uniffi::export]
pub fn file_encrypt(
    key: String,
    item_id: String,
    attachment_id: String,
    plaintext: Vec<u8>,
) -> R<Vec<u8>> {
    let key = FileKey::from_b64(&key)?;
    Ok(file::encrypt(&key, &item_id, &attachment_id, &plaintext)?)
}

/// Decrypt a whole (small) file at once; `DecryptFailed` unless it is whole and authentic.
#[uniffi::export]
pub fn file_decrypt(
    key: String,
    item_id: String,
    attachment_id: String,
    ciphertext: Vec<u8>,
) -> R<Vec<u8>> {
    let key = FileKey::from_b64(&key)?;
    Ok(file::decrypt(&key, &item_id, &attachment_id, &ciphertext)?)
}

/// Derive master keys from what prelogin returned (`kdf_json` is its `kdf` object).
#[uniffi::export]
pub fn derive_master_keys(
    password: String,
    secret_key: Option<String>,
    account_id: String,
    kdf_json: String,
    secret_key_required: bool,
) -> R<Arc<MasterKeys>> {
    let kdf: KdfParams = json_in(&kdf_json)?;
    Ok(Arc::new(MasterKeys(keys::derive_master_keys(
        &password,
        secret_key.as_deref(),
        &account_id,
        &kdf,
        secret_key_required,
    )?)))
}

#[uniffi::export]
pub fn opaque_register_start(master: Arc<MasterKeys>) -> R<OpaqueStart> {
    let s = opaque::register_start(&master.0.login)?;
    Ok(OpaqueStart {
        state: s.state,
        message: s.message,
    })
}

#[uniffi::export]
pub fn opaque_register_finish(
    state: Vec<u8>,
    master: Arc<MasterKeys>,
    response: String,
) -> R<String> {
    Ok(opaque::register_finish(&state, &master.0.login, &response)?)
}

#[uniffi::export]
pub fn opaque_login_start(master: Arc<MasterKeys>) -> R<OpaqueStart> {
    let s = opaque::login_start(&master.0.login)?;
    Ok(OpaqueStart {
        state: s.state,
        message: s.message,
    })
}

/// Fails with `DecryptFailed` when the password or Secret Key is wrong.
#[uniffi::export]
pub fn opaque_login_finish(state: Vec<u8>, master: Arc<MasterKeys>, response: String) -> R<String> {
    Ok(opaque::login_finish(&state, &master.0.login, &response)?)
}

/// Parse an export file from another password manager; returns the import result as JSON.
#[uniffi::export]
pub fn import_file(data: Vec<u8>, password: Option<String>) -> R<String> {
    json_out(&import::import(&data, password.as_deref())?)
}

#[uniffi::export]
pub fn totp_code(secret: String, unix_seconds: u64) -> R<TotpCode> {
    let t = totp::Totp::parse(&secret)?;
    Ok(TotpCode {
        code: t.generate(unix_seconds),
        remaining: t.remaining(unix_seconds),
        period: t.period,
    })
}

/// `options_json`: the web vault's generator options, or `None` for defaults.
#[uniffi::export]
pub fn generate_password(options_json: Option<String>) -> R<String> {
    let opts: generator::PasswordOptions = options_json
        .as_deref()
        .map(json_in)
        .transpose()?
        .unwrap_or_default();
    Ok(generator::password(&opts)?)
}

#[uniffi::export]
pub fn generate_passphrase(options_json: Option<String>) -> R<String> {
    let opts: generator::PassphraseOptions = options_json
        .as_deref()
        .map(json_in)
        .transpose()?
        .unwrap_or_default();
    Ok(generator::passphrase(&opts)?)
}

#[uniffi::export]
pub fn estimate_bits(password: String) -> f64 {
    generator::estimate_bits(&password)
}

/// Fingerprint of another member's public key (base64), for verifying shares.
#[uniffi::export]
pub fn fingerprint(public_key: String) -> R<String> {
    let pk: [u8; 32] = unb64(&public_key)?
        .try_into()
        .map_err(|_| CoreError::Invalid("invalid public key".into()))?;
    Ok(key_fingerprint(&pk))
}

#[uniffi::export]
pub fn new_id() -> R<String> {
    let mut b: [u8; 16] = random_bytes()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

/// Plaintext PassAuth JSON export of `items_json` (a JSON array of items).
#[uniffi::export]
pub fn export_vault_json(items_json: String) -> R<String> {
    let items: Vec<Item> = json_in(&items_json)?;
    Ok(export::json(&items)?)
}

/// Password-protected PassAuth JSON export (password: at least 10 characters).
#[uniffi::export]
pub fn export_vault_encrypted(items_json: String, password: String) -> R<String> {
    let items: Vec<Item> = json_in(&items_json)?;
    Ok(export::encrypted(&items, &password)?)
}

/// CSV export of logins and secure notes.
#[uniffi::export]
pub fn export_vault_csv(items_json: String) -> R<String> {
    let items: Vec<Item> = json_in(&items_json)?;
    Ok(export::csv(&items)?)
}

/// Create a discoverable ES256 passkey for `rp_id` (call after the user confirmed).
#[uniffi::export]
pub fn passkey_create(rp_id: String) -> R<NewPasskey> {
    let p = passkey::create(&rp_id)?;
    Ok(NewPasskey {
        credential_id: p.credential_id,
        private_key_pkcs8: p.private_key_pkcs8,
        public_key_spki: p.public_key_spki,
        authenticator_data: p.authenticator_data,
        attestation_object: p.attestation_object,
    })
}

/// Sign `authenticatorData || clientDataHash` with a stored passkey.
#[uniffi::export]
pub fn passkey_assert(
    private_key_pkcs8: Vec<u8>,
    rp_id: String,
    client_data_hash: Vec<u8>,
) -> R<PasskeyAssertion> {
    let a = passkey::assert(&private_key_pkcs8, &rp_id, &client_data_hash)?;
    Ok(PasskeyAssertion {
        authenticator_data: a.authenticator_data,
        signature: a.signature,
    })
}

/// clientDataJSON for requests from Android apps (which don't send a hash).
#[uniffi::export]
pub fn passkey_client_data_json(kind: String, challenge_b64url: String, origin: String) -> String {
    passkey::client_data_json(&kind, &challenge_b64url, &origin)
}

#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    passkey::sha256(&data)
}

// ------------------------------------------------------------------ sites (passauth_core::site)

/// A saved website for [`match_urls`].
#[derive(uniffi::Record)]
pub struct SavedUrl {
    pub url: String,
    /// "default", "domain", "host", "starts_with", "exact", "regex" or "never".
    pub match_type: String,
    /// The login is in the user's own vault (regular expressions count only then).
    pub allow_regex: bool,
}

/// A login that matches the page, for [`plan_save`].
#[derive(uniffi::Record)]
pub struct SaveCandidate {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    /// In a vault the user can edit.
    pub writable: bool,
    /// In the user's own vault, not one somebody shared with them.
    pub personal: bool,
    /// Name of the vault, shown when it is a shared one.
    #[uniffi(default)]
    pub vault: Option<String>,
}

/// A login offered under "Save in"; `vault` is set for one in a shared vault.
#[derive(uniffi::Record)]
pub struct SaveTarget {
    pub id: String,
    pub name: String,
    pub username: String,
    #[uniffi(default)]
    pub vault: Option<String>,
}

/// Which rule chose the login to update. Never apply an `Only` update without a prompt.
#[derive(uniffi::Enum)]
pub enum SaveReason {
    Same,
    Blank,
    Only,
}

/// What the save prompt offers ([`plan_save`]).
#[derive(uniffi::Enum)]
pub enum SavePlan {
    /// Nothing to offer: no password, or it is already saved.
    None,
    /// A new login, preselected; `targets` may be picked instead.
    Create { targets: Vec<SaveTarget> },
    /// Update `target` (always one of the user's own logins), preselected.
    Update {
        reason: SaveReason,
        target: String,
        targets: Vec<SaveTarget>,
    },
}

/// A login for [`passkey_save_targets`]: `urls` are its websites as saved.
#[derive(uniffi::Record)]
pub struct PasskeyLogin {
    pub id: String,
    pub name: String,
    pub username: String,
    pub urls: Vec<String>,
    pub writable: bool,
    pub personal: bool,
    #[uniffi(default)]
    pub vault: Option<String>,
}

/// A "Save in" choice for a new passkey; `preferred`: preselect it.
#[derive(uniffi::Record)]
pub struct PasskeyTarget {
    pub id: String,
    pub name: String,
    pub username: String,
    pub preferred: bool,
    #[uniffi(default)]
    pub vault: Option<String>,
}

/// A refused WebAuthn origin or RP ID: always a `SecurityError`; the message is the one the
/// page should see.
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum RpIdError {
    InvalidOrigin,
    InsecureOrigin,
    OriginNotDomain,
    InvalidRpId,
    NotRegistrableSuffix,
}

impl std::fmt::Display for RpIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(site::RpIdError::from(self).message())
    }
}

impl std::error::Error for RpIdError {}

impl From<&RpIdError> for site::RpIdError {
    fn from(e: &RpIdError) -> Self {
        match e {
            RpIdError::InvalidOrigin => Self::InvalidOrigin,
            RpIdError::InsecureOrigin => Self::InsecureOrigin,
            RpIdError::OriginNotDomain => Self::OriginNotDomain,
            RpIdError::InvalidRpId => Self::InvalidRpId,
            RpIdError::NotRegistrableSuffix => Self::NotRegistrableSuffix,
        }
    }
}

impl From<site::RpIdError> for RpIdError {
    fn from(e: site::RpIdError) -> Self {
        match e {
            site::RpIdError::InvalidOrigin => Self::InvalidOrigin,
            site::RpIdError::InsecureOrigin => Self::InsecureOrigin,
            site::RpIdError::OriginNotDomain => Self::OriginNotDomain,
            site::RpIdError::InvalidRpId => Self::InvalidRpId,
            site::RpIdError::NotRegistrableSuffix => Self::NotRegistrableSuffix,
        }
    }
}

fn site_target(t: site::SaveTarget) -> SaveTarget {
    SaveTarget {
        id: t.id,
        name: t.name,
        username: t.username,
        vault: t.vault,
    }
}

/// The user's "default match detection" setting; anything unknown counts as "domain".
fn default_match(s: &str) -> site::UrlMatch {
    site::parse_url_match(s).unwrap_or(site::UrlMatch::Domain)
}

/// Canonical host: IDNA to ASCII, lower case, IPv4/IPv6 normalised (IPv6 in brackets), no
/// trailing dot; `None` when it isn't a valid host.
#[uniffi::export]
pub fn normalize_host(host: String) -> Option<String> {
    site::normalize_host(&host)
}

/// Public suffix by the full list ("co.uk", "myfritz.net", "com"); "" for IP addresses and
/// invalid hosts.
#[uniffi::export]
pub fn public_suffix(host: String) -> String {
    site::public_suffix(&host)
}

/// Registrable domain ("example.co.uk", "nas.myfritz.net"); `None` for a public suffix itself,
/// IP addresses and invalid hosts.
#[uniffi::export]
pub fn registrable_domain(host: String) -> Option<String> {
    site::registrable_domain(&host)
}

/// The site "domain" matching compares: the registrable domain, else the host itself.
#[uniffi::export]
pub fn base_domain(host: String) -> String {
    site::base_domain(&host)
}

#[uniffi::export]
pub fn is_public_suffix(host: String) -> bool {
    site::is_public_suffix(&host)
}

/// "<date> <commit>" of the embedded Public Suffix List.
#[uniffi::export]
pub fn public_suffix_list_version() -> String {
    site::public_suffix_list_version()
}

/// Does the page match the saved website? `page` must be an absolute http(s) address. An
/// unknown `match_type` never matches; an unknown `default_match` counts as "domain" (with
/// "regex", "default" treats a plain address as "domain"); `allow_regex` is false for a
/// login in a shared vault.
#[uniffi::export]
pub fn matches_url(
    page: String,
    url: String,
    match_type: String,
    default_match: String,
    allow_regex: bool,
) -> bool {
    site::parse_url_match(&match_type).is_some_and(|m| {
        site::matches_url(
            &page,
            &url,
            m,
            self::default_match(&default_match),
            allow_regex,
        )
    })
}

/// What a saved website is matched as: `match_type` resolved with `default_match` (an unknown
/// one counts as "domain"; with "regex", "default" keeps a plain address as "domain"), never
/// "default"; "never" for an unknown `match_type`. An entry runs as a pattern exactly when
/// this is "regex": show `regex_error` and `regex_warning` for those.
#[uniffi::export]
pub fn resolve_match(url: String, match_type: String, default_match: String) -> String {
    site::parse_url_match(&match_type)
        .map_or(site::UrlMatch::Never, |m| {
            site::resolve_match(&url, m, self::default_match(&default_match))
        })
        .as_str()
        .to_owned()
}

/// [`matches_url`] for many saved websites against one page: one result per entry.
#[uniffi::export]
pub fn match_urls(page: String, default_match: String, urls: Vec<SavedUrl>) -> Vec<bool> {
    let page = site::Page::parse(&page);
    let fallback = self::default_match(&default_match);
    urls.iter()
        .map(|u| match (&page, site::parse_url_match(&u.match_type)) {
            (Some(p), Some(m)) => p.matches(&u.url, m, fallback, u.allow_regex),
            _ => false,
        })
        .collect()
}

/// True when filling would send a secret saved for an https site to an http page.
#[uniffi::export]
pub fn downgrade(page: String, url: String, match_type: String) -> bool {
    let m = site::parse_url_match(&match_type).unwrap_or(site::UrlMatch::Domain);
    site::downgrade(&page, &url, m)
}

/// Why a website pattern is refused (too long, too large, unsupported syntax such as
/// look-around), or `None` when it is evaluated.
#[uniffi::export]
pub fn regex_error(pattern: String) -> Option<String> {
    site::regex_error(&pattern)
}

/// Why an explicit website pattern can also match other websites (a warning for the item
/// editor: not anchored as `^https://<host>/`), or `None` when it pins its website or is
/// refused (`regex_error` says why then).
#[uniffi::export]
pub fn regex_warning(pattern: String) -> Option<String> {
    site::regex_warning(&pattern)
}

/// The save rule (docs/ARCHITECTURE.md "Save rule").
#[uniffi::export]
pub fn plan_save(candidates: Vec<SaveCandidate>, typed_user: String, password: String) -> SavePlan {
    let candidates: Vec<site::SaveCandidate> = candidates
        .into_iter()
        .map(|c| site::SaveCandidate {
            id: c.id,
            name: c.name,
            username: c.username,
            password: c.password,
            writable: c.writable,
            personal: c.personal,
            vault: c.vault,
        })
        .collect();
    let targets = |t: Vec<site::SaveTarget>| t.into_iter().map(site_target).collect();
    match site::plan_save(&candidates, &typed_user, &password) {
        site::SavePlan::None => SavePlan::None,
        site::SavePlan::Create { targets: t } => SavePlan::Create {
            targets: targets(t),
        },
        site::SavePlan::Update {
            reason,
            target,
            targets: t,
        } => SavePlan::Update {
            reason: match reason {
                site::SaveReason::Same => SaveReason::Same,
                site::SaveReason::Blank => SaveReason::Blank,
                site::SaveReason::Only => SaveReason::Only,
            },
            target,
            targets: targets(t),
        },
    }
}

/// The prompt's answer if the save offered it ("new" or one of `targets`), else `None`.
#[uniffi::export]
pub fn chosen_save_target(targets: Vec<SaveTarget>, answer: String) -> Option<String> {
    let targets: Vec<site::SaveTarget> = targets
        .into_iter()
        .map(|t| site::SaveTarget {
            id: t.id,
            name: t.name,
            username: t.username,
            vault: t.vault,
        })
        .collect();
    site::chosen_target(&targets, &answer)
}

/// Logins a new passkey can be saved in, best first.
#[uniffi::export]
pub fn passkey_save_targets(
    logins: Vec<PasskeyLogin>,
    host: String,
    rp_id: String,
    user_name: String,
    display_name: String,
) -> Vec<PasskeyTarget> {
    let logins: Vec<site::PasskeyLogin> = logins
        .into_iter()
        .map(|l| site::PasskeyLogin {
            id: l.id,
            name: l.name,
            username: l.username,
            urls: l.urls,
            writable: l.writable,
            personal: l.personal,
            vault: l.vault,
        })
        .collect();
    site::passkey_save_targets(&logins, &host, &rp_id, &user_name, &display_name)
        .into_iter()
        .map(|t| PasskeyTarget {
            id: t.id,
            name: t.name,
            username: t.username,
            preferred: t.preferred,
            vault: t.vault,
        })
        .collect()
}

/// The preselected "Save in" choice: the first preferred target's id, else "new".
#[uniffi::export]
pub fn passkey_default_target(targets: Vec<PasskeyTarget>) -> String {
    targets
        .into_iter()
        .find(|t| t.preferred)
        .map_or_else(|| site::NEW_LOGIN.to_owned(), |t| t.id)
}

/// The RP ID for a WebAuthn request from `origin` (the requested one if allowed, else the
/// origin's host).
#[uniffi::export]
pub fn effective_rp_id(
    requested_rp_id: Option<String>,
    origin: String,
) -> Result<String, RpIdError> {
    Ok(site::effective_rp_id(requested_rp_id.as_deref(), &origin)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_roundtrip_through_ffi_types() {
        let n = create_account(
            new_id().unwrap(),
            "correct horse battery staple".into(),
            false,
        )
        .unwrap();
        let account = &n.account;
        let vk = account.new_vault_key("vault-1".into()).unwrap();
        let item = r#"{"name":"GitHub","login":{"username":"octo","password":"s3cret","urls":[{"url":"https://github.com","match":"default"}]}}"#;
        let enc = vk
            .key
            .encrypt_item(item.into(), "item-1".into(), "vault-1".into())
            .unwrap();
        let reopened = account
            .open_vault_key(
                "vault-1".into(),
                vk.wrapped.clone(),
                "account".into(),
                0,
                true,
            )
            .unwrap();
        let json = reopened.decrypt_item(enc).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "GitHub");
        assert_eq!(v["login"]["password"], "s3cret");

        let restored =
            account_from_session_bytes(account.0.account_id.clone(), account.to_session_bytes())
                .unwrap();
        assert_eq!(restored.public_key(), account.public_key());
        // Restored under the stored bundle's id: it must match that bundle; under another
        // id (a bundle the server swapped in) it doesn't.
        assert!(restored.matches_bundle(n.bundle_json.clone()));
        let other_id =
            account_from_session_bytes(new_id().unwrap(), account.to_session_bytes()).unwrap();
        assert!(!other_id.matches_bundle(n.bundle_json.clone()));
        assert!(!restored.matches_bundle("{}".into()));
    }

    #[test]
    fn errors_map_to_ffi_variants() {
        let n = create_account(
            new_id().unwrap(),
            "correct horse battery staple".into(),
            false,
        )
        .unwrap();
        let other =
            create_account(new_id().unwrap(), "another long password 1".into(), false).unwrap();
        let vk = n.account.new_vault_key("v".into()).unwrap();
        assert!(matches!(
            other
                .account
                .open_vault_key("v".into(), vk.wrapped, "account".into(), 0, true),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            totp_code("not base32!".into(), 0),
            Err(CoreError::Invalid(_))
        ));
    }

    /// An account without running the KDF (debug-build Argon2id is slow).
    fn quick_account(id: &str) -> Arc<Account> {
        account_from_session_bytes(id.into(), random_bytes::<64>().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn send_through_ffi_types() {
        let key = send_new_key().unwrap();
        let name = send_encrypt(key.clone(), "name".into(), "Door code".into()).unwrap();
        let data = send_encrypt(key.clone(), "data".into(), "4711 ✓".into()).unwrap();
        assert_eq!(
            send_decrypt(key.clone(), "name".into(), name.clone()).unwrap(),
            "Door code"
        );
        assert_eq!(
            send_decrypt(key.clone(), "data".into(), data.clone()).unwrap(),
            "4711 ✓"
        );
        assert!(matches!(
            send_decrypt(key.clone(), "data".into(), name),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            send_encrypt(key.clone(), "text".into(), "x".into()),
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            send_decrypt("short".into(), "data".into(), data),
            Err(CoreError::Invalid(_))
        ));
        let owner = quick_account("owner");
        let wrapped = owner.wrap_send_key(key.clone()).unwrap();
        assert_eq!(owner.unwrap_send_key(wrapped.clone()).unwrap(), key);
        assert!(matches!(
            quick_account("other").unwrap_send_key(wrapped),
            Err(CoreError::DecryptFailed)
        ));
        let salt = send_password_salt().unwrap();
        assert!(salt.starts_with("sendpw-v1$"));
        assert!(send_password_verifier("pw".into(), "nonsense".into()).is_err());
    }

    #[test]
    fn send_v2_through_ffi_types() {
        let key = send_new_key().unwrap();
        // The core's floor (64 MiB), so this also runs without the test KDF feature.
        let salt = format!("sendpw-v1$m=65536,t=3,p=1${}", b64(&[9; 16]));
        let keys = send_password_keys("hunter2".into(), salt.clone(), key.clone()).unwrap();
        assert_eq!(
            keys.verifier,
            send_password_verifier("hunter2".into(), salt.clone()).unwrap()
        );
        let data =
            send_encrypt_v2(keys.content_key.clone(), "data".into(), "4711 ✓".into()).unwrap();
        assert_eq!(send_field_version(data.clone()).unwrap(), 2);
        assert_eq!(
            send_open(
                key.clone(),
                Some(keys.content_key.clone()),
                "data".into(),
                data.clone()
            )
            .unwrap(),
            "4711 ✓"
        );
        assert!(matches!(
            send_open(key.clone(), None, "data".into(), data.clone()),
            Err(CoreError::PasswordRequired)
        ));
        let wrong = send_password_keys("hunter3".into(), salt, key.clone()).unwrap();
        assert!(matches!(
            send_open(
                key.clone(),
                Some(wrong.content_key),
                "data".into(),
                data.clone()
            ),
            Err(CoreError::DecryptFailed)
        ));
        // v1 fields open with the link key alone, as before.
        let v1 = send_encrypt(key.clone(), "data".into(), "plain".into()).unwrap();
        assert_eq!(send_field_version(v1.clone()).unwrap(), 1);
        assert_eq!(
            send_open(key.clone(), None, "data".into(), v1).unwrap(),
            "plain"
        );
        // The owner opens it through `owner_content_key`, without the password.
        let owner = quick_account("owner");
        let wrapped = owner
            .wrap_send_content_key(keys.content_key.clone())
            .unwrap();
        let ck = owner.unwrap_send_content_key(wrapped.clone()).unwrap();
        assert_eq!(
            send_open(key, Some(ck), "data".into(), data).unwrap(),
            "4711 ✓"
        );
        assert!(
            quick_account("other")
                .unwrap_send_content_key(wrapped)
                .is_err()
        );
    }

    #[test]
    fn bound_wraps_and_item_revs_through_ffi_types() {
        let owner = quick_account("owner");
        let vault = "00000000-0000-4000-8000-0000000000aa".to_owned();
        let made = owner.new_vault_key_bound(vault.clone(), 0).unwrap();
        assert!(account_wrap_is_bound(made.wrapped.clone()));
        assert!(
            owner
                .open_vault_key(
                    vault.clone(),
                    made.wrapped.clone(),
                    "account".into(),
                    0,
                    false
                )
                .is_ok()
        );
        assert!(
            owner
                .open_vault_key(vault.clone(), made.wrapped, "account".into(), 1, true)
                .is_err()
        );
        let rewrapped = made
            .key
            .wrap_for_bound(owner.clone(), vault.clone(), 3)
            .unwrap();
        assert!(account_wrap_is_bound(rewrapped.clone()));
        assert!(
            owner
                .open_vault_key(vault.clone(), rewrapped, "account".into(), 3, false)
                .is_ok()
        );
        let v1 = made.key.wrap_for(owner.clone(), vault.clone()).unwrap();
        assert!(!account_wrap_is_bound(v1));
        // Item edit counters.
        let item = made
            .key
            .encrypt_item(r#"{"name":"x"}"#.into(), "i".into(), vault.clone())
            .unwrap();
        let rev = |e: &EncryptedItem| -> u64 {
            let json: serde_json::Value = serde_json::from_str(
                &made
                    .key
                    .decrypt_item(EncryptedItem {
                        id: e.id.clone(),
                        vault_id: e.vault_id.clone(),
                        key: e.key.clone(),
                        data: e.data.clone(),
                    })
                    .unwrap(),
            )
            .unwrap();
            json["rev"].as_u64().unwrap()
        };
        assert_eq!(rev(&item), 1);
        let edited = made
            .key
            .update_item(item, r#"{"name":"y","rev":0}"#.into())
            .unwrap();
        assert_eq!(rev(&edited), 2);
        // Vault manifests through the binding: start, verify, advance, the chain.
        let rows = |data: &str| format!(r#"[{{"id":"i1","deleted_at":null,"data":"{data}"}}]"#);
        let first = made
            .key
            .manifest_start("v".into(), 0, 1, None, rows("one"))
            .unwrap();
        let check = |w: &ManifestWrite,
                     remembered: Option<&ManifestWrite>,
                     log: Option<String>,
                     data: &str| {
            made.key
                .manifest_verify(
                    "v".into(),
                    0,
                    w.seq,
                    Some(w.prev.clone()),
                    Some(w.sealed.clone()),
                    remembered.map(|r| r.seq),
                    remembered.map(|r| r.link.clone()),
                    log,
                    rows(data),
                )
                .unwrap()
        };
        let ok = check(&first, None, None, "one");
        assert_eq!((ok.status.as_str(), ok.version, ok.live), ("ok", 1, 1));
        assert_eq!(ok.link.as_deref(), Some(first.link.as_str()));
        assert_eq!(
            manifest_link(1, first.prev.clone(), first.sealed.clone()).unwrap(),
            first.link
        );
        assert_eq!(check(&first, None, None, "two").status, "mismatch");
        let next = made
            .key
            .manifest_next(
                "v".into(),
                0,
                1,
                first.prev.clone(),
                first.sealed.clone(),
                rows("one"),
                rows("two"),
            )
            .unwrap();
        assert_eq!((next.seq, &next.prev), (2, &first.link));
        assert_eq!(check(&first, Some(&next), None, "one").status, "rollback");
        assert_eq!(check(&next, Some(&first), None, "two").status, "ok");
        // Two steps ahead of what is remembered: the log is asked for, then decides.
        let third = made
            .key
            .manifest_next(
                "v".into(),
                0,
                2,
                next.prev.clone(),
                next.sealed.clone(),
                rows("two"),
                rows("two"),
            )
            .unwrap();
        let ask = check(&third, Some(&first), None, "two");
        assert_eq!(
            (ask.status.as_str(), ask.version, ask.link.as_deref()),
            ("need_log", 1, Some(first.link.as_str()))
        );
        let digest = b64(&manifest::sealed_digest(&next.sealed));
        let log = format!(
            r#"[{{"seq":2,"prev":"{}","digest":"{digest}"}}]"#,
            next.prev
        );
        assert_eq!(check(&third, Some(&first), Some(log), "two").status, "ok");
        let empty = check(&third, Some(&first), Some("[]".into()), "two");
        assert_eq!(empty.status, "mismatch");
        // Rubbish in the log is skipped, not an error; text that is no list is one.
        let noisy = format!(
            r#"[null,7,"x",{{"seq":-1}},{{"seq":2,"prev":"{}","digest":"{digest}"}},{{"seq":2.5,"prev":1,"digest":[]}}]"#,
            next.prev
        );
        assert_eq!(check(&third, Some(&first), Some(noisy), "two").status, "ok");
        let rubbish = r#"[null,{"seq":-1,"prev":"x","digest":"y"}]"#;
        let skipped = check(&third, Some(&first), Some(rubbish.into()), "two");
        assert_eq!(skipped.status, "mismatch");
        let verify_raw = |version: Option<u64>, link: Option<String>, log: Option<&str>| {
            made.key.manifest_verify(
                "v".into(),
                0,
                3,
                Some(third.prev.clone()),
                Some(third.sealed.clone()),
                version,
                link,
                log.map(str::to_owned),
                rows("two"),
            )
        };
        assert!(verify_raw(Some(1), Some(first.link.clone()), Some("{}")).is_err());
        // The link no manifest has is no memory.
        let zero = b64(&manifest::NO_LINK);
        assert!(verify_raw(Some(1), Some(zero), None).is_err());
        // The very next version naming another predecessor: settled without a log.
        let other = made
            .key
            .manifest_start("v".into(), 0, 2, Some(first.link.clone()), rows("two"))
            .unwrap();
        assert_ne!(other.link, next.link);
        assert_eq!(check(&third, Some(&other), None, "two").status, "mismatch");
        // "Use the server's copy": the served vault judged with nothing remembered.
        let accept = |w: Option<&ManifestWrite>, data: &str| {
            made.key
                .manifest_accept(
                    "v".into(),
                    0,
                    w.map_or(0, |w| w.seq),
                    w.map(|w| w.prev.clone()),
                    w.map(|w| w.sealed.clone()),
                    rows(data),
                )
                .unwrap()
        };
        let taken = accept(Some(&third), "two");
        assert_eq!(
            (taken.status.as_str(), taken.version, taken.link.as_deref()),
            ("ok", 3, Some(third.link.as_str()))
        );
        let refused = accept(Some(&third), "one");
        assert_eq!(
            (refused.status.as_str(), refused.version, refused.link),
            ("mismatch", 0, None)
        );
        let none = accept(None, "two");
        assert_eq!(
            (none.status.as_str(), none.version, none.link),
            ("none", 0, None)
        );
        // A key replacement's manifest (or a baseline) names the row's link.
        let rotated = made
            .key
            .manifest_start("v".into(), 1, 4, Some(third.link.clone()), rows("three"))
            .unwrap();
        assert_eq!(rotated.prev, third.link);
        // Half a memory is a bug, not "nothing remembered".
        assert!(
            made.key
                .manifest_verify(
                    "v".into(),
                    0,
                    1,
                    Some(first.prev.clone()),
                    Some(first.sealed.clone()),
                    Some(1),
                    None,
                    None,
                    rows("one"),
                )
                .is_err()
        );
        // A row's `deleted_at` is null or a time: 0 is refused, not read as either.
        let zero = r#"[{"id":"i1","deleted_at":0,"data":"one"}]"#;
        assert!(
            made.key
                .manifest_start("v".into(), 0, 1, None, zero.into())
                .is_err()
        );
        let hashed = format!(
            r#"[{{"id":"i1","data_sha256":"{}"}}]"#,
            manifest_data_hash("two".into())
        );
        let by_hash = made
            .key
            .manifest_verify(
                "v".into(),
                0,
                2,
                Some(next.prev.clone()),
                Some(next.sealed.clone()),
                None,
                None,
                None,
                hashed,
            )
            .unwrap();
        assert_eq!(by_hash.status, "ok");
        assert_eq!(item_rev_check(None, 2).unwrap(), "new");
        assert_eq!(item_rev_check(Some(2), 2).unwrap(), "same");
        assert_eq!(item_rev_check(Some(2), 3).unwrap(), "newer");
        assert_eq!(item_rev_check(Some(2), 1).unwrap(), "rollback");
    }

    #[test]
    fn files_through_ffi_types() {
        let key = file_new_key().unwrap();
        let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let enc = FileEncryptor::new(key.clone(), "item".into(), "att".into()).unwrap();
        let mut ct = Vec::new();
        for piece in plain.chunks(30_000) {
            ct.extend(enc.push(piece.to_vec()).unwrap());
        }
        ct.extend(enc.finish().unwrap());
        assert!(enc.push(vec![1]).is_err());
        assert_eq!(
            ct.len() as u64,
            file_encrypted_size(plain.len() as u64).unwrap()
        );
        assert_eq!(
            file_plain_size(ct.len() as u64).unwrap(),
            plain.len() as u64
        );
        let dec = FileDecryptor::new(key.clone(), "item".into(), "att".into()).unwrap();
        let mut out = Vec::new();
        for piece in ct.chunks(50_001) {
            out.extend(dec.push(piece.to_vec()).unwrap());
        }
        out.extend(dec.finish().unwrap());
        assert_eq!(out, plain);
        assert_eq!(
            file_decrypt(key.clone(), "item".into(), "att".into(), ct.clone()).unwrap(),
            plain
        );
        let one_shot =
            file_encrypt(key.clone(), "item".into(), "att".into(), plain.clone()).unwrap();
        assert_eq!(one_shot.len(), ct.len());
        // Another attachment's id, or cut short.
        assert!(matches!(
            file_decrypt(key.clone(), "item".into(), "att2".into(), ct.clone()),
            Err(CoreError::DecryptFailed)
        ));
        let dec = FileDecryptor::new(key, "item".into(), "att".into()).unwrap();
        dec.push(ct[..ct.len() - 1].to_vec()).unwrap();
        assert!(matches!(dec.finish(), Err(CoreError::DecryptFailed)));
        assert!(FileEncryptor::new("bad".into(), "item".into(), "att".into()).is_err());
    }

    #[test]
    fn emergency_access_through_ffi_types() {
        let grantor = quick_account("grantor-1");
        let contact = quick_account("contact-1");
        let vk = grantor.new_vault_key("v1".into()).unwrap();
        let item = r#"{"name":"Bank","notes":"PIN 1234"}"#;
        let enc = vk
            .key
            .encrypt_item(item.into(), "i1".into(), "v1".into())
            .unwrap();
        let new = grantor.new_emergency_key("g1".into()).unwrap();
        let sealed = new
            .key
            .seal_for(contact.public_key(), "grantor-1".into(), "g1".into())
            .unwrap();
        let again = grantor
            .open_emergency_key("g1".into(), new.wrapped.clone())
            .unwrap();
        let wrapped = again.wrap_vault_key(vk.key.clone(), "v1".into()).unwrap();
        // Opened again, the key can't be sealed to anyone.
        assert!(
            again
                .seal_for(contact.public_key(), "grantor-1".into(), "g1".into())
                .is_err()
        );
        let theirs = contact
            .open_sealed_emergency_key("grantor-1".into(), "g1".into(), sealed.clone())
            .unwrap();
        assert_eq!(
            (theirs.grantor_id(), theirs.grant_id()),
            ("grantor-1".to_owned(), "g1".to_owned())
        );
        let opened = theirs.open_vault_key("v1".into(), wrapped.clone()).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&opened.decrypt_item(enc).unwrap()).unwrap();
        assert_eq!(json["notes"], "PIN 1234");
        // Only that vault, that access, that grantor and that contact.
        assert!(matches!(
            theirs.open_vault_key("v2".into(), wrapped.clone()),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            contact.open_sealed_emergency_key("grantor-2".into(), "g1".into(), sealed.clone()),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            quick_account("x").open_sealed_emergency_key("grantor-1".into(), "g1".into(), sealed),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            contact.open_emergency_key("g1".into(), new.wrapped.clone()),
            Err(CoreError::DecryptFailed)
        ));
        assert!(
            new.key
                .seal_for(b64(&[0; 32]), "grantor-1".into(), "g1".into())
                .is_err()
        );
        // The roster opens for its own account only.
        let roster = grantor
            .seal_emergency_roster(r#"{"version":1,"accesses":[]}"#.into())
            .unwrap();
        assert_eq!(
            grantor.open_emergency_roster(roster.clone()).unwrap(),
            r#"{"version":1,"accesses":[]}"#
        );
        assert!(matches!(
            contact.open_emergency_roster(roster),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn kdf_minimums_are_checked_before_deriving() {
        for (m, t) in [
            (Some(32), None),
            (Some(4096), None),
            (None, Some(2)),
            (None, Some(50)),
        ] {
            assert!(create_account_with_kdf("a".into(), "pw".into(), false, m, t).is_err());
            assert!(
                quick_account("a")
                    .rewrap_with_kdf("{}".into(), "pw".into(), false, None, m, t)
                    .is_err()
            );
        }
        // Too weak and too strong are told apart (review I7).
        assert!(matches!(
            create_account_with_kdf("a".into(), "pw".into(), false, Some(32), None),
            Err(CoreError::WeakKdf)
        ));
        assert!(matches!(
            create_account_with_kdf("a".into(), "pw".into(), false, None, Some(50)),
            Err(CoreError::KdfTooStrong)
        ));
        assert_eq!(CoreError::KdfTooStrong.to_string(), "kdf_too_strong");
        let salt = |m: u32, t: u32| format!("sendpw-v1$m={m},t={t},p=1${}", b64(&[7; 16]));
        assert!(matches!(
            send_password_verifier("pw".into(), salt(1024 * 1024, 3)),
            Err(CoreError::KdfTooStrong)
        ));
        assert!(matches!(
            send_password_verifier("pw".into(), salt(65536, 7)),
            Err(CoreError::KdfTooStrong)
        ));
    }

    #[test]
    fn device_login_through_ffi_types() {
        let n = create_account(
            new_id().unwrap(),
            "correct horse battery staple".into(),
            true,
        )
        .unwrap();
        let sk = n.secret_key.clone().unwrap();
        let account_id = n.account.0.account_id.clone();
        let request = LoginRequestKey::generate().unwrap();
        assert_eq!(
            login_phrase(request.public_key()).unwrap(),
            request.phrase()
        );
        assert!(login_phrase("short".into()).is_err());
        let choices = login_phrase_choices(request.public_key(), 3).unwrap();
        assert_eq!(choices.len(), 3);
        assert_eq!(
            choices.iter().filter(|c| **c == request.phrase()).count(),
            1
        );
        assert!(login_phrase_choices(request.public_key(), 6).is_err());
        // Fixed per key (a request seen twice shows the same list).
        assert_eq!(
            login_phrase_choices(request.public_key(), 3).unwrap(),
            choices
        );
        assert_eq!(
            login_phrase_choices("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(), 2).unwrap(),
            [
                "could regulator babied luckiness pavement",
                "lung spout ashen sudoku gloating"
            ]
        );

        // A decoy, or another key's words, seal nothing.
        let decoy = choices.iter().find(|c| **c != request.phrase()).unwrap();
        assert!(matches!(
            n.account.approve_login_request(
                request.public_key(),
                "req-1".into(),
                decoy.clone(),
                None
            ),
            Err(CoreError::PhraseMismatch)
        ));
        let approval = n
            .account
            .approve_login_request(
                request.public_key(),
                "req-1".into(),
                request.phrase(),
                Some(sk.clone()),
            )
            .unwrap();
        assert_eq!(approval.code.len(), 6);
        let approved = request
            .open(approval.sealed.clone(), account_id.clone(), "req-1".into())
            .unwrap();
        assert_eq!(approved.account_id(), account_id);
        // Nothing before the code; a wrong one costs an attempt.
        assert!(matches!(
            approved.secret_key(),
            Err(CoreError::NotConfirmed)
        ));
        assert!(matches!(
            approved.unlock(n.bundle_json.clone()),
            Err(CoreError::NotConfirmed)
        ));
        let wrong = format!(
            "{:06}",
            (approval.code.parse::<u32>().unwrap() + 1) % 1_000_000
        );
        assert!(matches!(
            approved.confirm(wrong.clone()),
            Err(CoreError::WrongCode)
        ));
        assert_eq!(approved.attempts_left(), 2);
        assert!(matches!(
            approved.confirm("12ab56".into()),
            Err(CoreError::Invalid(_))
        ));
        assert!(!approved.is_confirmed());
        approved
            .confirm(format!("{} {}", &approval.code[..3], &approval.code[3..]))
            .unwrap();
        assert!(approved.is_confirmed());
        assert_eq!(approved.secret_key().unwrap(), Some(sk));
        let unlocked = approved.unlock(n.bundle_json.clone()).unwrap();
        assert_eq!(unlocked.public_key(), n.account.public_key());
        assert!(matches!(
            request.open(approval.sealed.clone(), account_id.clone(), "req-2".into()),
            Err(CoreError::DecryptFailed)
        ));
        // Three wrong codes refuse a fresh handle for good.
        let again = request
            .open(approval.sealed, account_id, "req-1".into())
            .unwrap();
        assert!(matches!(
            again.confirm(wrong.clone()),
            Err(CoreError::WrongCode)
        ));
        assert!(matches!(
            again.confirm(wrong.clone()),
            Err(CoreError::WrongCode)
        ));
        assert!(matches!(
            again.confirm(wrong),
            Err(CoreError::TooManyWrongCodes)
        ));
        assert!(matches!(
            again.confirm(approval.code.clone()),
            Err(CoreError::TooManyWrongCodes)
        ));
        assert!(matches!(
            again.unlock(n.bundle_json.clone()),
            Err(CoreError::NotConfirmed)
        ));
        let zero = b64(&[0; 32]);
        assert!(matches!(
            n.account.approve_login_request(
                zero.clone(),
                "req-1".into(),
                login_phrase(zero).unwrap(),
                None
            ),
            Err(CoreError::Invalid(_))
        ));

        // The challenge as the server seals it.
        let pk: [u8; 32] = unb64(&n.account.public_key()).unwrap().try_into().unwrap();
        let challenge = b64(&passauth_core::crypto::seal_to(
            &pk,
            &[7; 32],
            b"passauth/login-with-device/challenge/v1:req-1",
        )
        .unwrap());
        assert_eq!(
            n.account
                .open_login_challenge(challenge.clone(), "req-1".into())
                .unwrap(),
            b64(&[7; 32])
        );
        assert!(matches!(
            n.account.open_login_challenge(challenge, "req-2".into()),
            Err(CoreError::DecryptFailed)
        ));
    }

    #[test]
    fn sites_through_ffi_types() {
        assert_eq!(base_domain("a.nas.myfritz.net".into()), "nas.myfritz.net");
        assert_eq!(registrable_domain("myfritz.net".into()), None);
        assert_eq!(
            normalize_host("BÜCHER.de.".into()).as_deref(),
            Some("xn--bcher-kva.de")
        );
        assert!(public_suffix_list_version().starts_with("20"));

        let saved = |url: &str, match_type: &str, allow_regex| SavedUrl {
            url: url.into(),
            match_type: match_type.into(),
            allow_regex,
        };
        let urls = vec![
            saved("https://example.com", "default", true),
            saved("https://attacker.myfritz.net", "domain", true),
            saved(r"^https://www\.example\.com/", "regex", true),
            saved(r"^https://www\.example\.com/", "regex", false),
            saved("https://www.example.com", "unknown", true),
        ];
        let page = "https://www.example.com/login".to_string();
        assert_eq!(
            match_urls(page.clone(), "domain".into(), urls),
            [true, false, true, false, false]
        );
        assert!(!matches_url(
            page.clone(),
            "https://example.com".into(),
            "default".into(),
            "host".into(),
            true
        ));
        assert!(matches_url(
            page,
            "https://example.com".into(),
            "default".into(),
            "bogus".into(),
            true
        ));
        assert!(downgrade(
            "http://example.com/".into(),
            "example.com".into(),
            "domain".into()
        ));
        assert!(regex_error("(?=x)".into()).is_some());
        assert!(regex_warning(r"example\.com".into()).is_some());
        assert_eq!(
            resolve_match(
                "https://example.com".into(),
                "default".into(),
                "regex".into()
            ),
            "domain"
        );
        assert_eq!(
            resolve_match("example.com".into(), "default".into(), "regex".into()),
            "regex"
        );
        assert_eq!(
            resolve_match("x".into(), "bogus".into(), "regex".into()),
            "never"
        );
        assert_eq!(regex_warning(r"^https://example\.com/".into()), None);
        // "default" with the regex setting keeps a plain address to its site (review M2).
        assert!(!matches_url(
            "https://evil.example/https://example.com".into(),
            "https://example.com".into(),
            "default".into(),
            "regex".into(),
            true
        ));
        assert!(!matches_url(
            "example.com".into(),
            "https://example.com".into(),
            "domain".into(),
            "domain".into(),
            true
        ));

        let candidate = |id: &str, username: &str, personal| SaveCandidate {
            id: id.into(),
            name: id.into(),
            username: username.into(),
            password: "old".into(),
            writable: true,
            personal,
            vault: (!personal).then(|| "Team".into()),
        };
        let plan = plan_save(
            vec![candidate("s", "alex", false), candidate("a", "alex", true)],
            "alex".into(),
            "new".into(),
        );
        let SavePlan::Update {
            reason: SaveReason::Same,
            target,
            targets,
        } = plan
        else {
            panic!("expected an update");
        };
        assert_eq!(target, "a");
        assert_eq!(
            targets.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
            ["a", "s"]
        );
        assert_eq!(targets[1].vault.as_deref(), Some("Team"));
        assert_eq!(
            chosen_save_target(targets, "s".into()).as_deref(),
            Some("s")
        );
        assert!(matches!(
            plan_save(vec![], "alex".into(), String::new()),
            SavePlan::None
        ));

        let login = PasskeyLogin {
            id: "a".into(),
            name: "Example".into(),
            username: "alex".into(),
            urls: vec!["https://login.example.com".into()],
            writable: true,
            personal: true,
            vault: None,
        };
        let targets = passkey_save_targets(
            vec![login],
            "login.example.com".into(),
            "example.com".into(),
            "alex".into(),
            String::new(),
        );
        assert!(targets[0].preferred);
        assert_eq!(passkey_default_target(targets), "a");

        assert_eq!(
            effective_rp_id(
                Some("example.com".into()),
                "https://login.example.com".into()
            )
            .unwrap(),
            "example.com"
        );
        let err = effective_rp_id(Some("myfritz.net".into()), "https://nas.myfritz.net".into())
            .unwrap_err();
        assert!(matches!(err, RpIdError::NotRegistrableSuffix));
        assert_eq!(
            err.to_string(),
            "The RP ID is not a registrable domain suffix of the origin."
        );
    }
}
