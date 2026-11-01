//! Kotlin and Swift bindings (UniFFI) for the native PassAuth apps.
//!
//! Mirrors `passauth-core-wasm`: keys stay in Rust objects (`MasterKeys`,
//! `Account`, `VaultKey`) and the apps only hold handles. Items, bundles and
//! KDF parameters cross the boundary as JSON in the same shape as the server
//! API and the web vault, so all clients read and write the same data.

use std::sync::Arc;

use passauth_core::crypto::{KeyPair, SymmetricKey, fingerprint as key_fingerprint, random_bytes};
use passauth_core::item::{EncryptedItem as CoreEncrypted, Item, b64, unb64};
use passauth_core::kdf::{KdfParams, MasterKeys as CoreMaster};
use passauth_core::keys::{self, AccountBundle, NewAccount as CoreNew, UnlockedAccount};
use passauth_core::{Error, generator, import, opaque, passkey, totp};

uniffi::setup_scaffolding!();

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    /// Wrong key, wrong master password / Secret Key, or tampered data.
    DecryptFailed,
    /// The import file is password protected.
    PasswordRequired,
    Invalid(String),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecryptFailed => f.write_str("decrypt_failed"),
            Self::PasswordRequired => f.write_str("password_required"),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<Error> for CoreError {
    fn from(e: Error) -> Self {
        match e {
            Error::Decrypt => Self::DecryptFailed,
            Error::PasswordRequired => Self::PasswordRequired,
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

    /// `kind` is the membership's `key_kind`: "account" (own vault) or "sealed" (shared to us).
    pub fn open_vault_key(
        &self,
        vault_id: String,
        wrapped: String,
        kind: String,
    ) -> R<Arc<VaultKey>> {
        let key = match kind.as_str() {
            "sealed" => self.0.open_shared_vault_key(&vault_id, &wrapped)?,
            _ => self.0.open_vault_key(&vault_id, &wrapped)?,
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

    /// Re-encrypt an edited item, keeping its Item Key.
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
            .open_vault_key("vault-1".into(), vk.wrapped.clone(), "account".into())
            .unwrap();
        let json = reopened.decrypt_item(enc).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "GitHub");
        assert_eq!(v["login"]["password"], "s3cret");

        let restored =
            account_from_session_bytes(account.0.account_id.clone(), account.to_session_bytes())
                .unwrap();
        assert_eq!(restored.public_key(), account.public_key());
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
                .open_vault_key("v".into(), vk.wrapped, "account".into()),
            Err(CoreError::DecryptFailed)
        ));
        assert!(matches!(
            totp_code("not base32!".into(), 0),
            Err(CoreError::Invalid(_))
        ));
    }
}
