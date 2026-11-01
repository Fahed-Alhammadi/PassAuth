//! WebAssembly bindings for the web vault and browser extension.
//!
//! Keys stay inside WASM memory: JavaScript only holds opaque handles
//! (`MasterKeys`, `Account`, `VaultKey`) and never sees raw key bytes.

use passauth_core::crypto::SymmetricKey;
use passauth_core::item::{EncryptedItem, Item, unb64};
use passauth_core::kdf::{KdfParams, MasterKeys as CoreMaster};
use passauth_core::keys::{self, AccountBundle, NewAccount as CoreNew, UnlockedAccount};
use passauth_core::{Error, generator, import, opaque, totp};
use serde::Serialize;
use wasm_bindgen::prelude::*;

type R<T> = Result<T, JsError>;

fn js_err(e: Error) -> JsError {
    match e {
        Error::PasswordRequired => JsError::new("password_required"),
        Error::Decrypt => JsError::new("decrypt_failed"),
        other => JsError::new(&other.to_string()),
    }
}

fn to_js<T: Serialize>(v: &T) -> R<JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn from_js<T: serde::de::DeserializeOwned>(v: JsValue) -> R<T> {
    serde_wasm_bindgen::from_value(v).map_err(|e| JsError::new(&format!("invalid input: {e}")))
}

// ------------------------------------------------------------------ handles

#[wasm_bindgen]
pub struct MasterKeys(CoreMaster);

#[wasm_bindgen]
impl MasterKeys {
    /// Decrypt the account bundle returned by the server after login.
    pub fn unlock(&self, bundle: JsValue) -> R<Account> {
        let bundle: AccountBundle = from_js(bundle)?;
        bundle.unlock(&self.0.auk).map(Account).map_err(js_err)
    }
}

#[wasm_bindgen]
pub struct Account(UnlockedAccount);

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        passauth_core::item::b64(&self.0.keypair.public_bytes())
    }

    pub fn fingerprint(&self) -> String {
        passauth_core::crypto::fingerprint(&self.0.keypair.public_bytes())
    }

    #[wasm_bindgen(js_name = newVaultKey)]
    pub fn new_vault_key(&self, vault_id: &str) -> R<NewVaultKey> {
        let (key, wrapped) = self.0.new_vault_key(vault_id).map_err(js_err)?;
        Ok(NewVaultKey {
            key: Some(VaultKey(key)),
            wrapped,
        })
    }

    /// `kind` is the membership's `key_kind`: "account" (own vault) or "sealed" (shared to us).
    #[wasm_bindgen(js_name = openVaultKey)]
    pub fn open_vault_key(&self, vault_id: &str, wrapped: &str, kind: &str) -> R<VaultKey> {
        let key = match kind {
            "sealed" => self.0.open_shared_vault_key(vault_id, wrapped),
            _ => self.0.open_vault_key(vault_id, wrapped),
        };
        key.map(VaultKey).map_err(js_err)
    }

    /// Serialize the unlocked keys so a browser extension can keep them in
    /// `chrome.storage.session` (memory-only, extension-private) across
    /// service-worker restarts. Never write these bytes to disk.
    #[wasm_bindgen(js_name = toSessionBytes)]
    pub fn to_session_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(self.0.account_key.as_bytes());
        out.extend_from_slice(&self.0.keypair.secret_bytes());
        out
    }

    /// New password and/or Secret Key setting. Re-register OPAQUE with the
    /// returned master keys, then upload the new bundle.
    /// Pass the current Secret Key to keep it; omit it to generate a new one.
    pub fn rewrap(
        &self,
        bundle: JsValue,
        new_password: &str,
        with_secret_key: bool,
        existing_secret_key: Option<String>,
    ) -> R<NewAccount> {
        let bundle: AccountBundle = from_js(bundle)?;
        bundle
            .rewrap(
                &self.0,
                new_password,
                with_secret_key,
                existing_secret_key.as_deref(),
            )
            .map(NewAccount::from)
            .map_err(js_err)
    }
}

#[wasm_bindgen]
pub struct VaultKey(SymmetricKey);

#[wasm_bindgen]
impl VaultKey {
    /// Returns `{ id, vault_id, key, data }` ready for the API.
    #[wasm_bindgen(js_name = encryptItem)]
    pub fn encrypt_item(&self, item: JsValue, id: &str, vault_id: &str) -> R<JsValue> {
        let item: Item = from_js(item)?;
        to_js(&EncryptedItem::encrypt(&item, id, vault_id, &self.0).map_err(js_err)?)
    }

    /// Re-encrypt an edited item, keeping its Item Key.
    #[wasm_bindgen(js_name = updateItem)]
    pub fn update_item(&self, encrypted: JsValue, item: JsValue) -> R<JsValue> {
        let enc: EncryptedItem = from_js(encrypted)?;
        let item: Item = from_js(item)?;
        to_js(&enc.update(&item, &self.0).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = decryptItem)]
    pub fn decrypt_item(&self, encrypted: JsValue) -> R<JsValue> {
        let enc: EncryptedItem = from_js(encrypted)?;
        to_js(&enc.decrypt(&self.0).map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = encryptMeta)]
    pub fn encrypt_meta(&self, vault_id: &str, meta: JsValue) -> R<String> {
        let v: serde_json::Value = from_js(meta)?;
        let json = serde_json::to_vec(&v).map_err(|e| JsError::new(&e.to_string()))?;
        keys::encrypt_vault_meta(&self.0, vault_id, &json).map_err(js_err)
    }

    #[wasm_bindgen(js_name = decryptMeta)]
    pub fn decrypt_meta(&self, vault_id: &str, meta: &str) -> R<JsValue> {
        let json = keys::decrypt_vault_meta(&self.0, vault_id, meta).map_err(js_err)?;
        let v: serde_json::Value =
            serde_json::from_slice(&json).map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&v)
    }

    /// Seal this vault key to another member's public key.
    #[wasm_bindgen(js_name = shareTo)]
    pub fn share_to(&self, vault_id: &str, recipient_public_key: &str) -> R<String> {
        keys::share_vault_key(vault_id, &self.0, recipient_public_key).map_err(js_err)
    }

    /// Wrap this key for the owner's own account (used after rotation).
    #[wasm_bindgen(js_name = wrapFor)]
    pub fn wrap_for(&self, account: &Account, vault_id: &str) -> R<String> {
        let wrapped = account
            .0
            .account_key
            .wrap(
                &self.0,
                format!("passauth/vault-key/v1/{vault_id}").as_bytes(),
            )
            .map_err(js_err)?;
        Ok(passauth_core::item::b64(&wrapped))
    }
}

#[wasm_bindgen]
pub struct NewVaultKey {
    key: Option<VaultKey>,
    wrapped: String,
}

#[wasm_bindgen]
impl NewVaultKey {
    #[wasm_bindgen(getter)]
    pub fn wrapped(&self) -> String {
        self.wrapped.clone()
    }

    /// Take the key handle (can be called once).
    #[wasm_bindgen(js_name = takeKey)]
    pub fn take_key(&mut self) -> R<VaultKey> {
        self.key
            .take()
            .ok_or_else(|| JsError::new("key already taken"))
    }
}

#[wasm_bindgen]
pub struct NewAccount {
    bundle: AccountBundle,
    secret_key: Option<String>,
    account: Option<Account>,
    master: Option<MasterKeys>,
}

impl From<CoreNew> for NewAccount {
    fn from(n: CoreNew) -> Self {
        Self {
            bundle: n.bundle,
            secret_key: n.secret_key,
            account: Some(Account(n.unlocked)),
            master: Some(MasterKeys(n.master)),
        }
    }
}

#[wasm_bindgen]
impl NewAccount {
    #[wasm_bindgen(getter)]
    pub fn bundle(&self) -> R<JsValue> {
        to_js(&self.bundle)
    }

    /// Show once in the Emergency Kit; `undefined` when not enabled.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> Option<String> {
        self.secret_key.clone()
    }

    #[wasm_bindgen(js_name = takeAccount)]
    pub fn take_account(&mut self) -> R<Account> {
        self.account
            .take()
            .ok_or_else(|| JsError::new("account already taken"))
    }

    #[wasm_bindgen(js_name = takeMaster)]
    pub fn take_master(&mut self) -> R<MasterKeys> {
        self.master
            .take()
            .ok_or_else(|| JsError::new("master keys already taken"))
    }
}

#[wasm_bindgen]
pub struct OpaqueStart {
    state: Vec<u8>,
    message: String,
}

#[wasm_bindgen]
impl OpaqueStart {
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> Vec<u8> {
        self.state.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
}

// --------------------------------------------------------------- functions

/// Restore an unlocked account from [`Account::to_session_bytes`].
#[wasm_bindgen(js_name = accountFromSessionBytes)]
pub fn account_from_session_bytes(account_id: &str, bytes: &[u8]) -> R<Account> {
    if bytes.len() != 64 {
        return Err(JsError::new("invalid session data"));
    }
    let account_key = SymmetricKey::from_slice(&bytes[..32]).map_err(js_err)?;
    let secret: [u8; 32] = bytes[32..].try_into().expect("checked length");
    Ok(Account(UnlockedAccount {
        account_id: account_id.to_owned(),
        account_key,
        keypair: passauth_core::crypto::KeyPair::from_secret_bytes(secret),
    }))
}

#[wasm_bindgen(js_name = createAccount)]
pub fn create_account(account_id: &str, password: &str, with_secret_key: bool) -> R<NewAccount> {
    AccountBundle::create(account_id, password, with_secret_key)
        .map(NewAccount::from)
        .map_err(js_err)
}

/// Derive master keys from what prelogin returned (`{ account_id, kdf, secret_key_required }`).
#[wasm_bindgen(js_name = deriveMasterKeys)]
pub fn derive_master_keys(
    password: &str,
    secret_key: Option<String>,
    account_id: &str,
    kdf: JsValue,
    secret_key_required: bool,
) -> R<MasterKeys> {
    let kdf: KdfParams = from_js(kdf)?;
    keys::derive_master_keys(
        password,
        secret_key.as_deref(),
        account_id,
        &kdf,
        secret_key_required,
    )
    .map(MasterKeys)
    .map_err(js_err)
}

#[wasm_bindgen(js_name = opaqueRegisterStart)]
pub fn opaque_register_start(master: &MasterKeys) -> R<OpaqueStart> {
    let s = opaque::register_start(&master.0.login).map_err(js_err)?;
    Ok(OpaqueStart {
        state: s.state,
        message: s.message,
    })
}

#[wasm_bindgen(js_name = opaqueRegisterFinish)]
pub fn opaque_register_finish(state: &[u8], master: &MasterKeys, response: &str) -> R<String> {
    opaque::register_finish(state, &master.0.login, response).map_err(js_err)
}

#[wasm_bindgen(js_name = opaqueLoginStart)]
pub fn opaque_login_start(master: &MasterKeys) -> R<OpaqueStart> {
    let s = opaque::login_start(&master.0.login).map_err(js_err)?;
    Ok(OpaqueStart {
        state: s.state,
        message: s.message,
    })
}

/// Throws `decrypt_failed` when the password or Secret Key is wrong.
#[wasm_bindgen(js_name = opaqueLoginFinish)]
pub fn opaque_login_finish(state: &[u8], master: &MasterKeys, response: &str) -> R<String> {
    opaque::login_finish(state, &master.0.login, response).map_err(js_err)
}

/// Parse an export from another password manager. Throws `password_required`
/// for password-protected files when `password` is missing.
#[wasm_bindgen(js_name = importFile)]
pub fn import_file(data: &[u8], password: Option<String>) -> R<JsValue> {
    to_js(&import::import(data, password.as_deref()).map_err(js_err)?)
}

#[derive(Serialize)]
struct TotpCode {
    code: String,
    remaining: u64,
    period: u64,
}

#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(secret: &str, unix_seconds: f64) -> R<JsValue> {
    let t = totp::Totp::parse(secret).map_err(js_err)?;
    let now = unix_seconds.max(0.0) as u64;
    to_js(&TotpCode {
        code: t.generate(now),
        remaining: t.remaining(now),
        period: t.period,
    })
}

#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options: JsValue) -> R<String> {
    let opts: generator::PasswordOptions = if options.is_undefined() {
        Default::default()
    } else {
        from_js(options)?
    };
    generator::password(&opts).map_err(js_err)
}

#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase(options: JsValue) -> R<String> {
    let opts: generator::PassphraseOptions = if options.is_undefined() {
        Default::default()
    } else {
        from_js(options)?
    };
    generator::passphrase(&opts).map_err(js_err)
}

#[wasm_bindgen(js_name = estimateBits)]
pub fn estimate_bits(password: &str) -> f64 {
    generator::estimate_bits(password)
}

#[wasm_bindgen]
pub fn fingerprint(public_key: &str) -> R<String> {
    let pk: [u8; 32] = unb64(public_key)
        .map_err(js_err)?
        .try_into()
        .map_err(|_| JsError::new("invalid public key"))?;
    Ok(passauth_core::crypto::fingerprint(&pk))
}

#[wasm_bindgen(js_name = newId)]
pub fn new_id() -> String {
    uuid_v4()
}

fn uuid_v4() -> String {
    let mut b: [u8; 16] = passauth_core::crypto::random_bytes().expect("rng");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    #[test]
    fn uuid_format() {
        let id = super::uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
    }
}
