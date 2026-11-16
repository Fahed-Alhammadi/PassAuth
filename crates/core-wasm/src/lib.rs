//! WebAssembly bindings for the web vault and browser extension.
//!
//! Keys stay inside WASM memory: JavaScript only holds opaque handles
//! (`MasterKeys`, `Account`, `VaultKey`, `EmergencyKey`). The one exception is
//! `toSessionBytes`, which hands the unlocked account key to the extension so
//! it can keep the vault unlocked across service-worker restarts. Send keys and
//! attachment keys are base64url strings: they travel in a link's fragment and in
//! the (encrypted) item's attachment list anyway.
//!
//! Every string parameter is a `JsValue` checked by `string` / `opt_string` before any
//! other work, so a wrong type is a clean `Error("expected a string")`.
//! wasm-bindgen's own `&str` conversion trusts the TypeScript type: a number, boolean or
//! object there reached the allocator with a bogus length (a trap, undefined behaviour, or
//! gigabytes of memory never given back; review L1). `unchecked_param_type` keeps the
//! `.d.ts` types as they were.

use passauth_core::crypto::SymmetricKey;
use passauth_core::file::{self, FileKey};
use passauth_core::item::{EncryptedItem, Item, unb64};
use passauth_core::kdf::{KdfParams, MasterKeys as CoreMaster};
use passauth_core::keys::{
    self, AccountBundle, EmergencyKey as CoreEmergencyKey, NewAccount as CoreNew, UnlockedAccount,
};
use passauth_core::send::{self, SendField, SendKey};
use passauth_core::{Error, device_login, export, generator, import, opaque, totp};
use serde::Serialize;
use wasm_bindgen::prelude::*;

type R<T> = Result<T, JsError>;

/// The thrown `Error`: its message is the error's code (`decrypt_failed`, `weak_kdf`,
/// `not_confirmed`…, see `passauth_core::Error::code`) or else its description.
fn js_err(e: Error) -> JsError {
    match e.code() {
        Some(code) => JsError::new(code),
        None => JsError::new(&e.to_string()),
    }
}

/// A string argument (see the module docs).
fn string(v: JsValue) -> R<String> {
    v.as_string()
        .ok_or_else(|| JsError::new("expected a string"))
}

/// An optional string argument: `undefined` and `null` are none.
fn opt_string(v: JsValue) -> R<Option<String>> {
    if v.is_undefined() || v.is_null() {
        Ok(None)
    } else {
        string(v).map(Some)
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
    pub fn new_vault_key(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
    ) -> R<NewVaultKey> {
        let vault_id = string(vault_id)?;
        let (key, wrapped) = self.0.new_vault_key(&vault_id).map_err(js_err)?;
        Ok(NewVaultKey {
            key: Some(VaultKey(key)),
            wrapped,
        })
    }

    /// `kind` is the membership's `key_kind`: "account" (own vault) or "sealed" (shared to us).
    #[wasm_bindgen(js_name = openVaultKey)]
    pub fn open_vault_key(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] wrapped: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] kind: JsValue,
    ) -> R<VaultKey> {
        let (vault_id, wrapped, kind) = (string(vault_id)?, string(wrapped)?, string(kind)?);
        let key = match kind.as_str() {
            "sealed" => self.0.open_shared_vault_key(&vault_id, &wrapped),
            _ => self.0.open_vault_key(&vault_id, &wrapped),
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
        #[wasm_bindgen(unchecked_param_type = "string")] new_password: JsValue,
        with_secret_key: bool,
        #[wasm_bindgen(unchecked_optional_param_type = "string | null")]
        existing_secret_key: JsValue,
    ) -> R<NewAccount> {
        let new_password = string(new_password)?;
        let existing_secret_key = opt_string(existing_secret_key)?;
        let bundle: AccountBundle = from_js(bundle)?;
        bundle
            .rewrap(
                &self.0,
                &new_password,
                with_secret_key,
                existing_secret_key.as_deref(),
            )
            .map(NewAccount::from)
            .map_err(js_err)
    }

    /// `rewrap` following a server's KDF policy: memory = max(128 MiB,
    /// `min_memory_mib`), passes = max(3, `min_iterations`); pass the policy's
    /// `min_kdf_memory_mib` / `min_kdf_iterations` (or leave them out). A minimum
    /// outside 64–1024 MiB or 3–20 passes throws `weak_kdf` / `kdf_too_strong`. Also
    /// fixes a `kdf` policy violation (same password, new parameters).
    #[wasm_bindgen(js_name = rewrapWithKdf)]
    pub fn rewrap_with_kdf(
        &self,
        bundle: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] new_password: JsValue,
        with_secret_key: bool,
        #[wasm_bindgen(unchecked_optional_param_type = "string | null")]
        existing_secret_key: JsValue,
        #[wasm_bindgen(unchecked_optional_param_type = "number | null")] min_memory_mib: Option<
            u32,
        >,
        #[wasm_bindgen(unchecked_optional_param_type = "number | null")] min_iterations: Option<
            u32,
        >,
    ) -> R<NewAccount> {
        let new_password = string(new_password)?;
        let existing_secret_key = opt_string(existing_secret_key)?;
        let bundle: AccountBundle = from_js(bundle)?;
        let kdf = KdfParams::with_minimums(min_memory_mib, min_iterations).map_err(js_err)?;
        bundle
            .rewrap_with_kdf(
                &self.0,
                &new_password,
                with_secret_key,
                existing_secret_key.as_deref(),
                kdf,
            )
            .map(NewAccount::from)
            .map_err(js_err)
    }

    /// Wrap a Send's key (from `sendNewKey`) for this account: the Send's `owner_key`.
    #[wasm_bindgen(js_name = wrapSendKey)]
    pub fn wrap_send_key(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
    ) -> R<String> {
        let key = SendKey::from_b64(&string(key)?).map_err(js_err)?;
        self.0.wrap_send_key(&key).map_err(js_err)
    }

    /// The send key (base64url, for the link's fragment) from a Send's `owner_key`.
    #[wasm_bindgen(js_name = unwrapSendKey)]
    pub fn unwrap_send_key(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] wrapped: JsValue,
    ) -> R<String> {
        self.0
            .unwrap_send_key(&string(wrapped)?)
            .map(|k| k.to_b64())
            .map_err(js_err)
    }

    /// Emergency access, the grantor's side, when confirming contact `grantId` (the
    /// access's id): a new emergency key (`takeKey`) and it wrapped with this account's
    /// key (`wrapped`, the access's `grantor_key`).
    #[wasm_bindgen(js_name = newEmergencyKey)]
    pub fn new_emergency_key(
        &self,
        #[wasm_bindgen(js_name = "grantId", unchecked_param_type = "string")] grant_id: JsValue,
    ) -> R<NewEmergencyKey> {
        let new = self
            .0
            .new_emergency_key(&string(grant_id)?)
            .map_err(js_err)?;
        Ok(NewEmergencyKey {
            key: Some(EmergencyKey(new.key)),
            wrapped: new.wrapped,
        })
    }

    /// The emergency key of this account's access `grantId` again, from its
    /// `grantor_key` (it wraps vault keys; it can't be sealed to anyone again). Throws
    /// `decrypt_failed` for another account's or access's key.
    #[wasm_bindgen(js_name = openEmergencyKey)]
    pub fn open_emergency_key(
        &self,
        #[wasm_bindgen(js_name = "grantId", unchecked_param_type = "string")] grant_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] wrapped: JsValue,
    ) -> R<EmergencyKey> {
        let (grant_id, wrapped) = (string(grant_id)?, string(wrapped)?);
        self.0
            .open_emergency_key(&grant_id, &wrapped)
            .map(EmergencyKey)
            .map_err(js_err)
    }

    /// Emergency access: seal this account's roster of emergency contacts (JSON of the
    /// app's own) with its key: the server keeps it but can neither read nor change it.
    #[wasm_bindgen(js_name = sealEmergencyRoster)]
    pub fn seal_emergency_roster(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] json: JsValue,
    ) -> R<String> {
        self.0.seal_emergency_roster(&string(json)?).map_err(js_err)
    }

    /// The roster's JSON from what `sealEmergencyRoster` made. Throws `decrypt_failed`
    /// for another account's roster or a changed one.
    #[wasm_bindgen(js_name = openEmergencyRoster)]
    pub fn open_emergency_roster(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] sealed: JsValue,
    ) -> R<String> {
        self.0
            .open_emergency_roster(&string(sealed)?)
            .map_err(js_err)
    }

    /// Emergency access, the contact's side: open the `sealed_key` that account
    /// `grantorId` (the access's `grantor.id`) sealed to this account for access
    /// `grantId`. Throws `decrypt_failed` if it isn't for this account, that grantor
    /// or that access.
    #[wasm_bindgen(js_name = openSealedEmergencyKey)]
    pub fn open_sealed_emergency_key(
        &self,
        #[wasm_bindgen(js_name = "grantorId", unchecked_param_type = "string")] grantor_id: JsValue,
        #[wasm_bindgen(js_name = "grantId", unchecked_param_type = "string")] grant_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] sealed: JsValue,
    ) -> R<EmergencyKey> {
        let (grantor_id, grant_id, sealed) =
            (string(grantor_id)?, string(grant_id)?, string(sealed)?);
        self.0
            .open_sealed_emergency_key(&grantor_id, &grant_id, &sealed)
            .map(EmergencyKey)
            .map_err(js_err)
    }

    /// Approve a sign-in request from another device, after the user picked, among
    /// `loginPhraseChoices(requesterPublicKey, n)`, `chosenPhrase` as the words the new
    /// device shows. Returns `{ sealed, code }`: `sealed` is the request's `sealed_key`
    /// (this account's key, and the Secret Key when `secretKey` is given, sealed to the
    /// request's public key); show `code` (6 digits) for the user to enter on the new
    /// device. Throws `phrase_mismatch` unless `chosenPhrase` is exactly
    /// `loginPhrase(requesterPublicKey)`, and for a malformed or low-order key.
    #[wasm_bindgen(js_name = approveLoginRequest, unchecked_return_type = "LoginApproval")]
    pub fn approve_login_request(
        &self,
        #[wasm_bindgen(js_name = "requesterPublicKey", unchecked_param_type = "string")]
        requester_public_key: JsValue,
        #[wasm_bindgen(js_name = "requestId", unchecked_param_type = "string")] request_id: JsValue,
        #[wasm_bindgen(js_name = "chosenPhrase", unchecked_param_type = "string")]
        chosen_phrase: JsValue,
        #[wasm_bindgen(js_name = "secretKey", unchecked_optional_param_type = "string | null")]
        secret_key: JsValue,
    ) -> R<JsValue> {
        let requester_public_key = string(requester_public_key)?;
        let request_id = string(request_id)?;
        let chosen_phrase = string(chosen_phrase)?;
        let secret_key = opt_string(secret_key)?;
        let approval = self
            .0
            .approve_login_request(
                &requester_public_key,
                &request_id,
                &chosen_phrase,
                secret_key.as_deref(),
            )
            .map_err(js_err)?;
        to_js(&LoginApproval {
            sealed: approval.sealed,
            code: approval.code,
        })
    }

    /// The `proof` for approving request `requestId`: its `challenge`, opened with this
    /// account's private key (base64url).
    #[wasm_bindgen(js_name = openLoginChallenge)]
    pub fn open_login_challenge(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] challenge: JsValue,
        #[wasm_bindgen(js_name = "requestId", unchecked_param_type = "string")] request_id: JsValue,
    ) -> R<String> {
        let (challenge, request_id) = (string(challenge)?, string(request_id)?);
        self.0
            .open_login_challenge(&challenge, &request_id)
            .map_err(js_err)
    }
}

/// `Account.approveLoginRequest`'s answer.
#[derive(Serialize)]
struct LoginApproval {
    sealed: String,
    code: String,
}

/// A new device's key pair for one sign-in request (its private half never leaves WASM).
#[wasm_bindgen]
pub struct LoginRequestKey(device_login::LoginRequestKey);

#[wasm_bindgen]
impl LoginRequestKey {
    pub fn generate() -> R<LoginRequestKey> {
        device_login::LoginRequestKey::generate()
            .map(LoginRequestKey)
            .map_err(js_err)
    }

    /// The request's `public_key` (base64url).
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.0.public_key()
    }

    /// The words this device shows (`loginPhrase` of its own public key).
    pub fn phrase(&self) -> String {
        self.0.phrase()
    }

    /// Open the approved request's `sealed_key` for account `accountId` (the sign-in's
    /// `user_id`). Throws if it was sealed to another key, account or request, or changed.
    /// What opens is usable only after `confirm(code)`.
    pub fn open(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] sealed: JsValue,
        #[wasm_bindgen(js_name = "accountId", unchecked_param_type = "string")] account_id: JsValue,
        #[wasm_bindgen(js_name = "requestId", unchecked_param_type = "string")] request_id: JsValue,
    ) -> R<ApprovedLogin> {
        let (sealed, account_id, request_id) =
            (string(sealed)?, string(account_id)?, string(request_id)?);
        self.0
            .open(&sealed, &account_id, &request_id)
            .map(ApprovedLogin)
            .map_err(js_err)
    }
}

/// An approved sign-in: the Account Key (it stays in WASM) and maybe the Secret Key, both
/// held back until `confirm` accepted the code the approving app shows.
#[wasm_bindgen]
pub struct ApprovedLogin(device_login::ApprovedLogin);

#[wasm_bindgen]
impl ApprovedLogin {
    #[wasm_bindgen(getter, js_name = accountId)]
    pub fn account_id(&self) -> String {
        self.0.account_id().to_owned()
    }

    /// Check the code the approving app shows (6 digits; spaces and hyphens are ignored).
    /// Throws `wrong_code` (see `attemptsLeft`), `too_many_wrong_codes` on the third wrong
    /// code and for good after it (start a new request), or a description for anything
    /// but 6 digits (not counted).
    pub fn confirm(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "string")] code: JsValue,
    ) -> R<()> {
        let code = string(code)?;
        self.0.confirm(&code).map_err(js_err)
    }

    /// Whether `confirm` accepted the code.
    #[wasm_bindgen(getter)]
    pub fn confirmed(&self) -> bool {
        self.0.is_confirmed()
    }

    /// Wrong codes `confirm` still takes (0 once refused).
    #[wasm_bindgen(getter, js_name = attemptsLeft)]
    pub fn attempts_left(&self) -> u32 {
        self.0.attempts_left()
    }

    /// The Secret Key (`PA1-…`) when the approving app included it; keep it like one the
    /// user typed, for unlocking with the master password later. Throws `not_confirmed`
    /// until `confirm` accepted the code.
    #[wasm_bindgen(js_name = secretKey)]
    pub fn secret_key(&self) -> R<Option<String>> {
        self.0.secret_key().map_err(js_err)
    }

    /// Unlock the account `bundle` the sign-in returned, without the master password.
    /// Throws `not_confirmed` until `confirm` accepted the code.
    pub fn unlock(&self, bundle: JsValue) -> R<Account> {
        let bundle: AccountBundle = from_js(bundle)?;
        self.0.unlock(&bundle).map(Account).map_err(js_err)
    }
}

/// Emergency access: the key of one access (one emergency contact), bound to its
/// grantor and access. It opens only the personal vault keys the grantor wrapped with
/// it for that access; the key itself never leaves WASM. The sealed box the contact
/// gets is anonymous, so a server could hand out one of its own making: show what it
/// opens read-only and never autofill it.
#[wasm_bindgen]
pub struct EmergencyKey(CoreEmergencyKey);

#[wasm_bindgen]
impl EmergencyKey {
    /// The grantor's account id.
    #[wasm_bindgen(getter, js_name = grantorId)]
    pub fn grantor_id(&self) -> String {
        self.0.grantor_id().to_owned()
    }

    /// The access this key belongs to.
    #[wasm_bindgen(getter, js_name = grantId)]
    pub fn grant_id(&self) -> String {
        self.0.grant_id().to_owned()
    }

    /// Seal this key to the contact's public key (check their fingerprint first): the
    /// access's `sealed_key`. Only a key from `Account.newEmergencyKey` can be sealed.
    /// Throws for a malformed or low-order key, and for a `grantorId` or `grantId` other
    /// than the key's own.
    #[wasm_bindgen(js_name = sealFor)]
    pub fn seal_for(
        &self,
        #[wasm_bindgen(js_name = "contactPublicKey", unchecked_param_type = "string")]
        contact_public_key: JsValue,
        #[wasm_bindgen(js_name = "grantorId", unchecked_param_type = "string")] grantor_id: JsValue,
        #[wasm_bindgen(js_name = "grantId", unchecked_param_type = "string")] grant_id: JsValue,
    ) -> R<String> {
        let contact_public_key = string(contact_public_key)?;
        let (grantor_id, grant_id) = (string(grantor_id)?, string(grant_id)?);
        self.0
            .seal_for(&contact_public_key, &grantor_id, &grant_id)
            .map_err(js_err)
    }

    /// Wrap personal vault `vaultId`'s key for this key's access: its `wrapped_key` in
    /// the access's `vault_keys`.
    #[wasm_bindgen(js_name = wrapVaultKey)]
    pub fn wrap_vault_key(
        &self,
        #[wasm_bindgen(js_name = "vaultKey")] vault_key: &VaultKey,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
    ) -> R<String> {
        self.0
            .wrap_vault_key(&vault_key.0, &string(vault_id)?)
            .map_err(js_err)
    }

    /// Open a vault key wrapped for vault `vaultId` and this key's access. Throws
    /// `decrypt_failed` for any other vault, access or key.
    #[wasm_bindgen(js_name = openVaultKey)]
    pub fn open_vault_key(
        &self,
        #[wasm_bindgen(js_name = "vaultId", unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] wrapped: JsValue,
    ) -> R<VaultKey> {
        let (vault_id, wrapped) = (string(vault_id)?, string(wrapped)?);
        self.0
            .open_vault_key(&vault_id, &wrapped)
            .map(VaultKey)
            .map_err(js_err)
    }
}

/// `Account.newEmergencyKey`'s answer.
#[wasm_bindgen]
pub struct NewEmergencyKey {
    key: Option<EmergencyKey>,
    wrapped: String,
}

#[wasm_bindgen]
impl NewEmergencyKey {
    /// The key wrapped with the account's key: the access's `grantor_key`.
    #[wasm_bindgen(getter)]
    pub fn wrapped(&self) -> String {
        self.wrapped.clone()
    }

    /// Take the key handle (can be called once).
    #[wasm_bindgen(js_name = takeKey)]
    pub fn take_key(&mut self) -> R<EmergencyKey> {
        self.key
            .take()
            .ok_or_else(|| JsError::new("key already taken"))
    }
}

/// Encrypts one attachment file in pieces (see `fileEncrypt`). The file is every
/// output of `push` and `finish`, concatenated in order. Call `free()` when done.
#[wasm_bindgen]
pub struct FileEncryptor(file::FileEncryptor);

#[wasm_bindgen]
impl FileEncryptor {
    /// `key` from `fileNewKey`; the item's id and the attachment's id as stored.
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] item_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] attachment_id: JsValue,
    ) -> R<FileEncryptor> {
        let (key, item_id, attachment_id) =
            (string(key)?, string(item_id)?, string(attachment_id)?);
        let key = FileKey::from_b64(&key).map_err(js_err)?;
        file::FileEncryptor::new(&key, &item_id, &attachment_id)
            .map(Self)
            .map_err(js_err)
    }

    /// More plaintext (any size; ~64 KiB–1 MiB pieces keep WASM memory small).
    /// Returns the ciphertext ready so far (may be empty).
    pub fn push(&mut self, chunk: &[u8]) -> R<Vec<u8>> {
        self.0.push(chunk).map_err(js_err)
    }

    /// The rest of the ciphertext. The encryptor can't be used afterwards.
    pub fn finish(&mut self) -> R<Vec<u8>> {
        self.0.finish().map_err(js_err)
    }
}

/// Decrypts one attachment file in pieces. Each output of `push` is authenticated
/// plaintext, in order; only a successful `finish` means the file is complete:
/// on any error (`decrypt_failed`), discard everything written so far.
#[wasm_bindgen]
pub struct FileDecryptor(file::FileDecryptor);

#[wasm_bindgen]
impl FileDecryptor {
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] item_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] attachment_id: JsValue,
    ) -> R<FileDecryptor> {
        let (key, item_id, attachment_id) =
            (string(key)?, string(item_id)?, string(attachment_id)?);
        let key = FileKey::from_b64(&key).map_err(js_err)?;
        file::FileDecryptor::new(&key, &item_id, &attachment_id)
            .map(Self)
            .map_err(js_err)
    }

    /// More ciphertext (any size). Returns the plaintext ready so far (may be empty).
    pub fn push(&mut self, chunk: &[u8]) -> R<Vec<u8>> {
        self.0.push(chunk).map_err(js_err)
    }

    /// The last piece of plaintext; throws `decrypt_failed` if the file was cut short.
    pub fn finish(&mut self) -> R<Vec<u8>> {
        self.0.finish().map_err(js_err)
    }
}

#[wasm_bindgen]
pub struct VaultKey(SymmetricKey);

#[wasm_bindgen]
impl VaultKey {
    /// Returns `{ id, vault_id, key, data }` ready for the API.
    #[wasm_bindgen(js_name = encryptItem)]
    pub fn encrypt_item(
        &self,
        item: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
    ) -> R<JsValue> {
        let (id, vault_id) = (string(id)?, string(vault_id)?);
        let item: Item = from_js(item)?;
        to_js(&EncryptedItem::encrypt(&item, &id, &vault_id, &self.0).map_err(js_err)?)
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
    pub fn encrypt_meta(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
        meta: JsValue,
    ) -> R<String> {
        let vault_id = string(vault_id)?;
        let v: serde_json::Value = from_js(meta)?;
        let json = serde_json::to_vec(&v).map_err(|e| JsError::new(&e.to_string()))?;
        keys::encrypt_vault_meta(&self.0, &vault_id, &json).map_err(js_err)
    }

    #[wasm_bindgen(js_name = decryptMeta)]
    pub fn decrypt_meta(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] meta: JsValue,
    ) -> R<JsValue> {
        let (vault_id, meta) = (string(vault_id)?, string(meta)?);
        let json = keys::decrypt_vault_meta(&self.0, &vault_id, &meta).map_err(js_err)?;
        let v: serde_json::Value =
            serde_json::from_slice(&json).map_err(|e| JsError::new(&e.to_string()))?;
        to_js(&v)
    }

    /// Seal this vault key to another member's public key.
    #[wasm_bindgen(js_name = shareTo)]
    pub fn share_to(
        &self,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
        #[wasm_bindgen(unchecked_param_type = "string")] recipient_public_key: JsValue,
    ) -> R<String> {
        let (vault_id, recipient_public_key) = (string(vault_id)?, string(recipient_public_key)?);
        keys::share_vault_key(&vault_id, &self.0, &recipient_public_key).map_err(js_err)
    }

    /// Wrap this key for the owner's own account (used after rotation).
    #[wasm_bindgen(js_name = wrapFor)]
    pub fn wrap_for(
        &self,
        account: &Account,
        #[wasm_bindgen(unchecked_param_type = "string")] vault_id: JsValue,
    ) -> R<String> {
        let vault_id = string(vault_id)?;
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

#[wasm_bindgen(typescript_custom_section)]
const LOGIN_TYPES: &str = r#"
/** `Account.approveLoginRequest`'s answer: `sealed` for the server, `code` (6 digits) to show. */
export interface LoginApproval { sealed: string; code: string }
"#;

/// The words both screens show for a sign-in request's public key (base64url): five
/// words of the EFF large wordlist. Work it out from the key you hold, never take the
/// server's `fingerprint_phrase`.
#[wasm_bindgen(js_name = loginPhrase)]
pub fn login_phrase(
    #[wasm_bindgen(js_name = "publicKey", unchecked_param_type = "string")] public_key: JsValue,
) -> R<String> {
    device_login::login_phrase(&string(public_key)?).map_err(js_err)
}

/// `count` (2–5) phrases for the approving app to offer, in random order: exactly one is
/// `loginPhrase(publicKey)`, the others are decoys sharing no word with it at the same
/// position. Offer them with "none of these"; pass the one the user picks to
/// `Account.approveLoginRequest`.
#[wasm_bindgen(js_name = loginPhraseChoices)]
pub fn login_phrase_choices(
    #[wasm_bindgen(js_name = "publicKey", unchecked_param_type = "string")] public_key: JsValue,
    count: u32,
) -> R<Vec<String>> {
    device_login::login_phrase_choices(&string(public_key)?, count as usize).map_err(js_err)
}

/// Restore an unlocked account from [`Account::to_session_bytes`].
#[wasm_bindgen(js_name = accountFromSessionBytes)]
pub fn account_from_session_bytes(
    #[wasm_bindgen(unchecked_param_type = "string")] account_id: JsValue,
    bytes: &[u8],
) -> R<Account> {
    let account_id = string(account_id)?;
    if bytes.len() != 64 {
        return Err(JsError::new("invalid session data"));
    }
    let account_key = SymmetricKey::from_slice(&bytes[..32]).map_err(js_err)?;
    let secret: [u8; 32] = bytes[32..].try_into().expect("checked length");
    Ok(Account(UnlockedAccount {
        account_id,
        account_key,
        keypair: passauth_core::crypto::KeyPair::from_secret_bytes(secret),
    }))
}

#[wasm_bindgen(js_name = createAccount)]
pub fn create_account(
    #[wasm_bindgen(unchecked_param_type = "string")] account_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
    with_secret_key: bool,
) -> R<NewAccount> {
    let (account_id, password) = (string(account_id)?, string(password)?);
    AccountBundle::create(&account_id, &password, with_secret_key)
        .map(NewAccount::from)
        .map_err(js_err)
}

/// `createAccount` following a server's KDF policy: memory = max(128 MiB,
/// `min_memory_mib`), passes = max(3, `min_iterations`) — pass `/api/config`
/// `policies.min_kdf_memory_mib` / `min_kdf_iterations`, or leave them out. A
/// minimum outside 64–1024 MiB or 3–20 passes throws `weak_kdf` / `kdf_too_strong`.
#[wasm_bindgen(js_name = createAccountWithKdf)]
pub fn create_account_with_kdf(
    #[wasm_bindgen(unchecked_param_type = "string")] account_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
    with_secret_key: bool,
    min_memory_mib: Option<u32>,
    min_iterations: Option<u32>,
) -> R<NewAccount> {
    let (account_id, password) = (string(account_id)?, string(password)?);
    let kdf = KdfParams::with_minimums(min_memory_mib, min_iterations).map_err(js_err)?;
    AccountBundle::create_with_kdf(&account_id, &password, with_secret_key, kdf)
        .map(NewAccount::from)
        .map_err(js_err)
}

// -------------------------------------------------------------------- Send

/// A new random send key: base64url of 32 bytes, for the link's fragment
/// (`/send/<id>#<key>`). Keep it only there and wrapped (`Account.wrapSendKey`).
#[wasm_bindgen(js_name = sendNewKey)]
pub fn send_new_key() -> R<String> {
    SendKey::generate().map(|k| k.to_b64()).map_err(js_err)
}

/// Encrypt a Send's `field` ("name" or "data"); returns the string the API takes.
#[wasm_bindgen(js_name = sendEncrypt)]
pub fn send_encrypt(
    #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] field: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] plaintext: JsValue,
) -> R<String> {
    let (key, field, plaintext) = (string(key)?, string(field)?, string(plaintext)?);
    let key = SendKey::from_b64(&key).map_err(js_err)?;
    let field = SendField::parse(&field).map_err(js_err)?;
    key.encrypt(field, plaintext.as_bytes()).map_err(js_err)
}

/// Decrypt a Send's `field`; needs no account (visitors). Throws `decrypt_failed`
/// for a wrong key, the other field or tampered data.
#[wasm_bindgen(js_name = sendDecrypt)]
pub fn send_decrypt(
    #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] field: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] ciphertext: JsValue,
) -> R<String> {
    let (key, field, ciphertext) = (string(key)?, string(field)?, string(ciphertext)?);
    let key = SendKey::from_b64(&key).map_err(js_err)?;
    let field = SendField::parse(&field).map_err(js_err)?;
    let bytes = key.decrypt(field, &ciphertext).map_err(js_err)?;
    String::from_utf8(bytes).map_err(|_| JsError::new("send text is not UTF-8"))
}

/// A new `access_salt` for a Send's password (Argon2id parameters + random salt).
#[wasm_bindgen(js_name = sendPasswordSalt)]
pub fn send_password_salt() -> R<String> {
    send::new_password_salt().map_err(js_err)
}

/// The `access_verifier` for `password` and a Send's `access_salt` (owner when
/// setting the password, visitor when opening). Runs Argon2id (128 MiB by default);
/// throws `weak_kdf` / `kdf_too_strong` for a salt outside 64–256 MiB, 3–6 passes,
/// 1–4 lanes.
#[wasm_bindgen(js_name = sendPasswordVerifier)]
pub fn send_password_verifier(
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] salt: JsValue,
) -> R<String> {
    let (password, salt) = (string(password)?, string(salt)?);
    send::password_verifier(&password, &salt).map_err(js_err)
}

// ------------------------------------------------------------- Attachments

/// A new random attachment key (base64url of 32 bytes) for the item's attachment list.
#[wasm_bindgen(js_name = fileNewKey)]
pub fn file_new_key() -> R<String> {
    FileKey::generate().map(|k| k.to_b64()).map_err(js_err)
}

/// A byte count from JavaScript: a whole number from 0 to 2^53 − 1.
fn js_size(n: f64) -> R<u64> {
    if n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9_007_199_254_740_991.0 {
        Ok(n as u64)
    } else {
        Err(JsError::new("invalid size"))
    }
}

/// The encrypted size of a file of `plain_length` bytes: the `size` for
/// `POST /items/{id}/attachments` and for the server's attachment size limit.
#[wasm_bindgen(js_name = fileEncryptedSize)]
pub fn file_encrypted_size(plain_length: f64) -> R<f64> {
    file::encrypted_size(js_size(plain_length)?)
        .map(|n| n as f64)
        .map_err(js_err)
}

/// The file size behind an encrypted size (throws for a size no file encrypts to).
#[wasm_bindgen(js_name = filePlainSize)]
pub fn file_plain_size(encrypted_length: f64) -> R<f64> {
    file::plain_size(js_size(encrypted_length)?)
        .map(|n| n as f64)
        .map_err(js_err)
}

/// Encrypt a whole (small) file at once; use `FileEncryptor` for large ones.
#[wasm_bindgen(js_name = fileEncrypt)]
pub fn file_encrypt(
    #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] item_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] attachment_id: JsValue,
    plaintext: &[u8],
) -> R<Vec<u8>> {
    let (key, item_id, attachment_id) = (string(key)?, string(item_id)?, string(attachment_id)?);
    let key = FileKey::from_b64(&key).map_err(js_err)?;
    file::encrypt(&key, &item_id, &attachment_id, plaintext).map_err(js_err)
}

/// Decrypt a whole (small) file at once; throws `decrypt_failed` unless it is whole and authentic.
#[wasm_bindgen(js_name = fileDecrypt)]
pub fn file_decrypt(
    #[wasm_bindgen(unchecked_param_type = "string")] key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] item_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] attachment_id: JsValue,
    ciphertext: &[u8],
) -> R<Vec<u8>> {
    let (key, item_id, attachment_id) = (string(key)?, string(item_id)?, string(attachment_id)?);
    let key = FileKey::from_b64(&key).map_err(js_err)?;
    file::decrypt(&key, &item_id, &attachment_id, ciphertext).map_err(js_err)
}

/// Derive master keys from what prelogin returned (`{ account_id, kdf, secret_key_required }`).
/// Throws `weak_kdf` / `kdf_too_strong` for parameters outside the core's range.
#[wasm_bindgen(js_name = deriveMasterKeys)]
pub fn derive_master_keys(
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string | null | undefined")] secret_key: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] account_id: JsValue,
    kdf: JsValue,
    secret_key_required: bool,
) -> R<MasterKeys> {
    let password = string(password)?;
    let secret_key = opt_string(secret_key)?;
    let account_id = string(account_id)?;
    let kdf: KdfParams = from_js(kdf)?;
    keys::derive_master_keys(
        &password,
        secret_key.as_deref(),
        &account_id,
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
pub fn opaque_register_finish(
    state: &[u8],
    master: &MasterKeys,
    #[wasm_bindgen(unchecked_param_type = "string")] response: JsValue,
) -> R<String> {
    let response = string(response)?;
    opaque::register_finish(state, &master.0.login, &response).map_err(js_err)
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
pub fn opaque_login_finish(
    state: &[u8],
    master: &MasterKeys,
    #[wasm_bindgen(unchecked_param_type = "string")] response: JsValue,
) -> R<String> {
    let response = string(response)?;
    opaque::login_finish(state, &master.0.login, &response).map_err(js_err)
}

/// Parse an export from another password manager. Throws `password_required`
/// for password-protected files when `password` is missing.
#[wasm_bindgen(js_name = importFile)]
pub fn import_file(
    data: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "string | null")] password: JsValue,
) -> R<JsValue> {
    let password = opt_string(password)?;
    to_js(&import::import(data, password.as_deref()).map_err(js_err)?)
}

/// The browser's clock (std's SystemTime isn't available in wasm32).
fn unix_now() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Plaintext PassAuth JSON export of an array of items.
#[wasm_bindgen(js_name = exportVaultJson)]
pub fn export_vault_json(items: JsValue) -> R<String> {
    let items: Vec<Item> = from_js(items)?;
    export::json_at(&items, unix_now()).map_err(js_err)
}

/// Password-protected PassAuth JSON export (password: at least 10 characters).
#[wasm_bindgen(js_name = exportVaultEncrypted)]
pub fn export_vault_encrypted(
    items: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
) -> R<String> {
    let password = string(password)?;
    let items: Vec<Item> = from_js(items)?;
    export::encrypted_at(&items, &password, unix_now()).map_err(js_err)
}

/// CSV export of logins and secure notes.
#[wasm_bindgen(js_name = exportVaultCsv)]
pub fn export_vault_csv(items: JsValue) -> R<String> {
    let items: Vec<Item> = from_js(items)?;
    export::csv(&items).map_err(js_err)
}

#[derive(Serialize)]
struct TotpCode {
    code: String,
    remaining: u64,
    period: u64,
}

#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(
    #[wasm_bindgen(unchecked_param_type = "string")] secret: JsValue,
    unix_seconds: f64,
) -> R<JsValue> {
    let t = totp::Totp::parse(&string(secret)?).map_err(js_err)?;
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
pub fn estimate_bits(#[wasm_bindgen(unchecked_param_type = "string")] password: JsValue) -> R<f64> {
    Ok(generator::estimate_bits(&string(password)?))
}

#[wasm_bindgen]
pub fn fingerprint(
    #[wasm_bindgen(unchecked_param_type = "string")] public_key: JsValue,
) -> R<String> {
    let pk: [u8; 32] = unb64(&string(public_key)?)
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

// ------------------------------------------------------------------ sites (passauth_core::site)

#[wasm_bindgen(typescript_custom_section)]
const SITE_TYPES: &str = r#"
/** "default" | "domain" | "host" | "starts_with" | "exact" | "regex" | "never" */
export type SiteUrlMatch = string;
/** A saved website for `matchUrls` (`match` missing = "default"). `allowRegex`: the login is in the user's own vault. */
export interface SiteSavedUrl { url: string; match?: SiteUrlMatch; allowRegex: boolean }
/** A login matching the page, for `planSave`. */
export interface SaveCandidate { id: string; name: string; username: string; password: string; writable: boolean; personal: boolean; vault?: string }
/** A login offered under "Save in" (`vault`: set for a shared vault). */
export interface SaveTarget { id: string; name: string; username: string; vault?: string }
export type SavePlan =
  | { action: "none" }
  | { action: "create"; target: "new"; targets: SaveTarget[] }
  | { action: "update"; reason: "same" | "blank" | "only"; target: string; targets: SaveTarget[] };
/** A login for `passkeySaveTargets` (`urls`: its websites as saved). */
export interface PasskeyLogin { id: string; name: string; username: string; urls: string[]; writable: boolean; personal: boolean; vault?: string }
export interface PasskeyTarget { id: string; name: string; username: string; preferred: boolean; vault?: string }
"#;

fn url_match(s: &str) -> Option<passauth_core::site::UrlMatch> {
    passauth_core::site::parse_url_match(s)
}

/// The user's "default match detection" setting; anything unknown counts as "domain".
fn default_match(s: &str) -> passauth_core::site::UrlMatch {
    url_match(s).unwrap_or(passauth_core::site::UrlMatch::Domain)
}

/// Canonical host: IDNA to ASCII, lower case, IPv4/IPv6 normalised (IPv6 in brackets), no
/// trailing dot. `undefined` when it isn't a valid host.
#[wasm_bindgen(js_name = normalizeHost)]
pub fn normalize_host(
    #[wasm_bindgen(unchecked_param_type = "string")] host: JsValue,
) -> R<Option<String>> {
    Ok(passauth_core::site::normalize_host(&string(host)?))
}

/// Public suffix by the full list ("co.uk", "myfritz.net", "com"); "" for IP addresses and
/// invalid hosts.
#[wasm_bindgen(js_name = publicSuffix)]
pub fn public_suffix(#[wasm_bindgen(unchecked_param_type = "string")] host: JsValue) -> R<String> {
    Ok(passauth_core::site::public_suffix(&string(host)?))
}

/// Registrable domain ("example.co.uk", "nas.myfritz.net"); `undefined` for a public suffix
/// itself, IP addresses and invalid hosts.
#[wasm_bindgen(js_name = registrableDomain)]
pub fn registrable_domain(
    #[wasm_bindgen(unchecked_param_type = "string")] host: JsValue,
) -> R<Option<String>> {
    Ok(passauth_core::site::registrable_domain(&string(host)?))
}

/// The site "domain" matching compares: the registrable domain, else the host itself.
#[wasm_bindgen(js_name = baseDomain)]
pub fn base_domain(#[wasm_bindgen(unchecked_param_type = "string")] host: JsValue) -> R<String> {
    Ok(passauth_core::site::base_domain(&string(host)?))
}

#[wasm_bindgen(js_name = isPublicSuffix)]
pub fn is_public_suffix(#[wasm_bindgen(unchecked_param_type = "string")] host: JsValue) -> R<bool> {
    Ok(passauth_core::site::is_public_suffix(&string(host)?))
}

/// "<date> <commit>" of the embedded Public Suffix List.
#[wasm_bindgen(js_name = publicSuffixListVersion)]
pub fn public_suffix_list_version() -> String {
    passauth_core::site::public_suffix_list_version()
}

/// Does the page match the saved website? `page` must be an absolute http(s) address.
/// `match` / `defaultMatch` are `SiteUrlMatch` strings (an unknown `match` never matches;
/// an unknown `defaultMatch` counts as "domain"; with `defaultMatch` "regex", "default"
/// treats a plain address as "domain"); `allowRegex`: false for a login in a vault somebody
/// shared.
#[wasm_bindgen(js_name = matchesUrl)]
pub fn matches_url(
    #[wasm_bindgen(unchecked_param_type = "string")] page: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
    #[wasm_bindgen(js_name = "match", unchecked_param_type = "string")] match_type: JsValue,
    #[wasm_bindgen(js_name = "defaultMatch", unchecked_param_type = "string")] default: JsValue,
    #[wasm_bindgen(js_name = "allowRegex")] allow_regex: bool,
) -> R<bool> {
    let (page, url) = (string(page)?, string(url)?);
    let (match_type, default) = (string(match_type)?, string(default)?);
    Ok(url_match(&match_type).is_some_and(|m| {
        passauth_core::site::matches_url(&page, &url, m, default_match(&default), allow_regex)
    }))
}

/// What a saved website is matched as: `match` resolved with `defaultMatch` (an unknown one
/// counts as "domain"; with "regex", "default" keeps a plain address as "domain"), never
/// "default"; "never" for an unknown `match`. An entry runs as a pattern exactly when this
/// is "regex": show `regexError` and `regexWarning` for those.
#[wasm_bindgen(js_name = resolveMatch, unchecked_return_type = "SiteUrlMatch")]
pub fn resolve_match(
    #[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
    #[wasm_bindgen(js_name = "match", unchecked_param_type = "string")] match_type: JsValue,
    #[wasm_bindgen(js_name = "defaultMatch", unchecked_param_type = "string")] default: JsValue,
) -> R<String> {
    let (url, match_type, default) = (string(url)?, string(match_type)?, string(default)?);
    let resolved = url_match(&match_type).map_or(passauth_core::site::UrlMatch::Never, |m| {
        passauth_core::site::resolve_match(&url, m, default_match(&default))
    });
    Ok(resolved.as_str().to_owned())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedUrl {
    #[serde(default)]
    url: String,
    /// Missing means "default", as in items.
    #[serde(default, rename = "match")]
    match_type: Option<String>,
    /// Missing means false: only the user's own logins may use regular expressions.
    #[serde(default)]
    allow_regex: bool,
}

/// `matchesUrl` for many saved websites against one page (parsed once): one boolean per entry.
#[wasm_bindgen(js_name = matchUrls, unchecked_return_type = "boolean[]")]
pub fn match_urls(
    #[wasm_bindgen(unchecked_param_type = "string")] page: JsValue,
    #[wasm_bindgen(js_name = "defaultMatch", unchecked_param_type = "string")] default: JsValue,
    #[wasm_bindgen(unchecked_param_type = "SiteSavedUrl[]")] urls: JsValue,
) -> R<JsValue> {
    let (page, default) = (string(page)?, string(default)?);
    let urls: Vec<SavedUrl> = from_js(urls)?;
    let page = passauth_core::site::Page::parse(&page);
    let fallback = default_match(&default);
    let out: Vec<bool> = urls
        .iter()
        .map(|u| {
            match (
                &page,
                url_match(u.match_type.as_deref().unwrap_or("default")),
            ) {
                (Some(p), Some(m)) => p.matches(&u.url, m, fallback, u.allow_regex),
                _ => false,
            }
        })
        .collect();
    to_js(&out)
}

/// True when filling would send a secret saved for an https site to an http page.
#[wasm_bindgen]
pub fn downgrade(
    #[wasm_bindgen(unchecked_param_type = "string")] page: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] url: JsValue,
    #[wasm_bindgen(js_name = "match", unchecked_param_type = "string")] match_type: JsValue,
) -> R<bool> {
    let (page, url, match_type) = (string(page)?, string(url)?, string(match_type)?);
    let m = url_match(&match_type).unwrap_or(passauth_core::site::UrlMatch::Domain);
    Ok(passauth_core::site::downgrade(&page, &url, m))
}

/// Why a website pattern is refused (too long, too large, unsupported syntax such as
/// look-around), or `undefined` when it is evaluated.
#[wasm_bindgen(js_name = regexError)]
pub fn regex_error(
    #[wasm_bindgen(unchecked_param_type = "string")] pattern: JsValue,
) -> R<Option<String>> {
    Ok(passauth_core::site::regex_error(&string(pattern)?))
}

/// Why an explicit website pattern can also match other websites (a warning for the item
/// editor: not anchored as `^https://<host>/`), or `undefined` when it pins its website or
/// is refused (`regexError` says why then).
#[wasm_bindgen(js_name = regexWarning)]
pub fn regex_warning(
    #[wasm_bindgen(unchecked_param_type = "string")] pattern: JsValue,
) -> R<Option<String>> {
    Ok(passauth_core::site::regex_warning(&string(pattern)?))
}

/// The save rule (docs/ARCHITECTURE.md "Save rule").
#[wasm_bindgen(js_name = planSave, unchecked_return_type = "SavePlan")]
pub fn plan_save(
    #[wasm_bindgen(unchecked_param_type = "SaveCandidate[]")] candidates: JsValue,
    #[wasm_bindgen(js_name = "typedUser", unchecked_param_type = "string")] typed_user: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] password: JsValue,
) -> R<JsValue> {
    let (typed_user, password) = (string(typed_user)?, string(password)?);
    let candidates: Vec<passauth_core::site::SaveCandidate> = from_js(candidates)?;
    to_js(&passauth_core::site::plan_save(
        &candidates,
        &typed_user,
        &password,
    ))
}

#[derive(serde::Deserialize)]
struct Offered {
    #[serde(default)]
    targets: Vec<passauth_core::site::SaveTarget>,
}

/// The prompt's answer if this save offered it ("new" or one of `plan.targets`), else `undefined`.
#[wasm_bindgen(js_name = chosenSaveTarget)]
pub fn chosen_save_target(
    #[wasm_bindgen(unchecked_param_type = "{ targets: SaveTarget[] }")] plan: JsValue,
    #[wasm_bindgen(unchecked_param_type = "unknown")] answer: JsValue,
) -> R<Option<String>> {
    let plan: Offered = from_js(plan)?;
    Ok(answer
        .as_string()
        .and_then(|a| passauth_core::site::chosen_target(&plan.targets, &a)))
}

/// Logins a new passkey can be saved in, best first (`preferred`: preselect it).
#[wasm_bindgen(js_name = passkeySaveTargets, unchecked_return_type = "PasskeyTarget[]")]
pub fn passkey_save_targets(
    #[wasm_bindgen(unchecked_param_type = "PasskeyLogin[]")] logins: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] host: JsValue,
    #[wasm_bindgen(js_name = "rpId", unchecked_param_type = "string")] rp_id: JsValue,
    #[wasm_bindgen(js_name = "userName", unchecked_param_type = "string")] user_name: JsValue,
    #[wasm_bindgen(js_name = "displayName", unchecked_param_type = "string")] display_name: JsValue,
) -> R<JsValue> {
    let (host, rp_id) = (string(host)?, string(rp_id)?);
    let (user_name, display_name) = (string(user_name)?, string(display_name)?);
    let logins: Vec<passauth_core::site::PasskeyLogin> = from_js(logins)?;
    to_js(&passauth_core::site::passkey_save_targets(
        &logins,
        &host,
        &rp_id,
        &user_name,
        &display_name,
    ))
}

/// The preselected "Save in" choice: the first preferred target's id, else "new".
#[wasm_bindgen(js_name = passkeyDefaultTarget)]
pub fn passkey_default_target(
    #[wasm_bindgen(unchecked_param_type = "PasskeyTarget[]")] targets: JsValue,
) -> R<String> {
    let targets: Vec<passauth_core::site::PasskeyTarget> = from_js(targets)?;
    Ok(passauth_core::site::passkey_default_target(&targets))
}

/// The RP ID for a WebAuthn request from `origin` (the requested one if allowed, else the
/// origin's host). Throws an `Error` named "SecurityError" whose message is the DOMException
/// message for the page.
#[wasm_bindgen(js_name = effectiveRpId)]
pub fn effective_rp_id(
    #[wasm_bindgen(
        js_name = "requestedRpId",
        unchecked_param_type = "string | null | undefined"
    )]
    requested_rp_id: JsValue,
    #[wasm_bindgen(unchecked_param_type = "string")] origin: JsValue,
) -> Result<String, JsValue> {
    let requested_rp_id = opt_string(requested_rp_id)?;
    let origin = string(origin)?;
    passauth_core::site::effective_rp_id(requested_rp_id.as_deref(), &origin).map_err(|e| {
        let error = js_sys::Error::new(e.message());
        error.set_name("SecurityError");
        error.into()
    })
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
