//! Account key hierarchy.
//!
//! ```text
//! password (+ Secret Key) ─Argon2id─► MasterKeys { auk, login }
//! AUK ─wraps─► Account Key ─wraps─► X25519 private key
//!                         ├─wraps─► personal Vault Keys ─wraps─► Item Keys
//!                         └─wraps─► Emergency Keys (one per emergency contact)
//!                                     └─wraps─► personal Vault Keys
//! ```
//! Everything in [`AccountBundle`] is safe to store on the server.

use serde::{Deserialize, Serialize};

use crate::crypto::{KeyPair, SymmetricKey, seal_to};
use crate::item::{b64, unb64};
use crate::kdf::{KdfParams, MasterKeys, SecretKey};
use crate::send::{SendContentKey, SendKey};
use crate::{Error, Result};

fn aad(kind: &str, id: &str) -> Vec<u8> {
    format!("passauth/{kind}/v1/{id}").into_bytes()
}

/// Associated data of a send key wrapped by the Account Key. Sends get their id
/// from the server after the app encrypted, so there is no id to bind.
const SEND_KEY_AAD: &[u8] = b"passauth/send-key/v1";
/// Associated data of a v2 Send's content key wrapped by the Account Key
/// (`owner_content_key`; unbound to the id like [`SEND_KEY_AAD`]).
const SEND_CONTENT_KEY_AAD: &[u8] = b"passauth/send-content-key/v1";

/// Emergency access (v2) kinds: an emergency key wrapped by the grantor's Account
/// Key (bound to grantor and access), sealed to the contact (the same), a personal
/// vault key wrapped by an emergency key (grantor, access and vault), and the
/// grantor's roster of emergency contacts sealed by their Account Key (account).
const EMERGENCY_KEY: &str = "emergency-key";
const SEALED_EMERGENCY_KEY: &str = "emergency-key-sealed";
const EMERGENCY_VAULT_KEY: &str = "emergency-vault-key";
const EMERGENCY_ROSTER: &str = "emergency-roster";

/// The account's profile picture, sealed by its Account Key (bound to the account).
const AVATAR_AAD: &str = "passauth/avatar/v1/";
/// Largest profile picture the apps seal: they send a small square JPEG (≈256 px).
pub const MAX_AVATAR_BYTES: usize = 256 * 1024;

/// `passauth/<kind>/v2/<id>/<id>…`: every id non-empty and without '/', so two
/// lists of ids never give the same bytes.
fn emergency_aad(kind: &str, ids: &[&str]) -> Result<Vec<u8>> {
    if ids.iter().any(|id| id.is_empty() || id.contains('/')) {
        return Err(Error::Malformed(
            "emergency access ids must be non-empty, without '/'",
        ));
    }
    Ok(format!("passauth/{kind}/v2/{}", ids.join("/")).into_bytes())
}

fn public_key(b64_key: &str) -> Result<[u8; 32]> {
    unb64(b64_key)?
        .try_into()
        .map_err(|_| Error::Malformed("public key length"))
}

/// Encrypted key material stored server-side. The server cannot open any of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBundle {
    pub account_id: String,
    pub kdf: KdfParams,
    pub secret_key_enabled: bool,
    pub wrapped_account_key: String,
    pub public_key: String,
    pub wrapped_private_key: String,
}

/// Decrypted keys held in client memory while the vault is unlocked.
pub struct UnlockedAccount {
    pub account_id: String,
    pub account_key: SymmetricKey,
    pub keypair: KeyPair,
}

pub struct NewAccount {
    pub bundle: AccountBundle,
    pub unlocked: UnlockedAccount,
    /// Use `master.login` as the OPAQUE registration password.
    pub master: MasterKeys,
    /// Present only when the Secret Key is enabled; show it once in the Emergency Kit.
    pub secret_key: Option<String>,
}

/// Derive master keys for an existing account from what prelogin returned.
pub fn derive_master_keys(
    password: &str,
    secret_key: Option<&str>,
    account_id: &str,
    kdf: &KdfParams,
    secret_key_enabled: bool,
) -> Result<MasterKeys> {
    let sk = match (secret_key_enabled, secret_key) {
        (true, Some(s)) => Some(SecretKey::parse(s)?),
        (true, None) => return Err(Error::InvalidSecretKey),
        (false, _) => None,
    };
    derive(password, kdf, sk.as_ref(), account_id)
}

impl AccountBundle {
    pub fn create(account_id: &str, password: &str, with_secret_key: bool) -> Result<NewAccount> {
        Self::create_with_kdf(
            account_id,
            password,
            with_secret_key,
            KdfParams::new_default()?,
        )
    }

    pub fn create_with_kdf(
        account_id: &str,
        password: &str,
        with_secret_key: bool,
        kdf: KdfParams,
    ) -> Result<NewAccount> {
        let sk = with_secret_key.then(SecretKey::generate).transpose()?;
        let master = derive(password, &kdf, sk.as_ref(), account_id)?;
        let account_key = SymmetricKey::generate()?;
        let keypair = KeyPair::generate()?;
        let bundle = AccountBundle {
            account_id: account_id.to_owned(),
            secret_key_enabled: sk.is_some(),
            wrapped_account_key: b64(&master
                .auk
                .wrap(&account_key, &aad("account-key", account_id))?),
            public_key: b64(&keypair.public_bytes()),
            wrapped_private_key: b64(
                &account_key.encrypt(&keypair.secret_bytes(), &aad("private-key", account_id))?
            ),
            kdf,
        };
        Ok(NewAccount {
            bundle,
            unlocked: UnlockedAccount {
                account_id: account_id.to_owned(),
                account_key,
                keypair,
            },
            master,
            secret_key: sk.map(|k| k.format()),
        })
    }

    pub fn unlock(&self, auk: &SymmetricKey) -> Result<UnlockedAccount> {
        let account_key = auk.unwrap_key(
            &unb64(&self.wrapped_account_key)?,
            &aad("account-key", &self.account_id),
        )?;
        self.unlock_with_account_key(account_key)
    }

    /// Unlock with the Account Key itself instead of the master password (a new device
    /// that another of the account's apps sealed the key to, `device_login`): opens the
    /// private key and checks it against `public_key`, so a key for another account fails.
    pub fn unlock_with_account_key(&self, account_key: SymmetricKey) -> Result<UnlockedAccount> {
        let id = &self.account_id;
        let secret = zeroize::Zeroizing::new(
            account_key.decrypt(&unb64(&self.wrapped_private_key)?, &aad("private-key", id))?,
        );
        let secret: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            secret
                .as_slice()
                .try_into()
                .map_err(|_| Error::Malformed("private key"))?,
        );
        let keypair = KeyPair::from_secret_bytes(*secret);
        if b64(&keypair.public_bytes()) != self.public_key {
            return Err(Error::Malformed("public key does not match private key"));
        }
        Ok(UnlockedAccount {
            account_id: id.clone(),
            account_key,
            keypair,
        })
    }

    /// Re-wrap the Account Key for a new password and/or Secret Key setting.
    /// Vault data is untouched. The caller must also re-register OPAQUE with
    /// the returned `master.login`.
    ///
    /// With `with_secret_key`, `existing_secret_key` is kept when given;
    /// otherwise a new one is generated and returned in `secret_key` (which
    /// is `None` whenever the user already has their key).
    pub fn rewrap(
        &self,
        unlocked: &UnlockedAccount,
        new_password: &str,
        with_secret_key: bool,
        existing_secret_key: Option<&str>,
    ) -> Result<NewAccount> {
        self.rewrap_with_kdf(
            unlocked,
            new_password,
            with_secret_key,
            existing_secret_key,
            KdfParams::new_default()?,
        )
    }

    /// [`rewrap`](Self::rewrap) with these KDF parameters (e.g.
    /// [`KdfParams::with_minimums`] for a server's policy, or a policy fix with the
    /// same password). The bundle must be the unlocked account's own (same account id
    /// and public key), or a wrap that can never unlock would replace the working one.
    pub fn rewrap_with_kdf(
        &self,
        unlocked: &UnlockedAccount,
        new_password: &str,
        with_secret_key: bool,
        existing_secret_key: Option<&str>,
        kdf: KdfParams,
    ) -> Result<NewAccount> {
        if self.account_id != unlocked.account_id {
            return Err(Error::Malformed("the bundle belongs to another account"));
        }
        if public_key(&self.public_key)? != unlocked.keypair.public_bytes() {
            return Err(Error::Malformed(
                "the bundle's public key is not the account's",
            ));
        }
        let (sk, generated) = match (with_secret_key, existing_secret_key) {
            (false, _) => (None, false),
            (true, Some(s)) => (Some(SecretKey::parse(s)?), false),
            (true, None) => (Some(SecretKey::generate()?), true),
        };
        let master = derive(new_password, &kdf, sk.as_ref(), &self.account_id)?;
        let mut bundle = self.clone();
        bundle.kdf = kdf;
        bundle.secret_key_enabled = sk.is_some();
        bundle.wrapped_account_key = b64(&master
            .auk
            .wrap(&unlocked.account_key, &aad("account-key", &self.account_id))?);
        Ok(NewAccount {
            bundle,
            unlocked: UnlockedAccount {
                account_id: unlocked.account_id.clone(),
                account_key: unlocked.account_key.clone(),
                keypair: unlocked.keypair.clone(),
            },
            master,
            secret_key: sk.filter(|_| generated).map(|k| k.format()),
        })
    }
}

/// Tests (and the `insecure-test-kdf` feature, used only by other crates'
/// test suites) skip the KDF floor so tests don't burn 128 MiB per hash.
fn derive(pw: &str, kdf: &KdfParams, sk: Option<&SecretKey>, id: &str) -> Result<MasterKeys> {
    if cfg!(any(test, feature = "insecure-test-kdf")) {
        crate::kdf::derive_master_unchecked(pw, kdf, sk, id)
    } else {
        crate::kdf::derive_master(pw, kdf, sk, id)
    }
}

/// Which account-wrap format apps write is a runtime choice since migration 16: v2
/// (epoch-bound) when the server's `/sync` says every app signed in to the account reads
/// it (`user.account_wraps_v2`, a compatibility hint only: a server that lies can only
/// make apps write v1, as before), else v1 ([`UnlockedAccount::wrap_vault_key`]). Old-key
/// replay is stopped by key ids and retired key ids in the account's key pins (`sharing`)
/// either way; v1 wraps of an epoch at or below the highest epoch this account opened
/// from a v2 wrap are refused (`KeyPins::legacy_wrap_allowed`).
///
/// The marker byte before a v2 account wrap (`0x02 ‖ version ‖ nonce ‖ ciphertext`);
/// a v1 wrap starts with the cipher's version byte (`0x01`).
const BOUND_WRAP: u8 = 0x02;

/// Associated data of a v2 account wrap: `passauth/vault-key/v2/<vault id>/<key epoch>`,
/// bound to the epoch it was written for (the epoch is the last part and a number, so
/// the bytes are unambiguous). v1 is `passauth/vault-key/v1/<vault id>`.
fn vault_key_aad_v2(vault_id: &str, key_epoch: u64) -> Vec<u8> {
    format!("passauth/vault-key/v2/{vault_id}/{key_epoch}").into_bytes()
}

/// Whether an `account` wrap is in the epoch-bound v2 format (its first byte is the
/// `0x02` marker). Apps tell the key pins so after opening it (`VaultObservation`
/// `bound_wrap`), which then refuse v1 wraps of that vault at or below that epoch.
/// Malformed base64 is `false` (opening it fails anyway).
pub fn wrap_is_bound(wrapped: &str) -> bool {
    unb64(wrapped).is_ok_and(|w| w.first() == Some(&BOUND_WRAP))
}

impl UnlockedAccount {
    /// Whether `bundle` is this account's own (review round 5, session restore): its
    /// `account_id` is this account's id, its private-key blob opens under this Account
    /// Key with associated data `passauth/private-key/v1/<bundle's account id>` to this
    /// account's X25519 private key, and its `public_key` is this account's. Only the
    /// holder of the Account Key can make such a blob, so a `true` here authenticates the
    /// bundle's account id: restore a session with the stored bundle's id, then refuse it
    /// (ask for the master password) unless this is `true`; check every bundle `/sync`
    /// sends the same way before storing it. Malformed bundles are `false`.
    pub fn matches_bundle(&self, bundle: &AccountBundle) -> bool {
        use subtle::ConstantTimeEq;
        if bundle.account_id != self.account_id
            || bundle.public_key != b64(&self.keypair.public_bytes())
        {
            return false;
        }
        let Ok(blob) = unb64(&bundle.wrapped_private_key) else {
            return false;
        };
        let Ok(secret) = self
            .account_key
            .decrypt(&blob, &aad("private-key", &bundle.account_id))
        else {
            return false;
        };
        let secret = zeroize::Zeroizing::new(secret);
        let own = zeroize::Zeroizing::new(self.keypair.secret_bytes());
        secret.len() == own.len() && bool::from(secret.as_slice().ct_eq(own.as_slice()))
    }

    /// A new vault key and its v1 `account` wrap ([`wrap_vault_key`](Self::wrap_vault_key)).
    pub fn new_vault_key(&self, vault_id: &str) -> Result<(SymmetricKey, String)> {
        let key = SymmetricKey::generate()?;
        let wrapped = self.wrap_vault_key(&key, vault_id)?;
        Ok((key, wrapped))
    }

    /// A new vault key and its v2 `account` wrap at `key_epoch`
    /// ([`wrap_vault_key_bound`](Self::wrap_vault_key_bound)): for a new vault (epoch 0)
    /// when `/sync` `user.account_wraps_v2` is true.
    pub fn new_vault_key_bound(
        &self,
        vault_id: &str,
        key_epoch: u64,
    ) -> Result<(SymmetricKey, String)> {
        let key = SymmetricKey::generate()?;
        let wrapped = self.wrap_vault_key_bound(&key, vault_id, key_epoch)?;
        Ok((key, wrapped))
    }

    /// Wrap `key` as `vault_id`'s key with this account's key (`key_kind` `account`,
    /// base64url) in the v1 format (no epoch): what apps write while `/sync`
    /// `user.account_wraps_v2` is not true (some app of the account may read only v1).
    pub fn wrap_vault_key(&self, key: &SymmetricKey, vault_id: &str) -> Result<String> {
        Ok(b64(&self
            .account_key
            .wrap(key, &aad("vault-key", vault_id))?))
    }

    /// Wrap `key` as `vault_id`'s key at `key_epoch` in the epoch-bound v2 format
    /// (`0x02` marker, associated data with the epoch): what apps write when `/sync`
    /// `user.account_wraps_v2` is true. `key_epoch` is the epoch the vault has *after*
    /// the write: 0 for a new vault, the row's `key_epoch` + 1 for a key replacement.
    pub fn wrap_vault_key_bound(
        &self,
        key: &SymmetricKey,
        vault_id: &str,
        key_epoch: u64,
    ) -> Result<String> {
        let mut out = vec![BOUND_WRAP];
        out.extend(
            self.account_key
                .wrap(key, &vault_key_aad_v2(vault_id, key_epoch))?,
        );
        Ok(b64(&out))
    }

    /// Open an `account` wrap of `vault_id`'s key; `key_epoch` is the row's `key_epoch`.
    /// The format is told by its first byte (no trial decryption): a v2 wrap (`0x02`)
    /// opens only for the epoch it was written for; a v1 wrap (no epoch) only with
    /// `legacy_allowed` (`KeyPins::legacy_wrap_allowed(vault_id, key_epoch)`).
    pub fn open_vault_key(
        &self,
        vault_id: &str,
        key_epoch: u64,
        wrapped: &str,
        legacy_allowed: bool,
    ) -> Result<SymmetricKey> {
        let wrapped = unb64(wrapped)?;
        match wrapped.split_first() {
            Some((&BOUND_WRAP, rest)) => self
                .account_key
                .unwrap_key(rest, &vault_key_aad_v2(vault_id, key_epoch)),
            _ if legacy_allowed => self
                .account_key
                .unwrap_key(&wrapped, &aad("vault-key", vault_id)),
            _ => Err(Error::Decrypt),
        }
    }

    /// Open a vault key that another member sealed to this account's public key.
    pub fn open_shared_vault_key(&self, vault_id: &str, sealed: &str) -> Result<SymmetricKey> {
        let raw = zeroize::Zeroizing::new(
            self.keypair
                .open(&unb64(sealed)?, &aad("shared-vault-key", vault_id))?,
        );
        SymmetricKey::from_slice(&raw)
    }

    /// Wrap a Send's key for its owner (`owner_key`, base64url).
    pub fn wrap_send_key(&self, key: &SendKey) -> Result<String> {
        Ok(b64(&self.account_key.wrap(key.key(), SEND_KEY_AAD)?))
    }

    /// Open an `owner_key` from [`wrap_send_key`](Self::wrap_send_key).
    pub fn unwrap_send_key(&self, wrapped: &str) -> Result<SendKey> {
        self.account_key
            .unwrap_key(&unb64(wrapped)?, SEND_KEY_AAD)
            .map(SendKey::from_key)
    }

    /// Wrap a v2 Send's content key for its owner (`owner_content_key`, base64url).
    pub fn wrap_send_content_key(&self, key: &SendContentKey) -> Result<String> {
        Ok(b64(&self
            .account_key
            .wrap(key.key(), SEND_CONTENT_KEY_AAD)?))
    }

    /// Open an `owner_content_key` from
    /// [`wrap_send_content_key`](Self::wrap_send_content_key).
    pub fn unwrap_send_content_key(&self, wrapped: &str) -> Result<SendContentKey> {
        self.account_key
            .unwrap_key(&unb64(wrapped)?, SEND_CONTENT_KEY_AAD)
            .map(SendContentKey::from_key)
    }

    /// Emergency access, the grantor's side, when confirming contact `grant_id` (the
    /// access's id): a new random emergency key for that access, and it wrapped with this
    /// account's Account Key (base64url, the access's `grantor_key`), so any of the
    /// account's apps can open it again to wrap more vault keys
    /// ([`open_emergency_key`](Self::open_emergency_key)). Only this key can be sealed to
    /// the contact ([`EmergencyKey::seal_for`]).
    pub fn new_emergency_key(&self, grant_id: &str) -> Result<NewEmergencyKey> {
        let aad = emergency_aad(EMERGENCY_KEY, &[&self.account_id, grant_id])?;
        let key = SymmetricKey::generate()?;
        let wrapped = b64(&self.account_key.wrap(&key, &aad)?);
        Ok(NewEmergencyKey {
            key: EmergencyKey {
                key,
                grantor_id: self.account_id.clone(),
                grant_id: grant_id.to_owned(),
                sealable: true,
            },
            wrapped,
        })
    }

    /// The emergency key of this account's access `grant_id`, from its `grantor_key`.
    /// It wraps and opens vault keys; it can't be sealed to anyone again.
    pub fn open_emergency_key(&self, grant_id: &str, wrapped: &str) -> Result<EmergencyKey> {
        let aad = emergency_aad(EMERGENCY_KEY, &[&self.account_id, grant_id])?;
        Ok(EmergencyKey {
            key: self.account_key.unwrap_key(&unb64(wrapped)?, &aad)?,
            grantor_id: self.account_id.clone(),
            grant_id: grant_id.to_owned(),
            sealable: false,
        })
    }

    /// Emergency access, the contact's side: open the `sealed_key` that account
    /// `grantor_id` sealed to this account for access `grant_id`. What opens only
    /// opens the vault keys that grantor wrapped for that access, and can't be sealed
    /// to anyone again.
    pub fn open_sealed_emergency_key(
        &self,
        grantor_id: &str,
        grant_id: &str,
        sealed: &str,
    ) -> Result<EmergencyKey> {
        let aad = emergency_aad(SEALED_EMERGENCY_KEY, &[grantor_id, grant_id])?;
        let raw = zeroize::Zeroizing::new(self.keypair.open(&unb64(sealed)?, &aad)?);
        Ok(EmergencyKey {
            key: SymmetricKey::from_slice(&raw)?,
            grantor_id: grantor_id.to_owned(),
            grant_id: grant_id.to_owned(),
            sealable: false,
        })
    }

    /// Emergency access: seal this account's roster of emergency contacts (the apps'
    /// own JSON: which accesses may get vault keys, and the version of the list) with
    /// the Account Key (base64url), so the server stores it but can neither read nor
    /// change it, nor pass another account's off as this one's.
    pub fn seal_emergency_roster(&self, json: &str) -> Result<String> {
        let aad = emergency_aad(EMERGENCY_ROSTER, &[&self.account_id])?;
        Ok(b64(&self.account_key.encrypt(json.as_bytes(), &aad)?))
    }

    /// Open a roster sealed by [`seal_emergency_roster`](Self::seal_emergency_roster):
    /// this account's, unchanged, or an error.
    pub fn open_emergency_roster(&self, sealed: &str) -> Result<String> {
        let aad = emergency_aad(EMERGENCY_ROSTER, &[&self.account_id])?;
        let json = self.account_key.decrypt(&unb64(sealed)?, &aad)?;
        String::from_utf8(json).map_err(|_| Error::Malformed("roster is not UTF-8"))
    }

    /// Seal the account's profile picture (the image file's bytes, at most
    /// [`MAX_AVATAR_BYTES`]) with the Account Key (base64url): the server keeps it for
    /// the account's devices but can't see it.
    pub fn seal_avatar(&self, image: &[u8]) -> Result<String> {
        if image.is_empty() || image.len() > MAX_AVATAR_BYTES {
            return Err(Error::Malformed("profile picture size"));
        }
        let aad = format!("{AVATAR_AAD}{}", self.account_id);
        Ok(b64(&self.account_key.encrypt(image, aad.as_bytes())?))
    }

    /// The image bytes from what [`seal_avatar`](Self::seal_avatar) made: this
    /// account's, unchanged, or an error. A picture longer than [`MAX_AVATAR_BYTES`]
    /// (or empty) is refused like one that doesn't open: no app seals one.
    pub fn open_avatar(&self, sealed: &str) -> Result<Vec<u8>> {
        let aad = format!("{AVATAR_AAD}{}", self.account_id);
        let image = self.account_key.decrypt(&unb64(sealed)?, aad.as_bytes())?;
        if image.is_empty() || image.len() > MAX_AVATAR_BYTES {
            return Err(Error::Malformed("profile picture size"));
        }
        Ok(image)
    }
}

/// Emergency access (v2): a random key of one access (one emergency contact), made by
/// the grantor's app when it confirms the contact. It is bound to its grantor and its
/// access, and opens only the vault keys the grantor wrapped with it for that access
/// (their personal vaults): never the Account Key, the private key, shared vaults or
/// Sends, and the raw key can't be read out. The grantor keeps it wrapped by their
/// Account Key (`grantor_key`); the contact gets it sealed to their public key
/// (`sealed_key`), once, when it is made. Wiped from memory on drop.
pub struct EmergencyKey {
    key: SymmetricKey,
    /// The grantor's account id: bound into every vault key this key wraps.
    grantor_id: String,
    /// The access: bound into every vault key this key wraps.
    grant_id: String,
    /// Made by [`UnlockedAccount::new_emergency_key`]: only such a key may be sealed
    /// to a contact, so code that opened an existing one can't hand it to a key pair
    /// of its own.
    sealable: bool,
}

/// [`UnlockedAccount::new_emergency_key`]'s answer.
pub struct NewEmergencyKey {
    pub key: EmergencyKey,
    /// The key wrapped by the grantor's Account Key (base64url): the access's `grantor_key`.
    pub wrapped: String,
}

impl EmergencyKey {
    /// The grantor's account id.
    pub fn grantor_id(&self) -> &str {
        &self.grantor_id
    }

    /// The access this key belongs to.
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    /// Seal this key to the contact's public key (base64url), after checking its
    /// fingerprint with them: the access's `sealed_key`. Only a key from
    /// [`UnlockedAccount::new_emergency_key`] can be sealed; refuses a malformed or
    /// low-order public key, and a grantor or access other than the key's own.
    pub fn seal_for(
        &self,
        contact_public_key: &str,
        grantor_id: &str,
        grant_id: &str,
    ) -> Result<String> {
        if !self.sealable {
            return Err(Error::Malformed(
                "only a new emergency key can be sealed to a contact",
            ));
        }
        if grantor_id != self.grantor_id || grant_id != self.grant_id {
            return Err(Error::Malformed(
                "the emergency key belongs to another account or access",
            ));
        }
        let aad = emergency_aad(SEALED_EMERGENCY_KEY, &[grantor_id, grant_id])?;
        Ok(b64(&seal_to(
            &public_key(contact_public_key)?,
            self.key.as_bytes(),
            &aad,
        )?))
    }

    /// Wrap personal vault `vault_id`'s key for this key's access (base64url).
    pub fn wrap_vault_key(&self, vault_key: &SymmetricKey, vault_id: &str) -> Result<String> {
        Ok(b64(&self
            .key
            .wrap(vault_key, &self.vault_aad(vault_id)?)?))
    }

    /// Open a vault key [`wrap_vault_key`](Self::wrap_vault_key) wrapped for this
    /// vault and this key's access.
    pub fn open_vault_key(&self, vault_id: &str, wrapped: &str) -> Result<SymmetricKey> {
        self.key
            .unwrap_key(&unb64(wrapped)?, &self.vault_aad(vault_id)?)
    }

    fn vault_aad(&self, vault_id: &str) -> Result<Vec<u8>> {
        emergency_aad(
            EMERGENCY_VAULT_KEY,
            &[&self.grantor_id, &self.grant_id, vault_id],
        )
    }
}

/// Seal a vault key to another member's public key (base64url).
pub fn share_vault_key(
    vault_id: &str,
    key: &SymmetricKey,
    recipient_public: &str,
) -> Result<String> {
    let pk = public_key(recipient_public)?;
    Ok(b64(&seal_to(
        &pk,
        key.as_bytes(),
        &aad("shared-vault-key", vault_id),
    )?))
}

/// Encrypt vault metadata (name, icon…) under its vault key.
pub fn encrypt_vault_meta(vault_key: &SymmetricKey, vault_id: &str, json: &[u8]) -> Result<String> {
    Ok(b64(&vault_key.encrypt(json, &aad("vault-meta", vault_id))?))
}

pub fn decrypt_vault_meta(vault_key: &SymmetricKey, vault_id: &str, meta: &str) -> Result<Vec<u8>> {
    vault_key.decrypt(&unb64(meta)?, &aad("vault-meta", vault_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::test_params;

    fn new(sk: bool) -> NewAccount {
        AccountBundle::create_with_kdf("user-1", "correct horse", sk, test_params()).unwrap()
    }

    fn master(b: &AccountBundle, pw: &str, sk: Option<&str>) -> Result<MasterKeys> {
        derive_master_keys(pw, sk, &b.account_id, &b.kdf, b.secret_key_enabled)
    }

    #[test]
    fn create_and_unlock() {
        let acct = new(false);
        assert!(acct.secret_key.is_none());
        assert_ne!(acct.master.auk.as_bytes(), acct.master.login.as_bytes());
        let m = master(&acct.bundle, "correct horse", None).unwrap();
        let u = acct.bundle.unlock(&m.auk).unwrap();
        assert_eq!(
            u.account_key.as_bytes(),
            acct.unlocked.account_key.as_bytes()
        );
        let wrong = master(&acct.bundle, "wrong", None).unwrap();
        assert!(acct.bundle.unlock(&wrong.auk).is_err());
    }

    #[test]
    fn secret_key_required_when_enabled() {
        let acct = new(true);
        let sk = acct.secret_key.clone().unwrap();
        assert!(master(&acct.bundle, "correct horse", None).is_err());
        let m = master(&acct.bundle, "correct horse", Some(&sk)).unwrap();
        assert!(acct.bundle.unlock(&m.auk).is_ok());
    }

    #[test]
    fn bundle_bound_to_account_id() {
        let mut acct = new(false);
        acct.bundle.account_id = "user-2".into();
        let m = master(&acct.bundle, "correct horse", None).unwrap();
        assert!(acct.bundle.unlock(&m.auk).is_err());
    }

    /// Review round 5 (iOS H): a restored session authenticates the stored bundle's
    /// account id; a bundle the server swapped in (another account's, a renamed one, one
    /// with another private key) doesn't match.
    #[test]
    fn a_session_matches_only_its_own_bundle() {
        let acct = new(false);
        let u = &acct.unlocked;
        assert!(u.matches_bundle(&acct.bundle));
        // A password change keeps the private-key blob: still the account's.
        let next = acct.bundle.rewrap(u, "new pw", false, None).unwrap();
        assert!(u.matches_bundle(&next.bundle));
        // Session bytes restored under another id (a server-chosen bundle account id).
        let wrong_id = UnlockedAccount {
            account_id: "user-2".into(),
            account_key: SymmetricKey::from_slice(u.account_key.as_bytes()).unwrap(),
            keypair: KeyPair::from_secret_bytes(u.keypair.secret_bytes()),
        };
        assert!(!wrong_id.matches_bundle(&acct.bundle));
        let mut renamed = acct.bundle.clone();
        renamed.account_id = "user-2".into();
        assert!(!wrong_id.matches_bundle(&renamed));
        assert!(!u.matches_bundle(&renamed));
        // Another account's bundle with the same id, a swapped public key, garbage.
        let other = AccountBundle::create_with_kdf("user-1", "pw", false, test_params()).unwrap();
        assert!(!u.matches_bundle(&other.bundle));
        let mut swapped = acct.bundle.clone();
        swapped.public_key = other.bundle.public_key.clone();
        assert!(!u.matches_bundle(&swapped));
        let mut mixed = acct.bundle.clone();
        mixed.wrapped_private_key = other.bundle.wrapped_private_key.clone();
        assert!(!u.matches_bundle(&mixed));
        mixed.wrapped_private_key = "not base64!".into();
        assert!(!u.matches_bundle(&mixed));
    }

    #[test]
    fn rewrap_keeps_account_key() {
        let acct = new(false);
        let next = acct
            .bundle
            .rewrap(&acct.unlocked, "new pw", true, None)
            .unwrap();
        let sk = next.secret_key.clone().unwrap();
        let m = master(&next.bundle, "new pw", Some(&sk)).unwrap();
        let u = next.bundle.unlock(&m.auk).unwrap();
        assert_eq!(
            u.account_key.as_bytes(),
            acct.unlocked.account_key.as_bytes()
        );
        // Changing only the password keeps the existing Secret Key.
        let again = next.bundle.rewrap(&u, "newer pw", true, Some(&sk)).unwrap();
        assert!(again.secret_key.is_none());
        let m = master(&again.bundle, "newer pw", Some(&sk)).unwrap();
        assert!(again.bundle.unlock(&m.auk).is_ok());
    }

    #[test]
    fn rewrap_refuses_another_accounts_bundle() {
        // Review I5: the result would be a wrap that never unlocks.
        let acct = new(false);
        let mut renamed = acct.bundle.clone();
        renamed.account_id = "user-2".into();
        assert!(matches!(
            renamed.rewrap(&acct.unlocked, "pw", false, None),
            Err(Error::Malformed(_))
        ));
        let other = AccountBundle::create_with_kdf("user-1", "pw", false, test_params()).unwrap();
        assert!(matches!(
            other.bundle.rewrap(&acct.unlocked, "pw", false, None),
            Err(Error::Malformed(_))
        ));
        let mut garbled = acct.bundle.clone();
        garbled.public_key = "not base64!".into();
        assert!(garbled.rewrap(&acct.unlocked, "pw", false, None).is_err());
        assert!(
            acct.bundle
                .rewrap(&acct.unlocked, "pw", false, None)
                .is_ok()
        );
    }

    #[test]
    fn vault_sharing() {
        let alice = new(false).unlocked;
        let bob = new(false).unlocked;
        // Written as v1 (what released apps read): opens under any epoch, when allowed.
        let (vk, wrapped) = alice.new_vault_key("v1").unwrap();
        assert_eq!(unb64(&wrapped).unwrap()[0], 1);
        for epoch in [0, 3] {
            assert_eq!(
                alice
                    .open_vault_key("v1", epoch, &wrapped, true)
                    .unwrap()
                    .as_bytes(),
                vk.as_bytes()
            );
        }
        assert!(matches!(
            alice.open_vault_key("v1", 0, &wrapped, false),
            Err(Error::Decrypt)
        ));
        assert!(alice.open_vault_key("v2", 0, &wrapped, true).is_err());
        // v2 (epoch-bound, marked 0x02): only for its epoch, whatever `legacy_allowed`.
        let bound = alice.wrap_vault_key_bound(&vk, "v1", 7).unwrap();
        assert_eq!(unb64(&bound).unwrap()[0], BOUND_WRAP);
        for legacy in [false, true] {
            assert_eq!(
                alice
                    .open_vault_key("v1", 7, &bound, legacy)
                    .unwrap()
                    .as_bytes(),
                vk.as_bytes()
            );
            assert!(alice.open_vault_key("v1", 6, &bound, legacy).is_err());
            assert!(alice.open_vault_key("v2", 7, &bound, legacy).is_err());
        }
        // What apps write when `/sync` says every app reads v2: a new vault at epoch 0.
        let (nk, nw) = alice.new_vault_key_bound("v3", 0).unwrap();
        assert!(wrap_is_bound(&nw));
        assert!(!wrap_is_bound(&wrapped));
        assert!(!wrap_is_bound("not base64!"));
        assert!(!wrap_is_bound(""));
        assert_eq!(
            alice
                .open_vault_key("v3", 0, &nw, false)
                .unwrap()
                .as_bytes(),
            nk.as_bytes()
        );
        assert!(alice.open_vault_key("v3", 1, &nw, true).is_err());
        assert!(bob.open_vault_key("v3", 0, &nw, true).is_err());
        // A v2 ciphertext without its marker is read as v1 and fails.
        let unmarked = b64(&unb64(&bound).unwrap()[1..]);
        assert!(alice.open_vault_key("v1", 7, &unmarked, true).is_err());
        let sealed = share_vault_key("v1", &vk, &b64(&bob.keypair.public_bytes())).unwrap();
        assert_eq!(
            bob.open_shared_vault_key("v1", &sealed).unwrap().as_bytes(),
            vk.as_bytes()
        );
        assert!(alice.open_shared_vault_key("v1", &sealed).is_err());
    }

    #[test]
    fn rewrap_with_kdf_uses_the_given_parameters() {
        let acct = new(false);
        let mut kdf = test_params();
        kdf.iterations = 2;
        let next = acct
            .bundle
            .rewrap_with_kdf(&acct.unlocked, "new pw", false, None, kdf.clone())
            .unwrap();
        assert_eq!(next.bundle.kdf, kdf);
        let m = master(&next.bundle, "new pw", None).unwrap();
        let u = next.bundle.unlock(&m.auk).unwrap();
        assert_eq!(
            u.account_key.as_bytes(),
            acct.unlocked.account_key.as_bytes()
        );
        // The policy's parameters for a new account and a rewrap (computed only:
        // deriving with 128 MiB+ is too slow for a unit test).
        let p = KdfParams::with_minimums(Some(256), Some(4)).unwrap();
        assert_eq!((p.memory_kib, p.iterations), (256 * 1024, 4));
    }

    #[test]
    fn send_keys_wrap_for_the_owner_only() {
        let alice = new(false).unlocked;
        let bob = new(false).unlocked;
        let key = SendKey::generate().unwrap();
        let wrapped = alice.wrap_send_key(&key).unwrap();
        assert_eq!(
            alice.unwrap_send_key(&wrapped).unwrap().to_b64(),
            key.to_b64()
        );
        assert!(matches!(bob.unwrap_send_key(&wrapped), Err(Error::Decrypt)));
        // A wrapped send key is not a vault key, nor the other way round.
        assert!(alice.open_vault_key("", 0, &wrapped, true).is_err());
        assert!(alice.open_vault_key("send", 0, &wrapped, true).is_err());
        let (_, vault) = alice.new_vault_key("v1").unwrap();
        assert!(matches!(alice.unwrap_send_key(&vault), Err(Error::Decrypt)));
        let mut bad = unb64(&wrapped).unwrap();
        bad[30] ^= 1;
        assert!(alice.unwrap_send_key(&b64(&bad)).is_err());
    }

    #[test]
    fn send_content_keys_wrap_for_the_owner_only() {
        let alice = new(false).unlocked;
        let bob = new(false).unlocked;
        let link = SendKey::generate().unwrap();
        let small = KdfParams {
            memory_kib: 256,
            iterations: 3,
            parallelism: 1,
            salt: b64(&[5; 16]),
        };
        let content = link.content_key(&crate::send::secrets("pw", &small).unwrap());
        let wrapped = alice.wrap_send_content_key(&content).unwrap();
        assert_eq!(
            alice.unwrap_send_content_key(&wrapped).unwrap().to_b64(),
            content.to_b64()
        );
        assert!(bob.unwrap_send_content_key(&wrapped).is_err());
        // Not interchangeable with the link key's wrap (other associated data).
        let owner_key = alice.wrap_send_key(&link).unwrap();
        assert!(alice.unwrap_send_content_key(&owner_key).is_err());
        assert!(alice.unwrap_send_key(&wrapped).is_err());
    }

    /// The grantor confirms contact `grant` (an access's id): (the contact, the
    /// grantor's new emergency key, its `grantor_key`, its `sealed_key`).
    fn confirmed(grantor: &UnlockedAccount, grant: &str) -> (UnlockedAccount, String, String) {
        let contact = new(false).unlocked;
        let NewEmergencyKey { key, wrapped } = grantor.new_emergency_key(grant).unwrap();
        let sealed = key
            .seal_for(
                &b64(&contact.keypair.public_bytes()),
                &grantor.account_id,
                grant,
            )
            .unwrap();
        (contact, wrapped, sealed)
    }

    #[test]
    fn emergency_keys_open_only_the_vault_keys_wrapped_for_their_access() {
        let grantor = new(false).unlocked;
        let (contact, grantor_key, sealed) = confirmed(&grantor, "grant-1");
        let (vk, _) = grantor.new_vault_key("v1").unwrap();
        let (other_vk, _) = grantor.new_vault_key("v2").unwrap();
        // The grantor's apps reopen the key from `grantor_key` and wrap vault keys with it.
        let mine = grantor.open_emergency_key("grant-1", &grantor_key).unwrap();
        assert_eq!((mine.grantor_id(), mine.grant_id()), ("user-1", "grant-1"));
        let wrapped = mine.wrap_vault_key(&vk, "v1").unwrap();
        let wrapped2 = mine.wrap_vault_key(&other_vk, "v2").unwrap();
        // The contact opens the sealed key, then exactly those vault keys.
        let theirs = contact
            .open_sealed_emergency_key("user-1", "grant-1", &sealed)
            .unwrap();
        assert_eq!(
            (theirs.grantor_id(), theirs.grant_id()),
            ("user-1", "grant-1")
        );
        assert_eq!(
            theirs.open_vault_key("v1", &wrapped).unwrap().as_bytes(),
            vk.as_bytes()
        );
        assert_eq!(
            theirs.open_vault_key("v2", &wrapped2).unwrap().as_bytes(),
            other_vk.as_bytes()
        );
        // A wrap for one vault isn't one for another.
        assert!(theirs.open_vault_key("v2", &wrapped).is_err());
        // The same box opened as another grantor's or another access's opens nothing.
        let renamed = contact.open_sealed_emergency_key("user-2", "grant-1", &sealed);
        assert!(matches!(renamed, Err(Error::Decrypt)));
        assert!(
            contact
                .open_sealed_emergency_key("user-1", "grant-2", &sealed)
                .is_err()
        );
        // Wrong contact, a changed box.
        let stranger = new(false).unlocked;
        assert!(
            stranger
                .open_sealed_emergency_key("user-1", "grant-1", &sealed)
                .is_err()
        );
        let mut bad = unb64(&sealed).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(
            contact
                .open_sealed_emergency_key("user-1", "grant-1", &b64(&bad))
                .is_err()
        );
        // `grantor_key` opens only for its own account and access.
        assert!(grantor.open_emergency_key("grant-2", &grantor_key).is_err());
        let other_account = AccountBundle::create_with_kdf("user-1", "pw", false, test_params())
            .unwrap()
            .unlocked;
        assert!(
            other_account
                .open_emergency_key("grant-1", &grantor_key)
                .is_err()
        );
        let mut renamed = new(false).unlocked;
        renamed.account_id = "user-2".into();
        renamed.account_key = grantor.account_key.clone();
        assert!(renamed.open_emergency_key("grant-1", &grantor_key).is_err());
    }

    #[test]
    fn emergency_keys_of_two_accesses_stay_apart() {
        let grantor = new(false).unlocked;
        let (contact_a, key_a, sealed_a) = confirmed(&grantor, "grant-a");
        let (contact_b, _, sealed_b) = confirmed(&grantor, "grant-b");
        let (vk, _) = grantor.new_vault_key("v1").unwrap();
        let a = grantor.open_emergency_key("grant-a", &key_a).unwrap();
        let for_a = a.wrap_vault_key(&vk, "v1").unwrap();
        // Contact B's key can't open what was wrapped for A.
        let b = contact_b
            .open_sealed_emergency_key("user-1", "grant-b", &sealed_b)
            .unwrap();
        assert!(matches!(
            b.open_vault_key("v1", &for_a),
            Err(Error::Decrypt)
        ));
        // Nor can A's contact open B's box, or A's box as B's access.
        assert!(
            contact_a
                .open_sealed_emergency_key("user-1", "grant-b", &sealed_b)
                .is_err()
        );
        assert!(
            contact_a
                .open_sealed_emergency_key("user-1", "grant-b", &sealed_a)
                .is_err()
        );
    }

    #[test]
    fn only_a_new_emergency_key_is_sealed_to_a_contact() {
        let grantor = new(false).unlocked;
        let (contact, grantor_key, sealed) = confirmed(&grantor, "grant-1");
        let other = b64(&new(false).unlocked.keypair.public_bytes());
        // Neither a key opened again by the grantor's apps nor one opened by the contact
        // can be handed to another key pair.
        let mine = grantor.open_emergency_key("grant-1", &grantor_key).unwrap();
        assert!(matches!(
            mine.seal_for(&other, "user-1", "grant-1"),
            Err(Error::Malformed(_))
        ));
        let theirs = contact
            .open_sealed_emergency_key("user-1", "grant-1", &sealed)
            .unwrap();
        assert!(matches!(
            theirs.seal_for(&other, "user-1", "grant-1"),
            Err(Error::Malformed(_))
        ));
        // A new key is sealed for its own grantor and access only.
        let NewEmergencyKey { key, .. } = grantor.new_emergency_key("grant-2").unwrap();
        assert!(key.seal_for(&other, "user-1", "grant-2").is_ok());
        for (grantor_id, grant_id) in [("user-2", "grant-2"), ("user-1", "grant-1")] {
            assert!(matches!(
                key.seal_for(&other, grantor_id, grant_id),
                Err(Error::Malformed(_))
            ));
        }
    }

    #[test]
    fn emergency_boxes_are_not_other_keys() {
        let grantor = new(false).unlocked;
        let (contact, grantor_key, sealed) = confirmed(&grantor, "grant-1");
        let (vk, account_wrapped) = grantor.new_vault_key("v1").unwrap();
        let key = grantor.open_emergency_key("grant-1", &grantor_key).unwrap();
        let wrapped = key.wrap_vault_key(&vk, "v1").unwrap();
        // A sealed emergency key is no shared vault key, and the other way round.
        assert!(contact.open_shared_vault_key("grant-1", &sealed).is_err());
        let shared =
            share_vault_key("grant-1", &vk, &b64(&contact.keypair.public_bytes())).unwrap();
        assert!(
            contact
                .open_sealed_emergency_key("user-1", "grant-1", &shared)
                .is_err()
        );
        // The Account Key's own wraps (vault keys, `grantor_key`) aren't emergency wraps.
        let theirs = contact
            .open_sealed_emergency_key("user-1", "grant-1", &sealed)
            .unwrap();
        assert!(theirs.open_vault_key("v1", &account_wrapped).is_err());
        assert!(theirs.open_vault_key("v1", &grantor_key).is_err());
        assert!(grantor.open_vault_key("v1", 0, &wrapped, true).is_err());
        assert!(
            grantor
                .open_vault_key("grant-1", 0, &grantor_key, true)
                .is_err()
        );
        assert!(grantor.open_emergency_key("grant-1", &wrapped).is_err());
        assert!(grantor.unwrap_send_key(&grantor_key).is_err());
    }

    #[test]
    fn emergency_keys_refuse_bad_public_keys_and_ids() {
        let grantor = new(false).unlocked;
        let NewEmergencyKey { key, .. } = grantor.new_emergency_key("grant-1").unwrap();
        // Malformed, wrong length, and low-order public keys.
        for bad in [
            "short".to_owned(),
            b64(&[0; 32]),
            b64(&[1; 31]),
            b64(&[1; 33]),
        ] {
            assert!(key.seal_for(&bad, "user-1", "grant-1").is_err(), "{bad}");
        }
        let order8 =
            hex::decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
                .unwrap();
        assert!(key.seal_for(&b64(&order8), "user-1", "grant-1").is_err());
        // Ids that could run into each other are refused everywhere.
        let (vk, _) = grantor.new_vault_key("v1").unwrap();
        for id in ["", "a/b"] {
            assert!(grantor.new_emergency_key(id).is_err());
            assert!(grantor.open_emergency_key(id, "AQ").is_err());
            assert!(key.wrap_vault_key(&vk, id).is_err());
            assert!(key.open_vault_key(id, "AQ").is_err());
            assert!(
                grantor
                    .open_sealed_emergency_key(id, "grant-1", "AQ")
                    .is_err()
            );
            assert!(
                grantor
                    .open_sealed_emergency_key("user-1", id, "AQ")
                    .is_err()
            );
        }
        assert!(key.open_vault_key("v1", "not base64!").is_err());
    }

    #[test]
    fn avatars_open_only_for_their_account() {
        let alice = new(false).unlocked;
        let image = b"\xFF\xD8\xFFjpeg bytes";
        let sealed = alice.seal_avatar(image).unwrap();
        assert_eq!(alice.open_avatar(&sealed).unwrap(), image);
        let bob = new(false).unlocked;
        assert!(matches!(bob.open_avatar(&sealed), Err(Error::Decrypt)));
        assert!(alice.seal_avatar(b"").is_err());
        assert!(alice.seal_avatar(&vec![0; MAX_AVATAR_BYTES + 1]).is_err());
        // The largest picture opens; a longer one sealed by other means doesn't.
        let largest = vec![7; MAX_AVATAR_BYTES];
        let sealed = alice.seal_avatar(&largest).unwrap();
        assert_eq!(alice.open_avatar(&sealed).unwrap(), largest);
        let aad = format!("{AVATAR_AAD}{}", alice.account_id);
        let seal = |image: &[u8]| b64(&alice.account_key.encrypt(image, aad.as_bytes()).unwrap());
        assert_eq!(alice.open_avatar(&seal(b"ok")).unwrap(), b"ok");
        for image in [vec![0; MAX_AVATAR_BYTES + 1], Vec::new()] {
            assert!(matches!(
                alice.open_avatar(&seal(&image)),
                Err(Error::Malformed("profile picture size"))
            ));
        }
        // Not interchangeable with the roster (same key, other AAD).
        let roster = alice.seal_emergency_roster("{}").unwrap();
        assert!(alice.open_avatar(&roster).is_err());
    }

    #[test]
    fn rosters_open_only_for_their_account_unchanged() {
        let alice = new(false).unlocked;
        let json =
            r#"{"version":3,"accesses":[{"id":"g1","contact_key":"pk","grantor_key_hash":"h"}]}"#;
        let sealed = alice.seal_emergency_roster(json).unwrap();
        assert_eq!(alice.open_emergency_roster(&sealed).unwrap(), json);
        assert_ne!(alice.seal_emergency_roster(json).unwrap(), sealed);
        // Another account (also one with the same id, or the same key under another id).
        let bob = new(false).unlocked;
        assert!(matches!(
            bob.open_emergency_roster(&sealed),
            Err(Error::Decrypt)
        ));
        let mut renamed = new(false).unlocked;
        renamed.account_id = "user-2".into();
        renamed.account_key = alice.account_key.clone();
        assert!(renamed.open_emergency_roster(&sealed).is_err());
        // Changed on the way.
        let mut bad = unb64(&sealed).unwrap();
        bad[30] ^= 1;
        assert!(alice.open_emergency_roster(&b64(&bad)).is_err());
        assert!(alice.open_emergency_roster("not base64!").is_err());
        // Nothing else the Account Key encrypts passes for a roster, nor the other way round.
        let (_, vault) = alice.new_vault_key("v1").unwrap();
        let send = alice.wrap_send_key(&SendKey::generate().unwrap()).unwrap();
        let NewEmergencyKey { wrapped, .. } = alice.new_emergency_key("g1").unwrap();
        for other in [&vault, &send, &wrapped] {
            assert!(alice.open_emergency_roster(other).is_err());
        }
        let key_sized = alice.seal_emergency_roster(&"k".repeat(32)).unwrap();
        assert!(alice.open_vault_key("v1", 0, &key_sized, true).is_err());
        assert!(alice.unwrap_send_key(&key_sized).is_err());
        assert!(alice.open_emergency_key("g1", &key_sized).is_err());
    }

    /// Known answers, computed independently (Node.js: X25519, HKDF-SHA256,
    /// HChaCha20 + OpenSSL ChaCha20-Poly1305) from the documented formats.
    /// Contact's X25519 secret 0x51 × 32, ephemeral secret 0x22 × 32, nonce 0x33 × 24:
    /// the emergency key 0x44 × 32 of access "grant-1" sealed by grantor "grantor-1".
    /// That grantor's Account Key 0x88 × 32 wrapping it (nonce 0x55 × 24); it
    /// wrapping vault "v1"'s key 0x77 × 32 (nonce 0x66 × 24); that Account Key
    /// sealing the roster `{"version":1,"accesses":[]}` (nonce 0x77 × 24). And an
    /// Account Key 0x44 × 32 wrapping the send key 0x55 × 32 (nonce 0x66 × 24).
    const KAT_SEALED_EMERGENCY_KEY: &str = "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyABMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzG_lIxoR6wrblvXpHaJBJ-ZOE0Ut74OHPvVvQJktbjLz6dNvakU-kSsrSIuymX7ax";
    const KAT_GRANTOR_KEY: &str = "AVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVTpzySSLYm4_7qND8yQV4dI0j5KhSngWLAh2igD886iz_pfZm9aExcBW9sVrBflikg";
    const KAT_EMERGENCY_VAULT_KEY: &str = "AWZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZtnqzdNMf5ljSMxWGXPHdJhCb3TsuIRGDDQunap9k-5oNf6FY6v3z6LXar1l6_QAVw";
    const KAT_ROSTER: &str = "AXd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d09jkwI3z1moKSpvWb_Rh-TpIXoNYVzpcvI18T8yAR-zPCt5rFZU7BGFeJQ";
    const KAT_WRAPPED_SEND_KEY: &str = "AWZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZvvI7_FuXbtBau50O1HlVrpgTVbOmqZkLhYMv4hfscxKbFUx2Fkhgidr7JyZEU5K2A";

    #[test]
    fn known_answers() {
        let contact = UnlockedAccount {
            account_id: "contact-1".into(),
            account_key: SymmetricKey::from_bytes([9; 32]),
            keypair: KeyPair::from_secret_bytes([0x51; 32]),
        };
        let theirs = contact
            .open_sealed_emergency_key("grantor-1", "grant-1", KAT_SEALED_EMERGENCY_KEY)
            .unwrap();
        assert_eq!(
            theirs
                .open_vault_key("v1", KAT_EMERGENCY_VAULT_KEY)
                .unwrap()
                .as_bytes(),
            &[0x77; 32]
        );
        let grantor = UnlockedAccount {
            account_id: "grantor-1".into(),
            account_key: SymmetricKey::from_bytes([0x88; 32]),
            keypair: KeyPair::from_secret_bytes([0x61; 32]),
        };
        let mine = grantor
            .open_emergency_key("grant-1", KAT_GRANTOR_KEY)
            .unwrap();
        assert_eq!(mine.key.as_bytes(), &[0x44; 32]);
        assert_eq!(theirs.key.as_bytes(), &[0x44; 32]);
        assert_eq!(
            grantor.open_emergency_roster(KAT_ROSTER).unwrap(),
            r#"{"version":1,"accesses":[]}"#
        );

        let sender = UnlockedAccount {
            account_id: "grantor-1".into(),
            account_key: SymmetricKey::from_bytes([0x44; 32]),
            keypair: KeyPair::from_secret_bytes([0x61; 32]),
        };
        assert_eq!(
            sender
                .unwrap_send_key(KAT_WRAPPED_SEND_KEY)
                .unwrap()
                .to_b64(),
            b64(&[0x55; 32])
        );
    }
}
