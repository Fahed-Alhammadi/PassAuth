//! Account key hierarchy.
//!
//! ```text
//! password (+ Secret Key) ─Argon2id─► MasterKeys { auk, login }
//! AUK ─wraps─► Account Key ─wraps─► X25519 private key
//!                         └─wraps─► personal Vault Keys ─wraps─► Item Keys
//! ```
//! Everything in [`AccountBundle`] is safe to store on the server.

use serde::{Deserialize, Serialize};

use crate::crypto::{KeyPair, SymmetricKey, seal_to};
use crate::item::{b64, unb64};
use crate::kdf::{KdfParams, MasterKeys, SecretKey};
use crate::send::SendKey;
use crate::{Error, Result};

fn aad(kind: &str, id: &str) -> Vec<u8> {
    format!("passauth/{kind}/v1/{id}").into_bytes()
}

/// Associated data of a send key wrapped by the Account Key. Sends get their id
/// from the server after the app encrypted, so there is no id to bind.
const SEND_KEY_AAD: &[u8] = b"passauth/send-key/v1";
/// Kind of an Account Key sealed to an emergency contact (bound to the grantor's id).
const EMERGENCY_KEY: &str = "emergency-account-key";

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

impl UnlockedAccount {
    pub fn new_vault_key(&self, vault_id: &str) -> Result<(SymmetricKey, String)> {
        let key = SymmetricKey::generate()?;
        let wrapped = b64(&self.account_key.wrap(&key, &aad("vault-key", vault_id))?);
        Ok((key, wrapped))
    }

    pub fn open_vault_key(&self, vault_id: &str, wrapped: &str) -> Result<SymmetricKey> {
        self.account_key
            .unwrap_key(&unb64(wrapped)?, &aad("vault-key", vault_id))
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

    /// Emergency access: seal this account's Account Key to a trusted contact's
    /// public key (base64url), after checking its fingerprint with them. The
    /// sealed box (base64url) names this account, so it can't pass for another
    /// grantor's key, nor for a shared vault key.
    pub fn seal_account_key_for(&self, recipient_public: &str) -> Result<String> {
        Ok(b64(&seal_to(
            &public_key(recipient_public)?,
            self.account_key.as_bytes(),
            &aad(EMERGENCY_KEY, &self.account_id),
        )?))
    }

    /// Emergency access, the contact's side: open the Account Key that account
    /// `grantor_account_id` sealed to this account. It can only open that
    /// account's own vault keys.
    pub fn open_sealed_account_key(
        &self,
        grantor_account_id: &str,
        sealed: &str,
    ) -> Result<GrantorKey> {
        let raw = zeroize::Zeroizing::new(
            self.keypair
                .open(&unb64(sealed)?, &aad(EMERGENCY_KEY, grantor_account_id))?,
        );
        Ok(GrantorKey {
            account_id: grantor_account_id.to_owned(),
            account_key: SymmetricKey::from_slice(&raw)?,
        })
    }
}

/// Another account's Account Key, opened by its emergency contact. It opens that
/// account's own vault keys (`key_kind = account`) for viewing, and nothing else:
/// no private key, no Sends, no new keys, and the raw key can't be read out.
pub struct GrantorKey {
    account_id: String,
    account_key: SymmetricKey,
}

impl GrantorKey {
    /// The grantor's account id.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// A vault key the grantor wrapped with their Account Key.
    pub fn open_vault_key(&self, vault_id: &str, wrapped: &str) -> Result<SymmetricKey> {
        self.account_key
            .unwrap_key(&unb64(wrapped)?, &aad("vault-key", vault_id))
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
        let (vk, wrapped) = alice.new_vault_key("v1").unwrap();
        assert_eq!(
            alice.open_vault_key("v1", &wrapped).unwrap().as_bytes(),
            vk.as_bytes()
        );
        assert!(alice.open_vault_key("v2", &wrapped).is_err());
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
        assert!(alice.open_vault_key("", &wrapped).is_err());
        assert!(alice.open_vault_key("send", &wrapped).is_err());
        let (_, vault) = alice.new_vault_key("v1").unwrap();
        assert!(matches!(alice.unwrap_send_key(&vault), Err(Error::Decrypt)));
        let mut bad = unb64(&wrapped).unwrap();
        bad[30] ^= 1;
        assert!(alice.unwrap_send_key(&b64(&bad)).is_err());
    }

    #[test]
    fn emergency_access_opens_only_the_grantors_vault_keys() {
        let grantor = new(false).unlocked;
        let contact = new(false).unlocked;
        let stranger = new(false).unlocked;
        let (vk, wrapped) = grantor.new_vault_key("v1").unwrap();
        let sealed = grantor
            .seal_account_key_for(&b64(&contact.keypair.public_bytes()))
            .unwrap();
        let key = contact.open_sealed_account_key("user-1", &sealed).unwrap();
        assert_eq!(key.account_id(), "user-1");
        assert_eq!(
            key.open_vault_key("v1", &wrapped).unwrap().as_bytes(),
            vk.as_bytes()
        );
        assert!(key.open_vault_key("v2", &wrapped).is_err());
        // Only the contact opens it, and only as this grantor's key.
        assert!(stranger.open_sealed_account_key("user-1", &sealed).is_err());
        assert!(contact.open_sealed_account_key("user-2", &sealed).is_err());
        // Not interchangeable with a vault key sealed for sharing.
        assert!(contact.open_shared_vault_key("user-1", &sealed).is_err());
        let shared = share_vault_key("user-1", &vk, &b64(&contact.keypair.public_bytes())).unwrap();
        assert!(contact.open_sealed_account_key("user-1", &shared).is_err());
        // Bad public keys.
        assert!(grantor.seal_account_key_for("short").is_err());
        assert!(grantor.seal_account_key_for(&b64(&[0; 32])).is_err());
        assert!(grantor.seal_account_key_for(&b64(&[1; 31])).is_err());
    }

    /// Known answers, computed independently (Node.js: X25519, HKDF-SHA256,
    /// HChaCha20 + OpenSSL ChaCha20-Poly1305) from the documented formats.
    /// Contact's X25519 secret 0x51 × 32, ephemeral secret 0x22 × 32, nonce 0x33 ×
    /// 24, sealed Account Key 0x44 × 32 for grantor "grantor-1"; and that Account
    /// Key wrapping the send key 0x55 × 32 (nonce 0x66 × 24).
    const KAT_SEALED_ACCOUNT_KEY: &str = "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyABMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzG_lIxoR6wrblvXpHaJBJ-ZOE0Ut74OHPvVvQJktbjLyaUjkaL1uEagznYxGXQmFc";
    const KAT_WRAPPED_SEND_KEY: &str = "AWZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZvvI7_FuXbtBau50O1HlVrpgTVbOmqZkLhYMv4hfscxKbFUx2Fkhgidr7JyZEU5K2A";

    #[test]
    fn known_answers() {
        let contact = UnlockedAccount {
            account_id: "contact-1".into(),
            account_key: SymmetricKey::from_bytes([9; 32]),
            keypair: KeyPair::from_secret_bytes([0x51; 32]),
        };
        let key = contact
            .open_sealed_account_key("grantor-1", KAT_SEALED_ACCOUNT_KEY)
            .unwrap();
        // Prove it holds 0x44 × 32: it opens a vault key wrapped with that key.
        let account_key = SymmetricKey::from_bytes([0x44; 32]);
        let vk = SymmetricKey::from_bytes([0x77; 32]);
        let wrapped = b64(&account_key.wrap(&vk, b"passauth/vault-key/v1/v1").unwrap());
        assert_eq!(
            key.open_vault_key("v1", &wrapped).unwrap().as_bytes(),
            &[0x77; 32]
        );

        let grantor = UnlockedAccount {
            account_id: "grantor-1".into(),
            account_key,
            keypair: KeyPair::from_secret_bytes([0x61; 32]),
        };
        assert_eq!(
            grantor
                .unwrap_send_key(KAT_WRAPPED_SEND_KEY)
                .unwrap()
                .to_b64(),
            b64(&[0x55; 32])
        );
    }
}
