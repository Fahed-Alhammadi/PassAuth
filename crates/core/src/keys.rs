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
use crate::{Error, Result};

fn aad(kind: &str, id: &str) -> Vec<u8> {
    format!("passauth/{kind}/v1/{id}").into_bytes()
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
        let id = &self.account_id;
        let account_key =
            auk.unwrap_key(&unb64(&self.wrapped_account_key)?, &aad("account-key", id))?;
        let secret =
            account_key.decrypt(&unb64(&self.wrapped_private_key)?, &aad("private-key", id))?;
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| Error::Malformed("private key"))?;
        let keypair = KeyPair::from_secret_bytes(secret);
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
        let kdf = KdfParams::new_default()?;
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
        let raw = self
            .keypair
            .open(&unb64(sealed)?, &aad("shared-vault-key", vault_id))?;
        SymmetricKey::from_slice(&raw)
    }
}

/// Seal a vault key to another member's public key (base64url).
pub fn share_vault_key(
    vault_id: &str,
    key: &SymmetricKey,
    recipient_public: &str,
) -> Result<String> {
    let pk: [u8; 32] = unb64(recipient_public)?
        .try_into()
        .map_err(|_| Error::Malformed("public key length"))?;
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
}
