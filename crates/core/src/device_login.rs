//! Approve a sign-in from another device: the apps' side of the server's
//! `login_with_device` feature (crates/server/src/auth_requests.rs).
//!
//! 1. The new device makes a [`LoginRequestKey`] for one request, sends its public key
//!    with the request and shows [`LoginRequestKey::phrase`].
//! 2. An unlocked app of the account lists the request and offers
//!    [`login_phrase_choices`] of the request's public key, worked out by itself (never the
//!    server's copy): that key's words among decoys derived from the key (the same on every
//!    device and every time, so seeing a request twice reveals nothing), and "none of
//!    these". The user picks
//!    the words the new device shows. [`UnlockedAccount::approve_login_request`] then seals
//!    the Account Key (and, if the user chooses, the Secret Key) to that key, and only to
//!    that key: it refuses unless the picked words are the key's own. It returns the sealed
//!    key for the server and a 6-digit code, which the app shows. The app also proves it
//!    holds the account's keys by opening the request's challenge
//!    ([`UnlockedAccount::open_login_challenge`]).
//! 3. The new device opens what it is handed ([`LoginRequestKey::open`]) and asks for the
//!    code shown on the approving app. [`ApprovedLogin::confirm`] checks it against the key
//!    it opened; until then [`ApprovedLogin::unlock`] and [`ApprovedLogin::secret_key`] fail
//!    with [`Error::NotConfirmed`]. Three wrong codes refuse the approval for good
//!    ([`Error::TooManyWrongCodes`]; the keys it holds are wiped).
//!
//! Why both checks: the sealed key is an anonymous sealed box, so the new device can't tell
//! who sealed it. The words stop a server that swaps the request's public key (the approving
//! app would seal to the server's key, whose words the user doesn't find on the new device).
//! The code stops a server that never asks a real app at all and seals an Account Key of its
//! own (with a bundle to match): that key gives another code than the one the user reads on
//! their own app, which only the account's real key gives, and which never passes through the
//! server. Picking the words among decoys, rather than confirming a pair shown side by side,
//! keeps a hurried "yes" from approving a stranger's request.
//!
//! Formats (base64url without padding everywhere):
//! - Phrase: d = SHA-256([`PHRASE_LABEL`] ‖ the 32 raw public-key bytes); word `i` (0..5)
//!   is line `u32_be(d[4i..4i+4]) mod 7776` (0-based) of the EFF large wordlist; words
//!   joined by single spaces.
//! - Choices: `count` (2–5) phrases, fixed per key and count. Decoy candidate `i` (0, 1, 2…)
//!   is the phrase of d_i = SHA-256([`DECOY_LABEL`] ‖ the 32 raw public-key bytes ‖
//!   u32_be(i)), its words taken like the phrase's; a candidate is skipped when it has the
//!   real phrase's word at any position or equals an earlier decoy, until `count` − 1 are
//!   taken. The real phrase goes in at position u64_be(e[0..8]) mod `count`, e =
//!   SHA-256([`POSITION_LABEL`] ‖ the key), the decoys around it in order. The decoys are no
//!   secret: picking one is always refused.
//! - Sealed key: a sealed box ([`crate::crypto::seal_to`]: ephemeral X25519, HKDF-SHA256,
//!   XChaCha20-Poly1305) to the request's public key. Associated data: [`KEY_LABEL`], then
//!   the account id and the request id, each preceded by its length in bytes (u64,
//!   big-endian). Plaintext: the Account Key (32 bytes), then the Secret Key's 16 raw
//!   bytes when it is included (48 bytes in all).
//! - Code: k = HKDF-SHA256(the Account Key, no salt, info [`CONFIRM_INFO`], 32 bytes);
//!   t = HMAC-SHA256(k, u64_be(len account id) ‖ account id ‖ u64_be(len request id) ‖
//!   request id ‖ the request's 32 raw public-key bytes); code = u64_be(t[0..8]) mod 10⁶ as
//!   6 decimal digits with leading zeros (bias below 10⁻¹³). The new device accepts the
//!   digits with spaces or hyphens between them, compares in constant time, and allows
//!   [`CODE_ATTEMPTS`] wrong codes per approval.
//! - Challenge: a sealed box to the account's public key with associated data
//!   [`CHALLENGE_AAD`] ‖ the request id; the proof is its plaintext.

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::{KeyPair, SymmetricKey, hkdf_key, seal_to};
use crate::generator::WORDLIST;
use crate::item::{b64, unb64};
use crate::kdf::SecretKey;
use crate::keys::{AccountBundle, UnlockedAccount};
use crate::{Error, Result};

/// Hashed in front of the public key for [`login_phrase`].
pub const PHRASE_LABEL: &[u8] = b"passauth/login-with-device/phrase/v1";
/// Words in a phrase (about 64.6 bits).
pub const PHRASE_WORDS: usize = 5;
/// Start of the associated data of a sealed login key.
pub const KEY_LABEL: &[u8] = b"passauth/login-with-device/key/v1";
/// Associated data of a request's challenge, followed by the request's id (as the server
/// seals it).
pub const CHALLENGE_AAD: &[u8] = b"passauth/login-with-device/challenge/v1:";
/// HKDF info of the key behind the confirmation code (derived from the Account Key).
pub const CONFIRM_INFO: &[u8] = b"passauth/login-with-device/confirm/v1";
/// Digits in a confirmation code.
pub const CODE_DIGITS: usize = 6;
/// Wrong codes an approval takes: the last one refuses it for good.
pub const CODE_ATTEMPTS: u32 = 3;
/// Hashed in front of the public key and a counter for [`login_phrase_choices`]' decoys.
pub const DECOY_LABEL: &[u8] = b"passauth/login-with-device/decoy/v1";
/// Hashed in front of the public key for where [`login_phrase_choices`] puts the real phrase.
pub const POSITION_LABEL: &[u8] = b"passauth/login-with-device/decoy-position/v1";
/// Fewest phrases [`login_phrase_choices`] offers (the real one and a decoy).
pub const MIN_CHOICES: usize = 2;
/// Most phrases [`login_phrase_choices`] offers.
pub const MAX_CHOICES: usize = 5;

const WORDLIST_LEN: u32 = 7776;
const ACCOUNT_KEY_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 16;

/// The words for a request's public key (base64url, 32 bytes): what both screens show.
pub fn login_phrase(public_key: &str) -> Result<String> {
    Ok(login_phrase_for(&public_key_bytes(public_key)?))
}

/// [`login_phrase`] for the raw key.
pub fn login_phrase_for(public_key: &[u8; 32]) -> String {
    phrase_words(public_key).join(" ")
}

/// `count` phrases (2–5) for the approving app to offer: exactly one is [`login_phrase`] of
/// `public_key`, the others are decoys (all different, none sharing a word with the real
/// phrase at the same position). They are derived from the key, so the same key and count
/// give the same phrases in the same order on every device and every time: a request seen
/// twice (after "Not now", or on two devices) doesn't give the real words away as the only
/// phrase in both lists. The user picks the one the new device shows; pass it to
/// [`UnlockedAccount::approve_login_request`].
pub fn login_phrase_choices(public_key: &str, count: usize) -> Result<Vec<String>> {
    if !(MIN_CHOICES..=MAX_CHOICES).contains(&count) {
        return Err(Error::Malformed("phrase choices: 2 to 5"));
    }
    let key = public_key_bytes(public_key)?;
    let real = phrase_words(&key);
    let mut choices: Vec<[&str; PHRASE_WORDS]> = Vec::with_capacity(count);
    // A candidate is skipped about once in 1500 (a word in common), so this ends at once.
    for i in 0u32.. {
        if choices.len() == count - 1 {
            break;
        }
        let digest = Sha256::new()
            .chain_update(DECOY_LABEL)
            .chain_update(key)
            .chain_update(i.to_be_bytes())
            .finalize();
        let decoy = words_of(&digest);
        if decoy.iter().zip(&real).any(|(a, b)| a == b) || choices.contains(&decoy) {
            continue;
        }
        choices.push(decoy);
    }
    let digest = Sha256::new()
        .chain_update(POSITION_LABEL)
        .chain_update(key)
        .finalize();
    let at = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % count as u64;
    choices.insert(at as usize, real);
    Ok(choices.iter().map(|words| words.join(" ")).collect())
}

fn phrase_words(public_key: &[u8; 32]) -> [&'static str; PHRASE_WORDS] {
    let digest = Sha256::new()
        .chain_update(PHRASE_LABEL)
        .chain_update(public_key)
        .finalize();
    words_of(&digest)
}

/// Word `i` of a phrase: line `u32_be(digest[4i..4i+4]) mod 7776` of the EFF large wordlist.
fn words_of(digest: &[u8]) -> [&'static str; PHRASE_WORDS] {
    let (chunks, _) = digest.as_chunks::<4>();
    std::array::from_fn(|i| {
        let n = u32::from_be_bytes(chunks[i]) % WORDLIST_LEN;
        WORDLIST
            .lines()
            .nth(n as usize)
            .expect("the EFF list has 7776 words")
    })
}

fn public_key_bytes(b64_key: &str) -> Result<[u8; 32]> {
    unb64(b64_key)?
        .try_into()
        .map_err(|_| Error::Malformed("public key length"))
}

/// Associated data of a sealed login key for this account and request.
fn key_aad(account_id: &str, request_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_LABEL.len() + 16 + account_id.len() + request_id.len());
    aad.extend_from_slice(KEY_LABEL);
    for part in [account_id, request_id] {
        aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}

/// The confirmation code (ASCII digits) for this Account Key, account, request and request
/// key (see the module's formats).
fn confirmation_code(
    account_key: &SymmetricKey,
    account_id: &str,
    request_id: &str,
    public_key: &[u8; 32],
) -> [u8; CODE_DIGITS] {
    let key = hkdf_key(account_key.as_bytes(), &[], CONFIRM_INFO);
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key length");
    for part in [account_id, request_id] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    mac.update(public_key);
    let tag = mac.finalize().into_bytes();
    let mut n = u64::from_be_bytes(tag[..8].try_into().expect("8 bytes")) % 1_000_000;
    let mut code = [b'0'; CODE_DIGITS];
    for digit in code.iter_mut().rev() {
        *digit = b'0' + (n % 10) as u8;
        n /= 10;
    }
    code
}

/// A typed code: 6 ASCII digits, with any spaces or hyphens around and between them.
fn parse_code(code: &str) -> Result<[u8; CODE_DIGITS]> {
    const BAD: Error = Error::Malformed("the code is 6 digits");
    let mut out = [0u8; CODE_DIGITS];
    let mut n = 0;
    for b in code.bytes() {
        match b {
            b'0'..=b'9' => {
                *out.get_mut(n).ok_or(BAD)? = b;
                n += 1;
            }
            b' ' | b'-' => {}
            _ => return Err(BAD),
        }
    }
    if n == CODE_DIGITS { Ok(out) } else { Err(BAD) }
}

/// The new device's key pair, made for one sign-in request. The private half never leaves
/// it.
pub struct LoginRequestKey {
    keypair: KeyPair,
}

impl LoginRequestKey {
    pub fn generate() -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate()?,
        })
    }

    /// The public key to send with the request (base64url, 32 bytes).
    pub fn public_key(&self) -> String {
        b64(&self.keypair.public_bytes())
    }

    /// The words this device shows: [`login_phrase`] of its own public key.
    pub fn phrase(&self) -> String {
        login_phrase_for(&self.keypair.public_bytes())
    }

    /// Open the sealed key an app of account `account_id` made for request `request_id`.
    /// Fails for anything sealed to another key, for another account or request, or changed
    /// on the way. What opens is not trusted yet: see [`ApprovedLogin::confirm`].
    pub fn open(&self, sealed: &str, account_id: &str, request_id: &str) -> Result<ApprovedLogin> {
        let plain = Zeroizing::new(
            self.keypair
                .open(&unb64(sealed)?, &key_aad(account_id, request_id))?,
        );
        let (key, rest) = plain
            .split_at_checked(ACCOUNT_KEY_LEN)
            .ok_or(Error::Malformed("sealed login key"))?;
        let secret_key = match rest.len() {
            0 => None,
            SECRET_KEY_LEN => Some(SecretKey::from_bytes(
                rest.try_into().expect("checked length"),
            )),
            _ => return Err(Error::Malformed("sealed login key")),
        };
        Ok(ApprovedLogin {
            account_id: account_id.to_owned(),
            request_id: request_id.to_owned(),
            public_key: self.keypair.public_bytes(),
            keys: Some(ApprovedKeys {
                account_key: SymmetricKey::from_slice(key)?,
                secret_key,
            }),
            wrong_codes: 0,
            confirmed: false,
        })
    }
}

/// What an approving app sealed to a [`LoginRequestKey`]: the Account Key (it can't be read
/// out) and, if the user included it, the Secret Key. Usable only after
/// [`confirm`](Self::confirm) accepted the code the approving app shows: until then anybody
/// (the server too) could have sealed it.
pub struct ApprovedLogin {
    account_id: String,
    request_id: String,
    /// The request key's public half: part of the code.
    public_key: [u8; 32],
    /// `None` once refused (wiped on drop).
    keys: Option<ApprovedKeys>,
    wrong_codes: u32,
    confirmed: bool,
}

struct ApprovedKeys {
    account_key: SymmetricKey,
    secret_key: Option<SecretKey>,
}

impl ApprovedLogin {
    /// The account the key was sealed for.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Check the code the approving app shows (6 digits; spaces and hyphens are ignored):
    /// only the account's real Account Key gives it. [`Error::WrongCode`] for another code
    /// (also after a successful confirmation, which it doesn't undo), [`Error::TooManyWrongCodes`]
    /// on the third wrong code and for good after it, [`Error::Malformed`] for anything
    /// but 6 digits (not counted as a wrong code).
    pub fn confirm(&mut self, code: &str) -> Result<()> {
        let keys = self.keys.as_ref().ok_or(Error::TooManyWrongCodes)?;
        let typed = parse_code(code)?;
        let expected = confirmation_code(
            &keys.account_key,
            &self.account_id,
            &self.request_id,
            &self.public_key,
        );
        if bool::from(typed.ct_eq(&expected)) {
            self.confirmed = true;
            return Ok(());
        }
        if self.confirmed {
            return Err(Error::WrongCode);
        }
        self.wrong_codes += 1;
        if self.wrong_codes >= CODE_ATTEMPTS {
            self.keys = None;
            return Err(Error::TooManyWrongCodes);
        }
        Err(Error::WrongCode)
    }

    /// Whether [`confirm`](Self::confirm) accepted the code.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed && self.keys.is_some()
    }

    /// Wrong codes [`confirm`](Self::confirm) still takes before refusing the approval for
    /// good (0 once refused).
    pub fn attempts_left(&self) -> u32 {
        if self.keys.is_some() {
            CODE_ATTEMPTS - self.wrong_codes
        } else {
            0
        }
    }

    /// The account's Secret Key (`PA1-…`), when the approving app included it: keep it
    /// like one typed in, so this device can later unlock with the master password.
    /// [`Error::NotConfirmed`] until the code is confirmed.
    pub fn secret_key(&self) -> Result<Option<String>> {
        Ok(self
            .confirmed_keys()?
            .secret_key
            .as_ref()
            .map(SecretKey::format))
    }

    /// Unlock the account bundle the server returned with the sign-in, without the master
    /// password. [`Error::NotConfirmed`] until the code is confirmed; fails for another
    /// account's bundle.
    pub fn unlock(&self, bundle: &AccountBundle) -> Result<UnlockedAccount> {
        let keys = self.confirmed_keys()?;
        if bundle.account_id != self.account_id {
            return Err(Error::Malformed("the bundle belongs to another account"));
        }
        bundle.unlock_with_account_key(keys.account_key.clone())
    }

    fn confirmed_keys(&self) -> Result<&ApprovedKeys> {
        match &self.keys {
            Some(keys) if self.confirmed => Ok(keys),
            _ => Err(Error::NotConfirmed),
        }
    }
}

/// What [`UnlockedAccount::approve_login_request`] returns.
pub struct LoginApproval {
    /// The request's `sealed_key` (base64url) for the server.
    pub sealed: String,
    /// The 6-digit code to show: the new device can't use the approval without it.
    pub code: String,
}

impl UnlockedAccount {
    /// Approve request `request_id`, after the user picked, among
    /// [`login_phrase_choices`] of `requester_public_key` (base64url), `chosen_phrase` as
    /// the words the new device shows. Seals the Account Key, and with `secret_key`
    /// (`PA1-…`) the Secret Key too, to that key and returns it with the code to show.
    /// [`Error::PhraseMismatch`] unless `chosen_phrase` is exactly
    /// [`login_phrase`]`(requester_public_key)` (so the approval goes only to the key whose
    /// words the user picked, even if the request was swapped meanwhile); refuses a
    /// malformed or low-order key (a box anyone could open).
    pub fn approve_login_request(
        &self,
        requester_public_key: &str,
        request_id: &str,
        chosen_phrase: &str,
        secret_key: Option<&str>,
    ) -> Result<LoginApproval> {
        let recipient = public_key_bytes(requester_public_key)?;
        if chosen_phrase != login_phrase_for(&recipient) {
            return Err(Error::PhraseMismatch);
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(ACCOUNT_KEY_LEN + SECRET_KEY_LEN));
        payload.extend_from_slice(self.account_key.as_bytes());
        if let Some(s) = secret_key {
            payload.extend_from_slice(SecretKey::parse(s)?.as_bytes());
        }
        let sealed = b64(&seal_to(
            &recipient,
            &payload,
            &key_aad(&self.account_id, request_id),
        )?);
        let code = confirmation_code(&self.account_key, &self.account_id, request_id, &recipient);
        Ok(LoginApproval {
            sealed,
            code: String::from_utf8(code.to_vec()).expect("ASCII digits"),
        })
    }

    /// Open request `request_id`'s challenge (sealed by the server to this account's
    /// public key): the base64url `proof` the approval sends back. Only a box sealed for
    /// this purpose and this request opens, so it can't be used to read other boxes.
    pub fn open_login_challenge(&self, challenge: &str, request_id: &str) -> Result<String> {
        let aad = [CHALLENGE_AAD, request_id.as_bytes()].concat();
        Ok(b64(&self.keypair.open(&unb64(challenge)?, &aad)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{KdfParams, test_params};
    use crate::keys::{NewAccount, derive_master_keys, share_vault_key};

    fn account(id: &str, with_secret_key: bool) -> NewAccount {
        AccountBundle::create_with_kdf(id, "correct horse", with_secret_key, test_params()).unwrap()
    }

    /// Approve `request` as the user would: pick its words among the choices.
    fn approve(
        account: &UnlockedAccount,
        request: &LoginRequestKey,
        request_id: &str,
        secret_key: Option<&str>,
    ) -> LoginApproval {
        let choices = login_phrase_choices(&request.public_key(), 4).unwrap();
        let picked = choices.iter().find(|c| **c == request.phrase()).unwrap();
        account
            .approve_login_request(&request.public_key(), request_id, picked, secret_key)
            .unwrap()
    }

    /// Another valid code than `code`.
    fn other_code(code: &str) -> String {
        format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000)
    }

    #[test]
    fn phrases_match_the_servers() {
        for (key, phrase) in [
            (
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                "lung spout ashen sudoku gloating",
            ),
            (
                "__________________________________________8",
                "granddad hate dangle spectrum dexterous",
            ),
            (
                "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk",
                "casket thwarting commodity blasphemy ramp",
            ),
        ] {
            assert_eq!(login_phrase(key).unwrap(), phrase);
        }
        assert_eq!(WORDLIST.lines().count(), 7776);
        let request = LoginRequestKey::generate().unwrap();
        assert_eq!(
            request.phrase(),
            login_phrase(&request.public_key()).unwrap()
        );
        assert_eq!(request.phrase().split(' ').count(), PHRASE_WORDS);
        for bad in ["", "short", "not base64!", &b64(&[1; 31]), &b64(&[1; 33])] {
            assert!(login_phrase(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn round_trip_unlocks_the_bundle_after_the_code() {
        let alice = account("user-1", false);
        let request = LoginRequestKey::generate().unwrap();
        let approval = approve(&alice.unlocked, &request, "req-1", None);
        assert_eq!(approval.code.len(), CODE_DIGITS);
        assert!(approval.code.bytes().all(|b| b.is_ascii_digit()));
        let mut approved = request.open(&approval.sealed, "user-1", "req-1").unwrap();
        assert_eq!(approved.account_id(), "user-1");
        assert!(!approved.is_confirmed());
        approved.confirm(&approval.code).unwrap();
        assert!(approved.is_confirmed());
        assert_eq!(approved.secret_key().unwrap(), None);
        let unlocked = approved.unlock(&alice.bundle).unwrap();
        assert_eq!(
            unlocked.account_key.as_bytes(),
            alice.unlocked.account_key.as_bytes()
        );
        assert_eq!(
            unlocked.keypair.public_bytes(),
            alice.unlocked.keypair.public_bytes()
        );
        // It opens the account's vaults, also those shared with it.
        let (vk, wrapped) = alice.unlocked.new_vault_key("v1").unwrap();
        assert_eq!(
            unlocked
                .open_vault_key("v1", 0, &wrapped, true)
                .unwrap()
                .as_bytes(),
            vk.as_bytes()
        );
        let shared = share_vault_key("v2", &vk, &alice.bundle.public_key).unwrap();
        assert!(unlocked.open_shared_vault_key("v2", &shared).is_ok());
        // Another account's bundle doesn't unlock, whatever its id says.
        let bob = account("user-2", false);
        assert!(approved.unlock(&bob.bundle).is_err());
        let mut forged = bob.bundle.clone();
        forged.account_id = "user-1".into();
        assert!(approved.unlock(&forged).is_err());
        // The same code again is fine; a confirmation isn't undone by a wrong one.
        approved.confirm(&approval.code).unwrap();
        assert!(matches!(
            approved.confirm(&other_code(&approval.code)),
            Err(Error::WrongCode)
        ));
        assert!(approved.unlock(&alice.bundle).is_ok());
    }

    #[test]
    fn nothing_is_handed_out_before_the_code() {
        let alice = account("user-1", true);
        let sk = alice.secret_key.clone().unwrap();
        let request = LoginRequestKey::generate().unwrap();
        let approval = approve(&alice.unlocked, &request, "req-1", Some(&sk));
        let mut approved = request.open(&approval.sealed, "user-1", "req-1").unwrap();
        assert!(matches!(approved.secret_key(), Err(Error::NotConfirmed)));
        assert!(matches!(
            approved.unlock(&alice.bundle),
            Err(Error::NotConfirmed)
        ));
        // A malformed code changes nothing and costs no attempt.
        for bad in [
            "",
            "12345",
            "1234567",
            "12 34 5",
            "12345a",
            "12_3456",
            "１２３４５６",
            "١٢٣٤٥٦",
            "+123456",
            "123456\n",
        ] {
            assert!(
                matches!(approved.confirm(bad), Err(Error::Malformed(_))),
                "{bad:?}"
            );
        }
        assert_eq!(approved.attempts_left(), CODE_ATTEMPTS);
        assert!(matches!(approved.secret_key(), Err(Error::NotConfirmed)));
        // Spaces and hyphens are fine.
        let c = &approval.code;
        approved
            .confirm(&format!(" {}-{} {} ", &c[..2], &c[2..4], &c[4..]))
            .unwrap();
        assert_eq!(approved.secret_key().unwrap().as_deref(), Some(sk.as_str()));
        assert!(approved.unlock(&alice.bundle).is_ok());
    }

    #[test]
    fn three_wrong_codes_refuse_the_approval_for_good() {
        let alice = account("user-1", true);
        let sk = alice.secret_key.clone().unwrap();
        let request = LoginRequestKey::generate().unwrap();
        let approval = approve(&alice.unlocked, &request, "req-1", Some(&sk));
        let mut approved = request.open(&approval.sealed, "user-1", "req-1").unwrap();
        let wrong = other_code(&approval.code);
        assert!(matches!(approved.confirm(&wrong), Err(Error::WrongCode)));
        assert_eq!(approved.attempts_left(), 2);
        assert!(matches!(approved.confirm(&wrong), Err(Error::WrongCode)));
        assert_eq!(approved.attempts_left(), 1);
        assert!(matches!(
            approved.confirm(&wrong),
            Err(Error::TooManyWrongCodes)
        ));
        assert_eq!(approved.attempts_left(), 0);
        // Even the right code is refused now, and nothing is handed out.
        assert!(matches!(
            approved.confirm(&approval.code),
            Err(Error::TooManyWrongCodes)
        ));
        assert!(!approved.is_confirmed());
        assert!(matches!(approved.secret_key(), Err(Error::NotConfirmed)));
        assert!(matches!(
            approved.unlock(&alice.bundle),
            Err(Error::NotConfirmed)
        ));
    }

    #[test]
    fn a_forged_approval_fails_the_code() {
        // Review M1 (the reviewer's proof of concept): a malicious server never asks a real
        // app. It picks an Account Key and a key pair, seals that key (and a Secret Key) to
        // the new device with the right associated data, and makes a bundle to match.
        let device = LoginRequestKey::generate().unwrap();
        let device_pk: [u8; 32] = unb64(&device.public_key()).unwrap().try_into().unwrap();
        let k_fake = SymmetricKey::generate().unwrap();
        let kp_fake = KeyPair::generate().unwrap();
        let (account_id, request_id) = ("victim-account-id", "req-42");
        let mut payload = k_fake.as_bytes().to_vec();
        payload.extend_from_slice(&[0xAB; 16]);
        let sealed = b64(&seal_to(&device_pk, &payload, &key_aad(account_id, request_id)).unwrap());
        let bundle = AccountBundle {
            account_id: account_id.into(),
            kdf: KdfParams::new_default().unwrap(),
            secret_key_enabled: true,
            wrapped_account_key: b64(&[1; 57]),
            public_key: b64(&kp_fake.public_bytes()),
            wrapped_private_key: b64(&k_fake
                .encrypt(
                    &kp_fake.secret_bytes(),
                    format!("passauth/private-key/v1/{account_id}").as_bytes(),
                )
                .unwrap()),
        };
        // The box still opens, but hands out nothing.
        let mut approved = device.open(&sealed, account_id, request_id).unwrap();
        assert!(matches!(approved.unlock(&bundle), Err(Error::NotConfirmed)));
        assert!(matches!(approved.secret_key(), Err(Error::NotConfirmed)));
        // The only code the user can get is the one their real app shows for this request
        // (here the real account approves the very same request key, which the server
        // then drops); it isn't the forged key's, and nothing in the user's hands is.
        let real = account(account_id, false);
        let real_code = approve(&real.unlocked, &device, request_id, None).code;
        assert_ne!(
            real_code.as_bytes(),
            confirmation_code(&k_fake, account_id, request_id, &device_pk)
        );
        assert!(matches!(
            approved.confirm(&real_code),
            Err(Error::WrongCode)
        ));
        // Guessing gets nowhere: two more wrong codes refuse the approval for good, after
        // which not even the forged key's own code (which the server knows but can't show
        // on the user's app) is taken.
        let forged = String::from_utf8(
            confirmation_code(&k_fake, account_id, request_id, &device_pk).to_vec(),
        )
        .unwrap();
        let guess = other_code(&forged);
        assert!(matches!(approved.confirm(&guess), Err(Error::WrongCode)));
        assert!(matches!(
            approved.confirm(&other_code(&guess)),
            Err(Error::TooManyWrongCodes)
        ));
        assert!(matches!(
            approved.confirm(&forged),
            Err(Error::TooManyWrongCodes)
        ));
        assert!(!approved.is_confirmed());
        assert!(matches!(approved.unlock(&bundle), Err(Error::NotConfirmed)));
        assert!(matches!(approved.secret_key(), Err(Error::NotConfirmed)));
    }

    #[test]
    fn approvals_go_only_to_the_key_whose_words_were_picked() {
        let alice = account("user-1", false).unlocked;
        let request = LoginRequestKey::generate().unwrap();
        let swapped = LoginRequestKey::generate().unwrap();
        // Review I6: the request's key changed after its words were shown, or the user
        // picked a decoy: nothing is sealed.
        assert!(matches!(
            alice.approve_login_request(&swapped.public_key(), "req-1", &request.phrase(), None),
            Err(Error::PhraseMismatch)
        ));
        let choices = login_phrase_choices(&request.public_key(), 5).unwrap();
        for decoy in choices.iter().filter(|c| **c != request.phrase()) {
            assert!(matches!(
                alice.approve_login_request(&request.public_key(), "req-1", decoy, None),
                Err(Error::PhraseMismatch)
            ));
        }
        // Exactly the words: no other spelling.
        let phrase = request.phrase();
        for near in [
            phrase.to_uppercase(),
            format!(" {phrase}"),
            phrase.replace(' ', "  "),
            phrase.replace(' ', "-"),
            String::new(),
        ] {
            assert!(matches!(
                alice.approve_login_request(&request.public_key(), "req-1", &near, None),
                Err(Error::PhraseMismatch)
            ));
        }
        assert!(
            alice
                .approve_login_request(&request.public_key(), "req-1", &phrase, None)
                .is_ok()
        );
        assert!(matches!(
            alice.approve_login_request("short", "req-1", &phrase, None),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn phrase_choices() {
        let mut seen_at = [0usize; MAX_CHOICES];
        for _ in 0..60 {
            let request = LoginRequestKey::generate().unwrap();
            let real = request.phrase();
            let real_words: Vec<&str> = real.split(' ').collect();
            for count in MIN_CHOICES..=MAX_CHOICES {
                let choices = login_phrase_choices(&request.public_key(), count).unwrap();
                assert_eq!(choices.len(), count);
                let at: Vec<usize> = (0..count).filter(|&i| choices[i] == real).collect();
                assert_eq!(at.len(), 1, "{choices:?}");
                if count == MAX_CHOICES {
                    seen_at[at[0]] += 1;
                }
                for (i, c) in choices.iter().enumerate() {
                    let words: Vec<&str> = c.split(' ').collect();
                    assert_eq!(words.len(), PHRASE_WORDS);
                    assert!(words.iter().all(|w| WORDLIST.lines().any(|l| l == *w)));
                    assert!(!choices[..i].contains(c), "duplicate {c}");
                    if *c != real {
                        assert!(
                            words.iter().zip(&real_words).all(|(a, b)| a != b),
                            "{c} shares a word with {real}"
                        );
                    }
                }
            }
        }
        // Across keys the real phrase turns up in every position.
        assert!(seen_at.iter().all(|&n| n > 0), "{seen_at:?}");
        let request = LoginRequestKey::generate().unwrap();
        for count in [0, 1, MAX_CHOICES + 1, usize::MAX] {
            assert!(login_phrase_choices(&request.public_key(), count).is_err());
        }
        assert!(login_phrase_choices("short", 3).is_err());
        assert!(login_phrase_choices(&b64(&[1; 33]), 3).is_err());
    }

    #[test]
    fn phrase_choices_are_fixed_per_key() {
        // A request seen twice (after "Not now", or on another device) shows the same list, so
        // the real words aren't the only phrase both lists have in common.
        let request = LoginRequestKey::generate().unwrap();
        let key = request.public_key();
        for count in MIN_CHOICES..=MAX_CHOICES {
            let first = login_phrase_choices(&key, count).unwrap();
            for _ in 0..5 {
                assert_eq!(login_phrase_choices(&key, count).unwrap(), first);
            }
        }
        // Another key: other phrases (the decoys too, not only the real one).
        let other = LoginRequestKey::generate().unwrap();
        let mine = login_phrase_choices(&key, MAX_CHOICES).unwrap();
        let theirs = login_phrase_choices(&other.public_key(), MAX_CHOICES).unwrap();
        assert!(
            mine.iter().all(|c| !theirs.contains(c)),
            "{mine:?} {theirs:?}"
        );
        // The first decoys stay the same as the list grows.
        let decoys = |count| -> Vec<String> {
            login_phrase_choices(&key, count)
                .unwrap()
                .into_iter()
                .filter(|c| *c != request.phrase())
                .collect()
        };
        assert_eq!(decoys(3)[..], decoys(MAX_CHOICES)[..2]);
    }

    /// Known answers, computed independently (Node.js: SHA-256 and the EFF list) from the
    /// documented format.
    #[test]
    fn phrase_choices_known_answers() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let (real, d0, d1, d2, d3) = (
            "lung spout ashen sudoku gloating",
            "could regulator babied luckiness pavement",
            "rejoicing chomp tribune rarity renter",
            "urchin provoking quickstep finicky surgical",
            "repent handsfree lid shush puzzling",
        );
        assert_eq!(login_phrase_choices(key, 2).unwrap(), [d0, real]);
        assert_eq!(login_phrase_choices(key, 3).unwrap(), [d0, d1, real]);
        assert_eq!(
            login_phrase_choices(key, 5).unwrap(),
            [real, d0, d1, d2, d3]
        );
        let key = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
        let real = "casket thwarting commodity blasphemy ramp";
        let (d0, d1) = (
            "endless consoling bacterium ramp splashy",
            "driveway smokeless relapse domain nicotine",
        );
        assert_eq!(login_phrase_choices(key, 3).unwrap(), [real, d0, d1]);
        assert_eq!(
            login_phrase_choices(key, 5).unwrap(),
            [
                d0,
                d1,
                real,
                "vagrantly kosher hunter lubricant luckless",
                "violet tasty second hut proud"
            ]
        );
    }

    #[test]
    fn the_secret_key_travels_when_included() {
        let alice = account("user-1", true);
        let sk = alice.secret_key.clone().unwrap();
        let request = LoginRequestKey::generate().unwrap();
        // Typed the way people copy it: lower case, no dashes.
        let typed = sk.replace('-', "").to_lowercase();
        let approval = approve(&alice.unlocked, &request, "req-1", Some(&typed));
        let mut approved = request.open(&approval.sealed, "user-1", "req-1").unwrap();
        approved.confirm(&approval.code).unwrap();
        assert_eq!(approved.secret_key().unwrap().as_deref(), Some(sk.as_str()));
        assert!(approved.unlock(&alice.bundle).is_ok());
        // The device can now unlock with the master password alone.
        let b = &alice.bundle;
        let secret_key = approved.secret_key().unwrap();
        let master = derive_master_keys(
            "correct horse",
            secret_key.as_deref(),
            &b.account_id,
            &b.kdf,
            b.secret_key_enabled,
        )
        .unwrap();
        assert!(b.unlock(&master.auk).is_ok());
        assert!(
            alice
                .unlocked
                .approve_login_request(
                    &request.public_key(),
                    "req-1",
                    &request.phrase(),
                    Some("PA1-NOPE")
                )
                .is_err()
        );
    }

    #[test]
    fn bound_to_the_key_the_account_and_the_request() {
        let alice = account("user-1", false);
        let request = LoginRequestKey::generate().unwrap();
        let approval = approve(&alice.unlocked, &request, "req-1", None);
        let sealed = &approval.sealed;
        assert!(request.open(sealed, "user-1", "req-1").is_ok());
        for (account_id, request_id) in [
            ("user-2", "req-1"),
            ("user-1", "req-2"),
            ("user-1req-1", ""),
            ("", "user-1req-1"),
        ] {
            assert!(matches!(
                request.open(sealed, account_id, request_id),
                Err(Error::Decrypt)
            ));
        }
        let other = LoginRequestKey::generate().unwrap();
        assert!(other.open(sealed, "user-1", "req-1").is_err());
        // Changed on the way.
        let mut bytes = unb64(sealed).unwrap();
        for i in [0, 33, bytes.len() - 1] {
            bytes[i] ^= 1;
            assert!(
                request.open(&b64(&bytes), "user-1", "req-1").is_err(),
                "byte {i}"
            );
            bytes[i] ^= 1;
        }
        assert!(request.open("not base64!", "user-1", "req-1").is_err());
        // An emergency-access box sealed to the same key is not a login key.
        let emergency = alice
            .unlocked
            .new_emergency_key("req-1")
            .unwrap()
            .key
            .seal_for(&request.public_key(), "user-1", "req-1")
            .unwrap();
        assert!(request.open(&emergency, "user-1", "req-1").is_err());
        // The code depends on the account, the request and the request key.
        let k = &alice.unlocked.account_key;
        let pk: [u8; 32] = unb64(&request.public_key()).unwrap().try_into().unwrap();
        let base = confirmation_code(k, "user-1", "req-1", &pk);
        assert_eq!(base, approval.code.as_bytes());
        assert_ne!(confirmation_code(k, "user-2", "req-1", &pk), base);
        assert_ne!(confirmation_code(k, "user-1", "req-2", &pk), base);
        assert_ne!(confirmation_code(k, "user-1req-1", "", &pk), base);
        assert_ne!(confirmation_code(k, "user-1", "req-1", &[7; 32]), base);
        let other_key = SymmetricKey::generate().unwrap();
        assert_ne!(confirmation_code(&other_key, "user-1", "req-1", &pk), base);
    }

    #[test]
    fn the_documented_format() {
        let alice = account("user-1", true);
        let sk = alice.secret_key.clone().unwrap();
        let secret = [0x51; 32];
        let request = LoginRequestKey {
            keypair: KeyPair::from_secret_bytes(secret),
        };
        let sealed = approve(&alice.unlocked, &request, "req-1", Some(&sk)).sealed;
        // Opened with the plain sealed-box primitive and the associated data written out.
        let mut aad = b"passauth/login-with-device/key/v1".to_vec();
        aad.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 6]);
        aad.extend_from_slice(b"user-1");
        aad.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 5]);
        aad.extend_from_slice(b"req-1");
        let plain = KeyPair::from_secret_bytes(secret)
            .open(&unb64(&sealed).unwrap(), &aad)
            .unwrap();
        assert_eq!(plain.len(), 48);
        assert_eq!(&plain[..32], alice.unlocked.account_key.as_bytes());
        assert_eq!(&plain[32..], SecretKey::parse(&sk).unwrap().as_bytes());
        // Any other payload length is refused.
        let odd = seal_to(
            &KeyPair::from_secret_bytes(secret).public_bytes(),
            &[7; 40],
            &aad,
        )
        .unwrap();
        assert!(matches!(
            request.open(&b64(&odd), "user-1", "req-1"),
            Err(Error::Malformed(_))
        ));
    }

    /// Known answer, computed independently (Node.js `crypto.hkdfSync` and `createHmac`)
    /// from the documented format: Account Key 0x44 × 32, account "user-1", request "req-1",
    /// request key = the X25519 public key of the secret 0x51 × 32
    /// (`rZCKinCKygdYjNp8TtPkTUlmqAqauy8eS7rFPGdBTjQ`).
    const KAT_CODE: &str = "598354";

    #[test]
    fn code_known_answer() {
        let pk = KeyPair::from_secret_bytes([0x51; 32]).public_bytes();
        assert_eq!(b64(&pk), "rZCKinCKygdYjNp8TtPkTUlmqAqauy8eS7rFPGdBTjQ");
        let key = SymmetricKey::from_bytes([0x44; 32]);
        assert_eq!(
            confirmation_code(&key, "user-1", "req-1", &pk),
            KAT_CODE.as_bytes()
        );
        // The same through the public API.
        let grantor = UnlockedAccount {
            account_id: "user-1".into(),
            account_key: key,
            keypair: KeyPair::from_secret_bytes([0x61; 32]),
        };
        let approval = grantor
            .approve_login_request(&b64(&pk), "req-1", &login_phrase_for(&pk), None)
            .unwrap();
        assert_eq!(approval.code, KAT_CODE);
        let request = LoginRequestKey {
            keypair: KeyPair::from_secret_bytes([0x51; 32]),
        };
        let mut approved = request.open(&approval.sealed, "user-1", "req-1").unwrap();
        approved.confirm(KAT_CODE).unwrap();
    }

    #[test]
    fn low_order_and_malformed_requester_keys_are_refused() {
        let alice = account("user-1", false).unlocked;
        let order8 = |h: &str| -> [u8; 32] { hex::decode(h).unwrap().try_into().unwrap() };
        for bad in [
            [0u8; 32],
            order8("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            order8("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ] {
            // Even with the right words picked.
            assert!(matches!(
                alice.approve_login_request(&b64(&bad), "req-1", &login_phrase_for(&bad), None),
                Err(Error::Malformed(_))
            ));
        }
        for bad in ["", "short", &b64(&[1; 31]), &b64(&[1; 33])] {
            assert!(
                alice.approve_login_request(bad, "req-1", "", None).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn challenges_open_only_for_their_request() {
        let alice = account("user-1", false).unlocked;
        // As the server seals it (auth_requests.rs `list`).
        let nonce = [0x42u8; 32];
        let aad = [CHALLENGE_AAD, b"req-1"].concat();
        let challenge = b64(&seal_to(&alice.keypair.public_bytes(), &nonce, &aad).unwrap());
        assert_eq!(
            alice.open_login_challenge(&challenge, "req-1").unwrap(),
            b64(&nonce)
        );
        assert!(alice.open_login_challenge(&challenge, "req-2").is_err());
        let bob = account("user-2", false).unlocked;
        assert!(bob.open_login_challenge(&challenge, "req-1").is_err());
        // Not a decryption oracle: a shared vault key or an emergency box sealed to the
        // account doesn't open as a challenge.
        let vk = SymmetricKey::generate().unwrap();
        let shared = share_vault_key("v1", &vk, &b64(&alice.keypair.public_bytes())).unwrap();
        assert!(alice.open_login_challenge(&shared, "v1").is_err());
        let emergency = bob
            .new_emergency_key("req-1")
            .unwrap()
            .key
            .seal_for(&b64(&alice.keypair.public_bytes()), "user-2", "req-1")
            .unwrap();
        assert!(alice.open_login_challenge(&emergency, "user-2").is_err());
        assert!(alice.open_login_challenge(&emergency, "req-1").is_err());
        assert!(alice.open_login_challenge("", "req-1").is_err());
    }
}
