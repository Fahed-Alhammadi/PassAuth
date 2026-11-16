//! Attachment files: XChaCha20-Poly1305 in the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizár 2015), so apps encrypt and decrypt files of any
//! size in 64 KiB pieces without holding a whole file in memory.
//!
//! ```text
//! file    = header ‖ chunk_0 ‖ … ‖ chunk_{n-1}       n = max(1, ⌈size / 65536⌉)
//! header  = 0x01 (version) ‖ prefix (19 random bytes, new for every encryption)
//! chunk_i = XChaCha20-Poly1305(file key, nonce_i, aad, plaintext_i) = ciphertext ‖ tag (16)
//! nonce_i = prefix ‖ i (u32, big-endian) ‖ 0x01 for the last chunk, else 0x00
//! aad     = "passauth/file/v1/<item id>/<attachment id>"
//! ```
//!
//! Every chunk holds 65536 bytes of the file except the last, which holds the
//! rest: 1–65536 bytes, 0 only for an empty file. So the encrypted size is
//! `20 + size + 16·n` ([`encrypted_size`]), which apps register with the server
//! before uploading.
//!
//! The counter in the nonce stops chunks from being reordered or dropped, the
//! last-chunk flag stops a file from being cut short at a chunk boundary or
//! extended, and the associated data stops a file from being served as another
//! attachment, or as one of another item. The vault is not bound: an item keeps
//! its id and its files when it moves to another vault. [`FileDecryptor`] gives
//! out a chunk's plaintext only after its tag checked out, and holds back a full
//! chunk until it knows whether more follows; a file that ends early, or goes on
//! after its last chunk, fails. Until [`FileDecryptor::finish`] succeeds, what
//! came out is an authentic beginning of the file, not the whole file: on an
//! error, throw away everything written so far.

use chacha20poly1305::{
    Tag, XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{SymmetricKey, random_bytes};
use crate::item::{b64, unb64};
use crate::{Error, Result};

pub const VERSION: u8 = 1;
/// Plaintext bytes per chunk (all but the last).
pub const CHUNK: usize = 64 * 1024;
/// Header bytes before the first chunk.
pub const HEADER: usize = 1 + PREFIX;
const PREFIX: usize = 19;
const TAG: usize = 16;
/// Ciphertext bytes per full chunk.
const SEALED_CHUNK: usize = CHUNK + TAG;
/// At most this many chunks (the counter is 32 bits): files up to 256 TiB.
const MAX_CHUNKS: u64 = 1 << 32;

/// An attachment's random 256-bit key, wiped from memory on drop. Apps keep it
/// (base64url) in the item's attachment list, inside the encrypted item.
#[derive(Clone)]
pub struct FileKey(SymmetricKey);

impl FileKey {
    pub fn generate() -> Result<Self> {
        SymmetricKey::generate().map(Self)
    }

    /// base64url (no padding) of exactly 32 bytes.
    pub fn from_b64(s: &str) -> Result<Self> {
        let raw = Zeroizing::new(unb64(s)?);
        SymmetricKey::from_slice(&raw)
            .map(Self)
            .map_err(|_| Error::Malformed("file key length"))
    }

    pub fn to_b64(&self) -> String {
        b64(self.0.as_bytes())
    }
}

/// The encrypted size of a file of `size` bytes: what the server is told before
/// the upload, and what counts toward its attachment size limit.
pub fn encrypted_size(size: u64) -> Result<u64> {
    let chunks = size.div_ceil(CHUNK as u64).max(1);
    if chunks > MAX_CHUNKS {
        return Err(Error::Malformed("file too large"));
    }
    // At most 2^48 + 2^36 + 20: no overflow.
    Ok(HEADER as u64 + size + TAG as u64 * chunks)
}

/// The size of the file behind an encrypted size; an error for a size no file
/// encrypts to.
pub fn plain_size(encrypted: u64) -> Result<u64> {
    const BAD: Error = Error::Malformed("not the size of an encrypted file");
    let body = encrypted.checked_sub(HEADER as u64).ok_or(BAD)?;
    let (full, rest) = (body / SEALED_CHUNK as u64, body % SEALED_CHUNK as u64);
    let size = match rest {
        0 if full > 0 => full * CHUNK as u64,
        r if r > TAG as u64 || (r == TAG as u64 && full == 0) => {
            full * CHUNK as u64 + (r - TAG as u64)
        }
        _ => return Err(BAD),
    };
    if encrypted_size(size)? != encrypted {
        return Err(BAD);
    }
    Ok(size)
}

/// Encrypt a whole file at once (small files; use [`FileEncryptor`] for large ones).
pub fn encrypt(
    key: &FileKey,
    item_id: &str,
    attachment_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut enc = FileEncryptor::new(key, item_id, attachment_id)?;
    let mut out =
        Vec::with_capacity(usize::try_from(encrypted_size(plaintext.len() as u64)?).unwrap_or(0));
    enc.push_into(plaintext, &mut out)?;
    enc.finish_into(&mut out)?;
    Ok(out)
}

/// Decrypt a whole file at once (small files; use [`FileDecryptor`] for large ones).
pub fn decrypt(
    key: &FileKey,
    item_id: &str,
    attachment_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut dec = FileDecryptor::new(key, item_id, attachment_id)?;
    let size = plain_size(ciphertext.len() as u64).unwrap_or(0);
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    let result = dec
        .push_into(ciphertext, &mut out)
        .and_then(|()| dec.finish_into(&mut out));
    wipe_on_error(result, out)
}

/// `out` on success; on an error, the plaintext gathered so far is wiped.
fn wipe_on_error(result: Result<()>, mut out: Vec<u8>) -> Result<Vec<u8>> {
    match result {
        Ok(()) => Ok(out),
        Err(e) => {
            out.zeroize();
            Err(e)
        }
    }
}

fn aad(item_id: &str, attachment_id: &str) -> Result<Vec<u8>> {
    if [item_id, attachment_id]
        .iter()
        .any(|id| id.is_empty() || id.contains('/'))
    {
        return Err(Error::Malformed(
            "item and attachment ids must be non-empty, without '/'",
        ));
    }
    Ok(format!("passauth/file/v1/{item_id}/{attachment_id}").into_bytes())
}

fn nonce(prefix: &[u8; PREFIX], counter: u32, last: bool) -> XNonce {
    let mut n = [0u8; 24];
    n[..PREFIX].copy_from_slice(prefix);
    n[PREFIX..PREFIX + 4].copy_from_slice(&counter.to_be_bytes());
    n[PREFIX + 4] = u8::from(last);
    XNonce::from(n)
}

fn cipher(key: &SymmetricKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key.as_bytes()).into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Finished,
    Failed,
}

fn closed() -> Error {
    Error::Malformed("file stream already finished or failed")
}

/// Encrypts one file in pieces: [`push`](Self::push) any amount of plaintext,
/// then [`finish`](Self::finish) once. The file is the concatenation of every
/// output, in order (the header comes out with the first one).
pub struct FileEncryptor {
    key: SymmetricKey,
    aad: Vec<u8>,
    prefix: [u8; PREFIX],
    counter: u32,
    header_written: bool,
    /// Plaintext of the chunk being filled (at most [`CHUNK`] bytes).
    buf: Zeroizing<Vec<u8>>,
    state: State,
}

impl FileEncryptor {
    /// `item_id` and `attachment_id` exactly as stored (the server's attachment id).
    pub fn new(key: &FileKey, item_id: &str, attachment_id: &str) -> Result<Self> {
        Self::with_prefix(key, item_id, attachment_id, random_bytes()?)
    }

    fn with_prefix(
        key: &FileKey,
        item_id: &str,
        attachment_id: &str,
        prefix: [u8; PREFIX],
    ) -> Result<Self> {
        Ok(Self {
            key: key.0.clone(),
            aad: aad(item_id, attachment_id)?,
            prefix,
            counter: 0,
            header_written: false,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK)),
            state: State::Open,
        })
    }

    /// Encrypt more of the file. Returns the ciphertext of every chunk that is now
    /// complete (often nothing: a full chunk waits until more data or `finish`).
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.push_into(data, &mut out)?;
        Ok(out)
    }

    /// The last chunk. The encryptor can't be used afterwards.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.finish_into(&mut out)?;
        Ok(out)
    }

    fn push_into(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.check_open()?;
        let seals = (self.buf.len() + data.len()).saturating_sub(1) / CHUNK;
        out.reserve(HEADER + seals * SEALED_CHUNK);
        self.write_header(out);
        loop {
            let take = (CHUNK - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            // A full chunk is sealed only once more data follows it.
            if self.buf.len() < CHUNK || data.is_empty() {
                return Ok(());
            }
            self.seal(false, out)?;
        }
    }

    fn finish_into(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.check_open()?;
        out.reserve(HEADER + self.buf.len() + TAG);
        self.write_header(out);
        self.seal(true, out)?;
        self.state = State::Finished;
        Ok(())
    }

    fn check_open(&self) -> Result<()> {
        if self.state == State::Open {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn write_header(&mut self, out: &mut Vec<u8>) {
        if !self.header_written {
            out.push(VERSION);
            out.extend_from_slice(&self.prefix);
            self.header_written = true;
        }
    }

    /// Encrypt the buffered chunk in place and append it to `out`.
    fn seal(&mut self, last: bool, out: &mut Vec<u8>) -> Result<()> {
        if !last && self.counter == u32::MAX {
            self.state = State::Failed;
            return Err(Error::Malformed("file too large"));
        }
        let nonce = nonce(&self.prefix, self.counter, last);
        let Ok(tag) = cipher(&self.key).encrypt_inout_detached(
            &nonce,
            &self.aad,
            self.buf.as_mut_slice().into(),
        ) else {
            self.state = State::Failed;
            return Err(Error::Malformed("chunk encryption failed"));
        };
        out.extend_from_slice(&self.buf);
        out.extend_from_slice(&tag);
        self.buf.clear();
        if !last {
            self.counter += 1;
        }
        Ok(())
    }
}

/// Decrypts one file in pieces: [`push`](Self::push) the ciphertext as it
/// arrives, in any sizes, then [`finish`](Self::finish) once. Each output is
/// plaintext whose chunk was authenticated; only `finish` tells the file was whole.
pub struct FileDecryptor {
    key: SymmetricKey,
    aad: Vec<u8>,
    /// Known once the header has arrived.
    prefix: Option<[u8; PREFIX]>,
    counter: u32,
    /// Header bytes until it is complete, then the ciphertext of one chunk at most.
    buf: Zeroizing<Vec<u8>>,
    state: State,
}

impl FileDecryptor {
    /// `item_id` and `attachment_id` exactly as when the file was encrypted.
    pub fn new(key: &FileKey, item_id: &str, attachment_id: &str) -> Result<Self> {
        Ok(Self {
            key: key.0.clone(),
            aad: aad(item_id, attachment_id)?,
            prefix: None,
            counter: 0,
            buf: Zeroizing::new(Vec::with_capacity(SEALED_CHUNK)),
            state: State::Open,
        })
    }

    /// Decrypt more of the file. Returns the plaintext of every chunk that is now
    /// complete and authentic; [`Error::Decrypt`] (and a failed decryptor) as soon
    /// as one is not.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let result = self.push_into(data, &mut out);
        wipe_on_error(result, out)
    }

    /// The last chunk's plaintext. Fails with [`Error::Decrypt`] when the file was
    /// cut short (or is not this attachment's). The decryptor can't be used afterwards.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let result = self.finish_into(&mut out);
        wipe_on_error(result, out)
    }

    fn push_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.check_open()?;
        let result = self.read(data, out);
        if result.is_err() {
            self.fail();
        }
        result
    }

    fn read(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.prefix.is_none() {
            let take = (HEADER - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() < HEADER {
                return Ok(());
            }
            if self.buf[0] != VERSION {
                return Err(Error::UnsupportedVersion(self.buf[0]));
            }
            self.prefix = Some(self.buf[1..HEADER].try_into().expect("header length"));
            self.buf.clear();
        }
        let opens = (self.buf.len() + data.len()).saturating_sub(1) / SEALED_CHUNK;
        out.reserve(opens * CHUNK);
        loop {
            let take = (SEALED_CHUNK - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            // A full chunk is the last one unless more data follows it.
            if self.buf.len() < SEALED_CHUNK || data.is_empty() {
                return Ok(());
            }
            self.open(false, out)?;
        }
    }

    fn finish_into(&mut self, out: &mut Vec<u8>) -> Result<()> {
        self.check_open()?;
        let result = if self.prefix.is_none() || self.buf.len() < TAG {
            // Cut short inside the header or the last chunk's tag.
            Err(Error::Decrypt)
        } else if self.buf.len() == TAG && self.counter > 0 {
            Err(Error::Malformed("empty last chunk"))
        } else {
            self.open(true, out)
        };
        match result {
            Ok(()) => self.state = State::Finished,
            Err(_) => self.fail(),
        }
        result
    }

    fn check_open(&self) -> Result<()> {
        if self.state == State::Open {
            Ok(())
        } else {
            Err(closed())
        }
    }

    fn fail(&mut self) {
        self.state = State::Failed;
        self.buf.zeroize();
    }

    /// Authenticate and decrypt the buffered chunk in place, then append it to `out`.
    fn open(&mut self, last: bool, out: &mut Vec<u8>) -> Result<()> {
        if !last && self.counter == u32::MAX {
            return Err(Error::Decrypt);
        }
        let prefix = self.prefix.as_ref().expect("header read");
        let nonce = nonce(prefix, self.counter, last);
        let split = self.buf.len() - TAG;
        let (msg, tag) = self.buf.split_at_mut(split);
        let tag = Tag::try_from(&*tag).expect("tag length");
        // Checks the tag before decrypting: nothing unauthenticated is ever written.
        cipher(&self.key)
            .decrypt_inout_detached(&nonce, &self.aad, msg.into(), &tag)
            .map_err(|_| Error::Decrypt)?;
        out.extend_from_slice(msg);
        self.buf.zeroize();
        if !last {
            self.counter += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const ITEM: &str = "0b7c5f0e-6a43-4c55-9d1f-3a2e8f9b1c00";
    const ATT: &str = "5d0f3c1a-8e2b-4f6d-a7c9-1b3e5d7f9a11";

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn key() -> FileKey {
        FileKey::generate().unwrap()
    }

    /// Push `plain` in slices of `step` bytes; returns the whole ciphertext.
    fn encrypt_in(k: &FileKey, plain: &[u8], step: usize) -> Vec<u8> {
        let mut enc = FileEncryptor::new(k, ITEM, ATT).unwrap();
        let mut out = Vec::new();
        for piece in plain.chunks(step.max(1)) {
            out.extend(enc.push(piece).unwrap());
        }
        out.extend(enc.finish().unwrap());
        out
    }

    fn decrypt_in(k: &FileKey, ct: &[u8], step: usize) -> Result<Vec<u8>> {
        let mut dec = FileDecryptor::new(k, ITEM, ATT)?;
        let mut out = Vec::new();
        for piece in ct.chunks(step.max(1)) {
            out.extend(dec.push(piece)?);
        }
        out.extend(dec.finish()?);
        Ok(out)
    }

    const SIZES: [usize; 9] = [
        0,
        1,
        CHUNK - 1,
        CHUNK,
        CHUNK + 1,
        2 * CHUNK - 1,
        2 * CHUNK,
        2 * CHUNK + 1,
        3 * CHUNK + 777,
    ];

    #[test]
    fn roundtrip_in_any_slicing() {
        let k = key();
        for size in SIZES {
            let plain = data(size);
            let one_shot = encrypt(&k, ITEM, ATT, &plain).unwrap();
            assert_eq!(one_shot.len() as u64, encrypted_size(size as u64).unwrap());
            assert_eq!(plain_size(one_shot.len() as u64).unwrap(), size as u64);
            assert_eq!(decrypt(&k, ITEM, ATT, &one_shot).unwrap(), plain);
            for step in [
                1,
                7,
                4096,
                CHUNK - 1,
                CHUNK,
                CHUNK + 1,
                SEALED_CHUNK,
                usize::MAX,
            ] {
                if step == 1 && size > CHUNK + 1 {
                    continue; // slow and covered by the smaller sizes
                }
                let ct = encrypt_in(&k, &plain, step);
                assert_eq!(ct.len(), one_shot.len(), "size {size} step {step}");
                assert_eq!(decrypt_in(&k, &ct, step).unwrap(), plain);
                assert_eq!(decrypt_in(&k, &ct, 13).unwrap(), plain);
                assert_eq!(decrypt(&k, ITEM, ATT, &ct).unwrap(), plain);
            }
        }
    }

    #[test]
    fn layout_matches_the_spec() {
        let k = key();
        let ct = encrypt(&k, ITEM, ATT, &data(CHUNK + 5)).unwrap();
        assert_eq!(ct[0], VERSION);
        assert_eq!(ct.len(), HEADER + SEALED_CHUNK + 5 + TAG);
        // Every chunk opens with the raw cipher, the documented nonce and associated data.
        let prefix: [u8; PREFIX] = ct[1..HEADER].try_into().unwrap();
        let aad = format!("passauth/file/v1/{ITEM}/{ATT}");
        let mut first = ct[HEADER..HEADER + SEALED_CHUNK].to_vec();
        let (msg, tag) = first.split_at_mut(CHUNK);
        cipher(&k.0)
            .decrypt_inout_detached(
                &nonce(&prefix, 0, false),
                aad.as_bytes(),
                msg.into(),
                &Tag::try_from(&*tag).unwrap(),
            )
            .unwrap();
        assert_eq!(msg, &data(CHUNK)[..]);
        let mut last = ct[HEADER + SEALED_CHUNK..].to_vec();
        let (msg, tag) = last.split_at_mut(5);
        cipher(&k.0)
            .decrypt_inout_detached(
                &nonce(&prefix, 1, true),
                aad.as_bytes(),
                msg.into(),
                &Tag::try_from(&*tag).unwrap(),
            )
            .unwrap();
        assert_eq!(msg, &data(CHUNK + 5)[CHUNK..]);
        // A new prefix for every encryption.
        let again = encrypt(&k, ITEM, ATT, &data(CHUNK + 5)).unwrap();
        assert_ne!(again[1..HEADER], ct[1..HEADER]);
    }

    #[test]
    fn wrong_key_or_another_attachment_fails() {
        let k = key();
        let ct = encrypt(&k, ITEM, ATT, &data(100)).unwrap();
        assert!(matches!(
            decrypt(&key(), ITEM, ATT, &ct),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            decrypt(&k, ITEM, "5d0f3c1a-8e2b-4f6d-a7c9-1b3e5d7f9a12", &ct),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            decrypt(&k, "0b7c5f0e-6a43-4c55-9d1f-3a2e8f9b1c01", ATT, &ct),
            Err(Error::Decrypt)
        ));
        // Ids can't be shifted between the two parts.
        assert!(aad("a/b", "c").is_err());
        assert!(aad("a", "b/c").is_err());
        assert!(FileEncryptor::new(&k, "", ATT).is_err());
        assert!(FileDecryptor::new(&k, ITEM, "").is_err());
    }

    #[test]
    fn any_flipped_bit_fails() {
        let k = key();
        let ct = encrypt(&k, ITEM, ATT, &data(CHUNK + 40)).unwrap();
        let spots = [
            0,
            1,
            HEADER - 1,
            HEADER,
            HEADER + CHUNK - 1,
            HEADER + CHUNK,
            HEADER + SEALED_CHUNK - 1,
            HEADER + SEALED_CHUNK,
            ct.len() - TAG,
            ct.len() - 1,
        ];
        for i in spots {
            let mut bad = ct.clone();
            bad[i] ^= 1;
            let err = decrypt_in(&k, &bad, 4096).unwrap_err();
            if i == 0 {
                assert!(matches!(err, Error::UnsupportedVersion(0)), "byte {i}");
            } else {
                assert!(matches!(err, Error::Decrypt), "byte {i}: {err:?}");
            }
        }
    }

    #[test]
    fn truncation_extension_and_reordering_fail() {
        let k = key();
        let plain = data(2 * CHUNK + 10);
        let ct = encrypt(&k, ITEM, ATT, &plain).unwrap();
        let c0 = &ct[HEADER..HEADER + SEALED_CHUNK];
        let c1 = &ct[HEADER + SEALED_CHUNK..HEADER + 2 * SEALED_CHUNK];
        let c2 = &ct[HEADER + 2 * SEALED_CHUNK..];
        let header = &ct[..HEADER];
        let join = |parts: &[&[u8]]| parts.concat();
        // Cut at chunk boundaries: the new last chunk wasn't sealed as the last.
        for cut in [join(&[header, c0]), join(&[header, c0, c1])] {
            assert!(matches!(decrypt(&k, ITEM, ATT, &cut), Err(Error::Decrypt)));
        }
        // Cut anywhere else, down to nothing.
        for len in [
            0,
            1,
            HEADER - 1,
            HEADER,
            HEADER + 1,
            HEADER + TAG,
            ct.len() - 1,
        ] {
            assert!(decrypt(&k, ITEM, ATT, &ct[..len]).is_err(), "len {len}");
        }
        // Extended: a chunk after the last one, or a single byte.
        assert!(decrypt(&k, ITEM, ATT, &join(&[&ct, c2])).is_err());
        assert!(decrypt(&k, ITEM, ATT, &join(&[&ct, &[0]])).is_err());
        // Reordered, duplicated or dropped chunks.
        for bad in [
            join(&[header, c1, c0, c2]),
            join(&[header, c0, c0, c2]),
            join(&[header, c1, c2]),
            join(&[header, c0, c2]),
        ] {
            assert!(matches!(decrypt(&k, ITEM, ATT, &bad), Err(Error::Decrypt)));
        }
        // Spliced from another encryption of the same file under the same key.
        let other = encrypt(&k, ITEM, ATT, &plain).unwrap();
        let mixed = join(&[header, c0, &other[HEADER + SEALED_CHUNK..]]);
        assert!(matches!(
            decrypt(&k, ITEM, ATT, &mixed),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn no_plaintext_before_authentication() {
        let k = key();
        let plain = data(2 * CHUNK + 10);
        let ct = encrypt(&k, ITEM, ATT, &plain).unwrap();
        let mut dec = FileDecryptor::new(&k, ITEM, ATT).unwrap();
        // A whole first chunk: held back, it might be the last one.
        assert!(dec.push(&ct[..HEADER + SEALED_CHUNK]).unwrap().is_empty());
        // One more byte proves it isn't: now it comes out.
        let out = dec
            .push(&ct[HEADER + SEALED_CHUNK..HEADER + SEALED_CHUNK + 1])
            .unwrap();
        assert_eq!(out, &plain[..CHUNK]);

        // A tampered chunk gives nothing, and the decryptor stays failed.
        let mut bad = ct.clone();
        bad[HEADER + 5] ^= 1;
        let mut dec = FileDecryptor::new(&k, ITEM, ATT).unwrap();
        assert!(dec.push(&bad[..HEADER + SEALED_CHUNK]).unwrap().is_empty());
        assert!(matches!(
            dec.push(&bad[HEADER + SEALED_CHUNK..]),
            Err(Error::Decrypt)
        ));
        assert!(dec.push(&ct[..1]).is_err());
        assert!(dec.finish().is_err());

        // After finish, nothing more.
        let mut dec = FileDecryptor::new(&k, ITEM, ATT).unwrap();
        let mut out = dec.push(&ct).unwrap();
        out.extend(dec.finish().unwrap());
        assert_eq!(out, plain);
        assert!(dec.push(b"x").is_err());
        assert!(dec.finish().is_err());
    }

    #[test]
    fn encryptor_is_single_use() {
        let k = key();
        let mut enc = FileEncryptor::new(&k, ITEM, ATT).unwrap();
        let mut ct = enc.push(b"abc").unwrap();
        assert_eq!(ct.len(), HEADER); // only the header so far
        ct.extend(enc.finish().unwrap());
        assert!(enc.push(b"more").is_err());
        assert!(enc.finish().is_err());
        assert_eq!(decrypt(&k, ITEM, ATT, &ct).unwrap(), b"abc");
        // Nothing pushed at all: an empty file.
        let mut enc = FileEncryptor::new(&k, ITEM, ATT).unwrap();
        let empty = enc.finish().unwrap();
        assert_eq!(empty.len(), HEADER + TAG);
        assert_eq!(decrypt(&k, ITEM, ATT, &empty).unwrap(), b"");
    }

    #[test]
    fn empty_last_chunk_after_full_ones_is_refused() {
        // Not something this encoder writes: each size has one encoding.
        // Built by hand: a full chunk sealed as not the last, then an empty last one.
        let k = key();
        let mut enc = FileEncryptor::new(&k, ITEM, ATT).unwrap();
        let mut file = Vec::new();
        enc.write_header(&mut file);
        enc.buf.extend_from_slice(&data(CHUNK));
        enc.seal(false, &mut file).unwrap();
        enc.seal(true, &mut file).unwrap();
        assert_eq!(file.len(), HEADER + SEALED_CHUNK + TAG);
        assert!(matches!(
            decrypt(&k, ITEM, ATT, &file),
            Err(Error::Malformed("empty last chunk"))
        ));
    }

    #[test]
    fn sizes() {
        assert_eq!(encrypted_size(0).unwrap(), 36);
        assert_eq!(encrypted_size(1).unwrap(), 37);
        assert_eq!(encrypted_size(CHUNK as u64).unwrap(), 20 + 65536 + 16);
        assert_eq!(encrypted_size(CHUNK as u64 + 1).unwrap(), 20 + 65537 + 32);
        let gib4 = 4u64 << 30;
        assert_eq!(encrypted_size(gib4).unwrap(), 20 + gib4 + 16 * 65536);
        assert_eq!(plain_size(20 + gib4 + 16 * 65536).unwrap(), gib4);
        let max = MAX_CHUNKS * CHUNK as u64;
        assert!(encrypted_size(max).is_ok());
        assert!(encrypted_size(max + 1).is_err());
        assert!(encrypted_size(u64::MAX).is_err());
        for size in [
            0u64, 1, 15, 16, 17, 65535, 65536, 65537, 131072, 131073, 10_000_000,
        ] {
            assert_eq!(plain_size(encrypted_size(size).unwrap()).unwrap(), size);
        }
        // Sizes no file encrypts to.
        for bad in [
            0u64,
            19,
            20,
            35,
            20 + SEALED_CHUNK as u64 + 1,
            20 + SEALED_CHUNK as u64 + 15,
            20 + SEALED_CHUNK as u64 + 16,
        ] {
            assert!(plain_size(bad).is_err(), "{bad}");
        }
        assert!(plain_size(u64::MAX).is_err());
    }

    #[test]
    fn counter_cannot_wrap() {
        let k = key();
        let mut enc = FileEncryptor::new(&k, ITEM, ATT).unwrap();
        enc.counter = u32::MAX;
        assert!(enc.push(&data(CHUNK + 1)).is_err());
        assert!(enc.finish().is_err());
        let mut dec = FileDecryptor::new(&k, ITEM, ATT).unwrap();
        let ct = encrypt(&k, ITEM, ATT, &data(CHUNK + 1)).unwrap();
        dec.push(&ct[..HEADER]).unwrap();
        dec.counter = u32::MAX;
        assert!(matches!(dec.push(&ct[HEADER..]), Err(Error::Decrypt)));
    }

    #[test]
    fn unknown_version() {
        let k = key();
        let mut ct = encrypt(&k, ITEM, ATT, b"x").unwrap();
        ct[0] = 2;
        let mut dec = FileDecryptor::new(&k, ITEM, ATT).unwrap();
        assert!(matches!(dec.push(&ct), Err(Error::UnsupportedVersion(2))));
    }

    #[test]
    fn keys_are_parsed_strictly() {
        let k = key();
        assert_eq!(FileKey::from_b64(&k.to_b64()).unwrap().to_b64(), k.to_b64());
        assert!(FileKey::from_b64(&b64(&[1; 16])).is_err());
        assert!(FileKey::from_b64("").is_err());
        assert!(FileKey::from_b64(&format!("{}=", k.to_b64())).is_err());
    }

    /// Known answer, computed independently (Node.js: HChaCha20 + OpenSSL
    /// ChaCha20-Poly1305) from the format in the module docs.
    #[test]
    fn known_answer() {
        let k = FileKey::from_b64(&b64(&(0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect::<Vec<_>>()))
        .unwrap();
        let prefix: [u8; PREFIX] = core::array::from_fn(|i| 0xa0 + i as u8);
        let item = "11111111-2222-4333-8444-555555555555";
        let att = "66666666-7777-4888-8999-aaaaaaaaaaaa";
        // A small file: one last chunk.
        let mut enc = FileEncryptor::with_prefix(&k, item, att, prefix).unwrap();
        let mut small = enc.push(b"PassAuth attachment").unwrap();
        small.extend(enc.finish().unwrap());
        assert_eq!(hex::encode(&small), KAT_SMALL);
        // Two chunks (65536 + 1000 bytes of i mod 251).
        let plain = data(CHUNK + 1000);
        let mut enc = FileEncryptor::with_prefix(&k, item, att, prefix).unwrap();
        let mut big = enc.push(&plain).unwrap();
        big.extend(enc.finish().unwrap());
        assert_eq!(big.len(), HEADER + SEALED_CHUNK + 1000 + TAG);
        assert_eq!(hex::encode(Sha256::digest(&big)), KAT_TWO_CHUNKS_SHA256);
        assert_eq!(decrypt(&k, item, att, &big).unwrap(), plain);
    }

    const KAT_SMALL: &str = "01a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2\
        72fcc90d91255d3f3744446cb6e87e2a645c7569ac9750b5cac4a6cc1c5d014859b36f";
    const KAT_TWO_CHUNKS_SHA256: &str =
        "1239e1c103d57727ac7563046da479c44870f380bbc38272916533bedb748b16";
}
