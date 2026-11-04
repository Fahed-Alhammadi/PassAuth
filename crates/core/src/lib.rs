//! PassAuth core: cryptography, vault data model, TOTP and importers.
//!
//! This crate is shared by every client (web vault and extension via WASM,
//! mobile via UniFFI). The server never links it for decryption — it only
//! stores the opaque ciphertexts produced here.

// The fast test KDF must never reach a release build of any client or server.
#[cfg(all(feature = "insecure-test-kdf", not(debug_assertions)))]
compile_error!("the `insecure-test-kdf` feature is for debug test builds only");

pub mod crypto;
pub mod error;
pub mod export;
pub mod generator;
pub mod import;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod opaque;
pub mod passkey;
pub mod totp;

pub use error::{Error, Result};
