//! PassAuth core: cryptography, vault data model, TOTP and importers.
//!
//! This crate is shared by every client (web vault and extension via WASM,
//! mobile via UniFFI). The server never links it for decryption — it only
//! stores the opaque ciphertexts produced here.

pub mod crypto;
pub mod error;
pub mod generator;
pub mod import;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod opaque;
pub mod passkey;
pub mod totp;

pub use error::{Error, Result};
