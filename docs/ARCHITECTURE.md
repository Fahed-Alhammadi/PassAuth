# PassAuth Architecture

PassAuth is a self-hosted, zero-knowledge password manager. The server stores only ciphertext and can never read vault contents, item names, or URLs.

## Components

| Component | Tech | Notes |
|---|---|---|
| `crates/core` | Rust | All crypto, item model, importers. One implementation shared by every client. |
| `crates/server` | Rust (axum, tokio, sqlx) | REST API + WebSocket sync, SMTP, admin. Serves the web vault. |
| `crates/core-wasm` | Rust → WebAssembly | `core` bindings for the web vault and extension. |
| `web/` | TypeScript, React, Vite | Web vault, embedded into the server binary. |
| `extension/` | TypeScript, Chrome MV3 | Login, autofill, TOTP, passkey provider. |
| `mobile/` (stage 2) | Swift / Kotlin | Native apps calling `core` through UniFFI. |

### Why Rust
- Memory-safe without a garbage collector: fast, small container, low RAM.
- The same crypto code compiles to WASM (browser, extension) and native libraries (iOS, Android), so there is exactly one audited implementation of the vault format.
- Mature, audited crates: RustCrypto (`argon2`, `chacha20poly1305`, `hkdf`, `x25519-dalek`, `ed25519-dalek`), `opaque-ke`, `webauthn-rs`, `lettre`.

## Cryptography

### Account keys
```
master password ─┐
                 ├─ Argon2id (m=128 MiB, t=3, p=1, salt=random 16 B per account)
secret key (optional per user, 128-bit, in Emergency Kit) ─ HKDF ─ XOR ─► Account Unlock Key (AUK)
AUK ─► decrypts Account Key (random 256-bit)
Account Key ─► decrypts X25519 keypair (sharing) + Ed25519 keypair (signing)
Vault Key (random 256-bit per vault) ─ wrapped by Account Key, or sealed to each member's X25519 key
Item Key (random 256-bit per item) ─ wrapped by Vault Key ─► encrypts item JSON
```
- Secret Key is **off by default**. Users turn it on in settings, and admins can require it via policy. Enabling it re-wraps the Account Key under a new AUK; no vault data is re-encrypted.
- Cipher: **XChaCha20-Poly1305** everywhere. No unauthenticated modes, no legacy fallbacks.
- AEAD associated data binds `{format_version, item_id, vault_id}`, so ciphertexts cannot be swapped between items or fields.
- The whole item (name, URLs, username, password, TOTP, passkeys, notes, fields) is one encrypted blob. Plaintext on the server is limited to IDs, type, timestamps, and sizes.
- Item JSON carries a `format` number (`ITEM_FORMAT` in `crates/core/src/item.rs`). Clients upgrade older items when they decrypt them and stamp the current format when they encrypt. The server can't read items, so schema changes never need a server migration. Format 2 (0.2.1): a website's URL match `default` follows the client's "Default URI match detection" setting; older items, saved when `domain` was the implicit default, read as `default`.
- KDF parameters are authenticated: clients enforce minimums and refuse to log in with weaker parameters than they already know.

### Authentication: OPAQUE (`opaque-ke`)
- The server never receives the password or a hash it could crack offline.
- OPAQUE's export key and the Secret Key together derive the AUK, so login and decryption keys stay independent.
- Sessions: access JWT (15 min) plus a **rotating** refresh token bound to the device, with reuse detection that revokes the device.
- 2FA: TOTP, email OTP, WebAuthn security keys, recovery codes. New-device login sends an email alert.

### Sharing (organizations)
- Vault keys are sealed to members' X25519 public keys.
- Public keys are shown as fingerprints for out-of-band verification, so a malicious server cannot silently substitute keys.
- Removing a member rotates the vault key, and items are re-encrypted lazily.

## Features (stage 1: server + extension)
- Item types: Login (multiple URLs, TOTP, passkeys), Secure Note, Card, Identity, SSH Key. Plus custom fields, folders, favorites, trash, password history, attachments.
- Password and passphrase generator; breach check via HIBP k-anonymity, run from the client only.
- **Import** (client-side only; plaintext never reaches the server): export files from other password managers (JSON, password-protected JSON, CSV, `.1pux`, KDBX). Formats and field mappings: `docs/IMPORT_FORMATS.md`. **Export**: encrypted PassAuth JSON plus plaintext JSON/CSV.
- SMTP: verification, invites, new-device alerts, email 2FA, recovery, admin test mail.
- Admin panel: off by default, Argon2-hashed token, no shell or executable-path settings.
- Real-time sync over WebSocket (`/api/ws`), plus a revision-date check for cheap polling.
- Website icons: `GET /api/icons/{host}` (unauthenticated, used as `<img src>`; clients fall back to a letter avatar on error). The server fetches the site's `<link rel=icon>` or `/favicon.ico` defensively: public DNS names only, every resolved IP must be public and the connection is pinned to it, redirects re-validated (max 3), ports 80/443, 5 s budget, 100 KiB cap, only PNG/ICO/GIF/JPEG/WebP by magic bytes (never SVG/HTML), `CSP: default-src 'none'`. Hits cached 7 days, misses 1 day (`ICON_CACHE_DIR`, default `icons/` beside the SQLite file). Uncached fetches are rate-limited per client IP (60/min) and capped at 8 concurrent. `ICON_SERVICE=off` disables it. Privacy: the server learns which sites' icons are requested (not which user, not vault contents); turn it off if that matters.
- Extension: login to any PassAuth server URL; autofill only on user action, in the top-level same-origin frame; inline save prompts; TOTP codes; acts as a WebAuthn **passkey provider** (ES256 keys stored inside the encrypted item, with fallback to browser or hardware keys).

## Deployment
- One container image `ghcr.io/fahed-alhammadi/passauth`, tagged `X.Y.Z`, `X.Y`, and `latest`, with multi-arch builds (amd64, arm64).
- `docker compose up` gives the server, with SQLite in `/data` by default and PostgreSQL optional via `DATABASE_URL`.
- Config via env or `*_FILE` secrets. See `.env.example`.

## CI/CD (GitHub Actions)
- `ci.yml`: fmt, clippy, tests, `cargo audit`, web and extension build and tests on every PR.
- `release.yml`: on tag `vX.Y.Z`, build and push the multi-arch image to GHCR, and attach the extension zip to the release.
- Stage 2: `ios.yml` (fastlane to App Store Connect / TestFlight) and `android.yml` (fastlane to Play Console internal track).
