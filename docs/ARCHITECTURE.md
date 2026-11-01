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
| `crates/core-ffi` | Rust → UniFFI | `core` bindings (Kotlin now, Swift later) for the native apps. |
| `android/` (stage 2) | Kotlin, Jetpack Compose | Android app; see "Android app" below. iOS (Swift) comes later. |

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

## Android app (`android/`)
- Gradle project with two modules. `:core` is an Android library holding the UniFFI bindings (`io.passauth.core`) and `libpassauth_ffi.so` (arm64-v8a, x86_64), both generated by `scripts/build-android-core.sh` and gitignored, plus JNA. `:app` is the app (`io.passauth.app`, minSdk 34, compile/target 36). Crypto only ever comes from the Rust core; items, bundles and KDF params cross as JSON in the server/web shape (`app/.../data/Item.kt` mirrors `web/src/lib/types.ts`).
- Build: `scripts/build-android-core.sh && cd android && ./gradlew :app:assembleDebug :app:testDebugUnitTest` (JVM tests don't load the native library). Release: `./gradlew :app:bundleRelease`, signed only when `ANDROID_UPLOAD_KEYSTORE_PATH`, `ANDROID_UPLOAD_KEYSTORE_PASSWORD`, `ANDROID_UPLOAD_KEY_ALIAS` and `ANDROID_UPLOAD_KEY_PASSWORD` are set. Debug builds use the `io.passauth.app.debug` id.
- Version: `versionName` = root `Cargo.toml` `[workspace.package] version`, `versionCode` = major·1 000 000 + minor·1 000 + patch (`android/buildSrc/src/main/kotlin/AppVersion.kt`, shared with the unit tests).
- Data layer (`app/.../data`): `VaultRepository` mirrors the extension's `background/vault.ts` (prelogin → OPAQUE → 2FA → bundle unlock → `/sync` → decrypt; create/update/trash; lock/logout; up to 5 accounts). `ApiClient` pins each request to one account and rotates refresh tokens on 401. `SecureStore` keeps tokens, settings and per-account data in a DataStore file encrypted with an Android Keystore AES-GCM key, plus an encrypted copy of the last `/sync` response (ciphertext) so the vault opens offline. Unlocked keys live only in memory as Rust handles.
- Unlock: master password (+ stored Secret Key), or biometrics: `Account.toSessionBytes()` (64 bytes) is wrapped by a per-account Keystore key that requires strong biometric auth and is invalidated when biometrics change. Vault timeout and action like the extension (`LockManager`); with "never" the session bytes are kept in the encrypted store.
- Hardening: no backup (`allowBackup=false`, extraction rules exclude everything), https only except `localhost`/`10.0.2.2` (network security config), `FLAG_SECURE` while unlocked or showing the Secret Key, clipboard copies marked sensitive and cleared after the user's delay, no secrets in logs.
- Autofill service (`app/.../autofill`, `PassAuthAutofillService`): `StructureParser` reads the AssistStructure (visible enabled text fields, `webDomain`/`webScheme`, only fields of the focused site's frame); `FieldClassifier` finds username/password/one-time-code fields from autofill hints, input type, HTML attributes and id/hint text (patterns of the extension's `fields.ts`). `FillTarget.resolve` decides what may match: web content in a browser on the privileged allowlist (package + signing cert) or in a WebView whose domain's asset links list the app → by website (`UrlMatcher`, default-match setting; scheme missing → https; Android gives no path, so "exact"/"starts with" see `scheme://domain/`); any other app → logins with the website `androidapp://<package>`; a browser's own UI and PassAuth itself → nothing. Web logins never match apps and vice versa; the extension's https→http downgrade refusal and "never fill/save on the PassAuth web vault" apply. Unlocked: one Dataset per login (drop-down + keyboard inline suggestions via `androidx.autofill`) plus "Open PassAuth". Locked: one "PassAuth is locked" entry whose authentication IntentSender opens `AutofillAuthActivity`, which unlocks (master password or biometrics) and returns the datasets in `EXTRA_AUTHENTICATION_RESULT`. Logins with a TOTP get per-dataset authentication: picking one runs `AutofillAuthActivity` (see-through, no UI when unlocked), which returns the filled Dataset with a fresh code (also filled into a one-time-code field) and copies it when "Copy verification code automatically" is on — the only reliable hook for running code at the moment of selection. Save: `SaveInfo` (password required, username optional, save when the form disappears, "Never" button → never-save list keyed by base domain or `androidapp://<package>`); `onSaveRequest` updates the same site+username login's password (old one kept in password history) or creates a login; locked → returns an IntentSender to unlock first (credentials stay in memory, never in the intent). Respects "Ask to save and update logins". Always the active account.
- Credential Manager provider (`app/.../credentials`, Android 14+, `androidx.credentials`): `PassAuthCredentialService` offers a `CreateEntry` for ES256/platform passkey requests, `PublicKeyCredentialEntry`s for matching passkeys (rpId, allowCredentials or discoverable) and `PasswordCredentialEntry`s (same matching as autofill); locked → an `AuthenticationAction`. `CredentialActivity` does the work after the user picks: origin check (`Origins`): privileged callers' origin from `CallingAppInfo.getOrigin(allowlist)` with `res/raw/privileged_allowlist.json` = Google Password Manager's published list (https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json, linked from the provider guide; Chrome stable/beta/dev/canary, Firefox, Edge, Brave, Samsung, …) and the RP ID checked against the origin like the extension's `effectiveRpId`; apps get `android:apk-key-hash:<b64url sha256(cert)>` and must be listed in `https://<rpId>/.well-known/assetlinks.json` (`delegate_permission/common.get_login_creds`, package + cert fingerprint; https, no redirects, 5 s, 256 KiB, cached 1 h; `include` not followed) or the request is refused. User verification: unlocking in the flow counts, otherwise BiometricPrompt (biometric or screen lock). excludeCredentials is checked after consent (InvalidStateError). Keys and signatures come from the core (`passkeyCreate`/`passkeyAssert`); clientDataJSON is built with `passkeyClientDataJson` for apps (and hashed), while browsers' `clientDataHash` is signed as given and the built JSON is only the placeholder the guide asks for. Responses are WebAuthn JSON; passkeys are stored like the extension's `storePasskey` (same fields, counter 0, discoverable), on the same site+username login or a new login for `https://<rpId>`.
- Settings → Autofill shows whether PassAuth is the autofill service and the passkey provider, with buttons to Android's settings, plus default URI match, TOTP copy, clipboard clearing, "Ask to save and update logins" and the never-save list. Debug-only test hooks (gradle properties, never in release builds): `passauth.testAssetLinksBase` (asset links from a local server) and `passauth.testPrivilegedApp` (trust one more browser, e.g. a Chromium snapshot). `:samples:login` is a debug-only test app (login form + Credential Manager calls), not part of the app or its bundle.
- Account deletion (Google Play requirement): Settings → About → Delete account. The master password is proven to the server with an OPAQUE login with `purpose: "reauth"` on the signed-in session (like the web vault's `reauth`), then `DELETE /api/account` with `x-reauth-token`; the account is then forgotten locally like Log out (biometric key, offline copy, stored Secret Key and two-step remember token removed; the last account keeps only the server address).
- Item editor TOTP field: type, "Paste" (clipboard) or "Scan QR code" (CameraX preview + ImageAnalysis, latest frame only, decoded in memory by ZXing core; no Play services; frames are never stored and the luminance buffer is wiped on close; the preview is a TextureView inside a dialog that inherits FLAG_SECURE). The `CAMERA` permission is requested only on tap; denial shows how to type or paste the key and a link to Android settings. `otpauth://totp/…` URIs are stored whole (scheme lower-cased for the core), plain base32 keys cleaned (upper case, no spaces); `OtpAuth` mirrors the core's TOTP checks so accepted keys always produce codes. HOTP and `otpauth-migration://` are refused with an explanation.
- Item page: "Password history" (count) opens the previous passwords (`password_history`, newest first, masked with reveal and copy). The overflow menu moves an item to another vault where the user is owner, admin or writer: re-encrypted with the target vault key under the same id and `PUT /api/items/{id}` with the new `vault_id` and the old revision (the web vault's `updateItem(entry, item, vaultId)`).
- Live sync (`LiveSync`): while MainActivity is started and the active account is unlocked, a WebSocket to `/api/ws?access_token=…` (OkHttp, 25 s pings). `{"type":"sync","revision":N}` with N above the shown revision re-syncs; `{"type":"logout"}` makes the app check its session (an ended one signs the account out through the refresh-token path). Disconnects on background, lock or account switch; reconnects with backoff (1 s doubling to 60 s, jitter), each time first calling `/sync/revision` so an expired access token is refreshed and missed changes are caught up. The item editor keeps the item as it was when editing started, so a live update during editing surfaces as the usual revision conflict instead of being overwritten.
- Export: Settings → Vault options → Export vault. Formats come from the core (`exportVaultEncrypted` (≥10-character export password, Argon2id), `exportVaultJson`, `exportVaultCsv` (logins and notes only)), with warnings for the unencrypted ones. The master password is checked locally against the bundle first; the file is written only to the location the user picks with `ACTION_CREATE_DOCUMENT` (`passauth-export-YYYY-MM-DD[-protected].json` / `.csv`).
- Web vault shortcuts open the account's server in the browser with path routes: Security → `/settings/two-step`, `/settings/security`; Vault options → `/settings/vaults`, `/import`, `/vault`.
- Accessibility: icon buttons have content descriptions, card titles and page titles are headings, label + value rows are read as one node before their actions, masked secrets read as "hidden", text drawn inside fixed shapes (avatar, TOTP ring) doesn't scale with the font, select fields wrap. Checked at font scale 2.0.

## Deployment
- One container image `ghcr.io/fahed-alhammadi/passauth`, tagged `X.Y.Z`, `X.Y`, and `latest`, with multi-arch builds (amd64, arm64).
- `docker compose up` gives the server, with SQLite in `/data` by default and PostgreSQL optional via `DATABASE_URL`.
- Config via env or `*_FILE` secrets. See `.env.example`.

## CI/CD (GitHub Actions)
- `ci.yml`: fmt, clippy, tests, `cargo audit`, web and extension build and tests on every PR.
- `release.yml`: on tag `vX.Y.Z`, build and push the multi-arch image to GHCR, and attach the extension zip to the release.
- Stage 2: `ios.yml` (fastlane to App Store Connect / TestFlight) and `android.yml` (fastlane to Play Console internal track).
