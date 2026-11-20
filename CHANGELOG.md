# Changelog

Changes to the PassAuth server and web vault, newest first. Each version is published as the Docker image `ghcr.io/fahed-alhammadi/passauth:X.Y.Z`, and `:latest` always points to the newest one. Update with `docker compose pull && docker compose up -d`.

The desktop app has its own releases on GitHub; the browser extension and the mobile apps show their changes in their stores.

<!-- scripts/release.sh server X.Y.Z adds each new version below this line. -->

## 0.17.0 (2026-11-20)

- Sign-in request push notifications (iOS first) via a push relay (d7f41de)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.16.1...server-0.17.0)

## 0.16.1 (2026-11-19)

- Server: an approved device sign-in skips two-step login (e844c9a)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.16.0...server-0.16.1)

## 0.16.0 (2026-11-19)

- Web + desktop: two-step key page and desktop hand-off (7fd1afa)
- Server: security-key key page for apps, sign-in context endpoint; WASM byte params only Uint8Array (b096101)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.15.0...server-0.16.0)

## 0.15.0 (2026-11-19)

- Last fixes before release: owners can delete newer-version items, longer log catch-up, sealed picture at rest in the extension (bab9a6b)
- Security review round 3: warnings kept with the copy, honest handling of unopenable items, root sign-in (262dede)
- Security review round 2: every warning has a way out, verified copy never replaced (ee5e8bc)
- Security review round 1: manifest hash chain and client hardening (106ac72)
- Apps: verify and keep vault manifests; require signed sharing on the server (1e1379a)
- Vault manifests: authenticated record of each vault's item set (core, server) (0b835c3)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.14.0...server-0.15.0)

## 0.14.0 (2026-11-18)

- Apps: bound wraps, Send v2 and item rollback warnings (260e0ac)
- Security: epoch-bound account wraps, password-keyed Sends, item edit counter (24282f5)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.13.1...server-0.14.0)

## 0.13.1 (2026-11-18)

- Server: allow blob: images in the web vault CSP (profile pictures) (2cfc7ae)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.13.0...server-0.13.1)

## 0.13.0 (2026-11-18)

- Apps: profile pictures and a globe tile when website icons are off (107d7ea)
- Profile pictures: sealed avatar in core, server storage and sync version (84c5010)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.12.1...server-0.13.0)

## 0.12.1 (2026-11-17)

- Web vault: reorganize Settings and the admin page into sections (8c73bd9)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.12.0...server-0.12.1)

## 0.12.0 (2026-11-16)

- Apps: adopt core round 5 — authenticated session restore, last-known pin merges, safe declines, unsent pins kept (fa84a4b)
- Core, server: pinned rosters always carry their hash, first signatures need consent, no merge across own identities (20c162d)
- Apps: accept what was shown, never offer Decline for unsigned vaults, tombstone only confirmed removals (a30a2ff)
- Core, server: key pins never un-retire a key, re-joins are explicit, keys first signed by an unknown account need consent (ad22a28)
- Web vault, desktop: check and sign shared vaults (1b23e3a)
- Core, server: signed vault sharing (423142f)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.11.0...server-0.12.0)

## 0.11.0 (2026-11-16)

- Web vault, desktop: emergency access with a key per contact, a sealed contact list and new keys on removal (1a2e06d)
- Core, server: emergency contacts get a key to the personal vaults only, and removing one replaces those keys (8545515)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.10.0...server-0.11.0)

## 0.10.0 (2026-11-16)

- Web vault, desktop: Send, attachments, emergency access, sign-in approval, password health, invitations, activity log and item history (1fcef6b)
- Server: delta sync, vault invitations, activity log, item history, Send, attachments, emergency access, sign-in approval, policies and limits on the admin page (ce04bb0)
- Core: crypto for Send, attachments, emergency access and sign-in from another device; site matching with the full Public Suffix List (25e9189)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.9.0...server-0.10.0)

## 0.9.0 (2026-11-14)

- Server: two-step login and allowed networks for the admin page (2c7ddc8)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.8.0...server-0.9.0)

## 0.8.0 (2026-11-14)

- Server: short docker-compose.yml + .env, admin sign-in with user name and password, settings on the admin page (d7feb17)
- Bump vite from 8.3.5 to 8.3.6 in /web (f897e0c)
- Bump zip from 9.2.2 to 9.4.2 (1ad2298)
- Bump uuid from 1.29.0 to 1.29.1 (5c92062)
- Bump node from `bc0a2af` to `add5c17` (f1c18b0)
- Bump rust from `ed2c95c` to `f2c004e` (98b4a79)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.7.0...server-0.8.0)

## 0.7.0 (2026-11-10)

- Web vault and desktop: redesigned dialogs, sign-in and settings; changing the master password keeps this device signed in (f4526f7)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.6.4...server-0.7.0)

## 0.6.4 (2026-11-10)

- Admin 2FA reset, remove member with key change in one step, doc fixes (6b89ffa)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.6.3...server-0.6.4)

## 0.6.3 (2026-11-10)

- Delete saved passkeys and two-step security keys in every app (095d97f)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.6.2...server-0.6.3)

## 0.6.2 (2026-11-10)

- server: bundle SQLite 3.54.1 (fixes RUSTSEC-2026-0459) (f8843d6)
- ci: ignore RUSTSEC-2026-0459 until sqlx allows libsqlite3-sys 0.39 (10e82ad)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.6.1...server-0.6.2)

## 0.6.1 (2026-11-09)

- Fill and save logins on the PassAuth web vault like on any site (bd361b2)
- Review round: AutoFill efficiency, desktop resource use, docs (1144623)
- Desktop: AutoFill host entitlement, start at login, Dock, background sync; Android background sync (93568c6)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.6.0...server-0.6.1)

## 0.6.0 (2026-11-08)

- Security keys as a two-step method; desktop vault timeout (daab5bd)
- Desktop: macOS AutoFill extension + verification-code links (47687d8)
- Bump zip from 9.2.1 to 9.2.2 (170e701)
- Bump aes from 0.9.3 to 0.9.4 (a89191e)
- Bump @vitejs/plugin-react from 6.1.2 to 6.2.1 in /web (64b14e1)
- Desktop app for macOS, Windows and Linux (Tauri 2) (f787a6d)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-0.5.1...server-0.6.0)

## 0.5.1 (2026-11-05)

- Node 26: install pnpm with npm in the image, build CI on Node 26 (1d9faf7)
- Bump node from 24-bookworm-slim to 26-bookworm-slim (9b4f54c)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-v0.5.0...server-0.5.1)

## 0.5.0 (2026-11-04)

- Web vault and website: review fixes, accessibility and phone layout (267f41d)
- Server and core: review fixes for sharing, concurrency and hardening (e79d195)

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/server-v0.4.5...server-v0.5.0)

## 0.4.5 (2026-11-03)

- Maintenance release.

[All changes](https://github.com/Fahed-Alhammadi/PassAuth/compare/v0.4.3...server-v0.4.5)
