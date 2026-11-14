# Changelog

Changes to the PassAuth server and web vault, newest first. Each version is published as the Docker image `ghcr.io/fahed-alhammadi/passauth:X.Y.Z`, and `:latest` always points to the newest one. Update with `docker compose pull && docker compose up -d`.

The desktop app has its own releases on GitHub; the browser extension and the mobile apps show their changes in their stores.

<!-- scripts/release.sh server X.Y.Z adds each new version below this line. -->

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
