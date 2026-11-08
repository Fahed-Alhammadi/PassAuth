# Changelog

Changes to the PassAuth server and web vault, newest first. Each version is published as the Docker image `ghcr.io/fahed-alhammadi/passauth:X.Y.Z`, and `:latest` always points to the newest one. Update with `docker compose pull && docker compose up -d`.

The browser extension and the mobile apps show their changes in their stores.

<!-- scripts/release.sh server X.Y.Z adds each new version below this line. -->

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
