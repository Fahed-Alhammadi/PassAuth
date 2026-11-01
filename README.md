# PassAuth

Self-hosted, zero-knowledge password manager: a server in one small container, a web vault, a Chrome extension, and native iOS/Android apps (coming next).

Everything is encrypted on your devices before it reaches the server. That includes item names and URLs, not just passwords. The server never sees your master password, not even as a hash: sign-in uses the OPAQUE protocol.

## Run the server

```bash
cp .env.example .env            # set DOMAIN, SMTP, ADMIN_TOKEN …
mkdir -p data && sudo chown 1000:1000 data
docker compose up -d
```

Open `http://localhost:8080`.

- **No root.** The container runs as uid/gid `1000` by default. Set `PUID` and `PGID` in `.env` to change that, and make sure `./data` is owned by the same uid/gid.
- **Images.** Images are published to `ghcr.io/fahed-alhammadi/passauth` with three tags: the exact version (`1.2.3`), the minor series (`1.2`) and `latest`.
- **Admin token.** Generate one with `docker run --rm -it ghcr.io/fahed-alhammadi/passauth hash-admin-token`.

## Security design

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). In short:

- **Key derivation.** Argon2id derives your keys from the master password, with an optional 128-bit Secret Key mixed in.
- **Encryption.** XChaCha20-Poly1305 with a separate key for every item. Each ciphertext is bound to its location, so it can't be swapped into another item or vault.
- **Sharing.** X25519 sealed boxes, with key fingerprints you can compare in person.
- **Sessions.** OPAQUE sign-in, refresh tokens that rotate and detect reuse, and 2FA by TOTP, email code or recovery code.

## Develop

```bash
cargo test --workspace          # core crypto + server API tests
cargo run -p passauth-server    # needs DATABASE_URL=sqlite://./data/passauth.db?mode=rwc
```

## Import

PassAuth imports from Bitwarden / Vaultwarden (JSON or CSV, including password-protected exports), 1Password (`.1pux`, CSV) and Passbolt (CSV, KDBX). Imports run entirely in your browser.
