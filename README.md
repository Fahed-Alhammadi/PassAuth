<p align="center"><img src="assets/passauth-logo.svg" alt="PassAuth" width="96"></p>

# PassAuth

PassAuth is a self-hosted password manager. You run the server; your passwords, verification codes, passkeys, cards and notes are encrypted on your own devices before they reach it.

- **Server**: one small container with the web vault built in. SQLite by default, PostgreSQL optional.
- **Web vault**: manage items, share vaults with other people, import from other password managers, two-step login, admin page.
- **Chrome extension**: fills logins and verification codes, saves new logins, works as a passkey provider, supports several accounts.
- **Mobile apps** (iOS and Android): coming next.

The server never sees your master password (sign-in uses the OPAQUE protocol) and stores only encrypted data, including item names and website addresses.

---

## Install the server

You need a Linux or macOS machine with **Docker** and **Docker Compose**. To use PassAuth from other devices you also need a domain name and HTTPS (see [HTTPS](#https)).

### 1. Get the files

Clone the repository, or copy `docker-compose.yml` and `.env.example` into an empty folder:

```bash
git clone https://github.com/Fahed-Alhammadi/PassAuth.git passauth
cd passauth
cp .env.example .env
```

### 2. Sign in to the image registry

The container image is published to GitHub's registry. While the repository is private, Docker needs a token to download it:

1. On GitHub open **Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token** and tick only `read:packages`.
2. Then run:
   ```bash
   echo YOUR_TOKEN | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
   ```

### 3. Edit `.env`

Open `.env` in a text editor and set at least:

| Setting | What to put |
|---|---|
| `DOMAIN` | The address people will open, without a trailing slash, e.g. `https://vault.example.com` (or `http://localhost:8080` to try it on this computer). Used in email links. |
| `PASSAUTH_VERSION` | `latest` to always run the newest release, or a version such as `0.3.2` to stay on it. |
| `PUID` / `PGID` | The user and group the container runs as (default `1000`). The container never runs as root. |
| `PASSAUTH_PORT` | Port on this machine (default `8080`). |

### 4. Create the data folder

Everything PassAuth stores (the database and cached website icons) goes into `./data`, which must belong to the `PUID:PGID` user:

```bash
mkdir -p data
sudo chown 1000:1000 data        # use your PUID:PGID if you changed them
```

On macOS you can instead set `PUID` and `PGID` in `.env` to the output of `id -u` and `id -g`, and skip `chown`.

### 5. Create an admin token

The admin page (`/admin`) is where you manage users, send invitations and close sign-ups. It stays off until you set an admin token. Only a **hash** of the token goes into `.env`; you type the token itself on the admin page.

1. Make up a strong token of at least 16 characters, and keep it somewhere safe:
   ```bash
   openssl rand -base64 32
   ```
2. Hash it. Run this and paste the token when asked:
   ```bash
   docker compose run --rm passauth hash-admin-token
   ```
   It prints a line starting with `$argon2id$`.
3. Add it to `.env`, writing **every `$` as `$$`** (otherwise Docker Compose reads `$` as the start of a variable):
   ```
   ADMIN_TOKEN=$$argon2id$$v=19$$m=19456,t=2,p=1$$...
   ```

Steps 2 and 3 in one command, printing the line already escaped for `.env`:

```bash
printf '%s\n' 'YOUR-TOKEN' | docker compose run --rm -T passauth hash-admin-token 2>/dev/null | sed 's/\$/$$/g'
```

To turn the admin page off again, remove `ADMIN_TOKEN` from `.env` and run `docker compose up -d`.

### 6. Email (optional, recommended)

With email set up, PassAuth sends sign-up verification, new-device alerts, two-step codes by email and invitations. Fill in the `SMTP_*` settings in `.env`:

```
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURITY=starttls        # starttls, force_tls or off
SMTP_USERNAME=passauth@example.com
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=passauth@example.com
```

Check it from the admin page with **Send test email**.

### 7. Start PassAuth

```bash
docker compose up -d
docker compose logs -f passauth      # "PassAuth server listening" means it's ready
```

Open your `DOMAIN` (or `http://localhost:8080`) and create your account. Then open `/admin`, sign in with your admin token, and turn off **Allow new accounts to sign up** if only people you invite should join.

### HTTPS

Put PassAuth behind a reverse proxy that handles HTTPS and forwards to port 8080, including WebSocket connections to `/api/ws`. With [Caddy](https://caddyserver.com), which gets certificates automatically, the whole configuration is:

```
vault.example.com {
    reverse_proxy localhost:8080
}
```

Tell PassAuth which header carries each visitor's real address, so rate limits work per visitor:

- Caddy: `IP_HEADER=X-Forwarded-For`
- nginx: add `proxy_set_header X-Real-IP $remote_addr;` and set `IP_HEADER=X-Real-IP`

---

## Update

```bash
docker compose pull
docker compose up -d
```

With `PASSAUTH_VERSION=latest` this always brings you to the newest release. Database changes are applied automatically when the new version starts.

## Back up

All data is in `./data`. To back up the SQLite database while PassAuth is running:

```bash
sqlite3 data/passauth.db ".backup 'passauth-backup.db'"
```

Or stop the container (`docker compose stop`), copy the `data` folder, and start it again. Vault contents in the backup are encrypted, but keep the backup private anyway.

## Configuration reference

All settings live in `.env`. Any secret can be read from a file instead by adding `_FILE` to its name, e.g. `SMTP_PASSWORD_FILE=/run/secrets/smtp`.

| Setting | Default | Meaning |
|---|---|---|
| `DOMAIN` | (required) | Public address of the server. |
| `PASSAUTH_VERSION` | `latest` | Image version to run. |
| `PASSAUTH_PORT` | `8080` | Port on the host. |
| `PUID` / `PGID` | `1000` | User and group the container runs as. |
| `DATABASE_URL` | SQLite in `/data` | `postgres://user:pass@host:5432/db` to use PostgreSQL. |
| `ADMIN_TOKEN` | off | Hash of the admin token (see step 5). |
| `SIGNUPS_ALLOWED` | `true` | Starting value for open sign-ups; the admin page can change it. |
| `SIGNUPS_DOMAINS_WHITELIST` | any | Only these email domains may sign up, e.g. `example.com,example.org`. |
| `SIGNUPS_VERIFY` | on when email is set up | Require email verification before the first sign-in. |
| `IP_HEADER` | none | Header with the visitor's address when behind a proxy. |
| `ICON_SERVICE` | `internal` | `off` stops the server fetching website icons. |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / text | Logging detail; `json` for structured logs. |
| `SMTP_*` | off | Email delivery (see step 6). |

---

## Chrome extension

1. Download `passauth-extension-vX.Y.Z.zip` from the latest [GitHub release](https://github.com/Fahed-Alhammadi/PassAuth/releases) and unzip it.
2. In Chrome open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked** and choose the unzipped folder.
3. Pin PassAuth, open it, enter your server address and sign in.

The extension needs an `https://` server address; plain `http` is allowed only for `localhost`.

## Import from another password manager

In the web vault open **Import** and choose the export file from your old password manager. JSON (including password-protected), CSV, `.1pux` and KDBX exports are supported. Files are read and encrypted in your browser; nothing unencrypted is sent to the server.

---

## Security design

- **Keys**: Argon2id derives your keys from your master password, optionally mixed with a 128-bit Secret Key that never leaves your devices.
- **Encryption**: every item has its own key and is encrypted with XChaCha20-Poly1305. Each ciphertext is bound to its item and vault, so it can't be moved or swapped.
- **Sign-in**: OPAQUE, so the server can't learn or test your master password. Refresh tokens rotate and detect reuse. Two-step login by authenticator app, email code or recovery code.
- **Sharing**: vault keys are sealed to each member's X25519 key, and fingerprints let you confirm who you share with.
- **Server**: runs as a non-root user on a read-only filesystem with no extra Linux capabilities.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Develop

```bash
cargo test --workspace                       # crypto, importers and server API tests
scripts/build-wasm.sh web/src/wasm && (cd web && pnpm install && pnpm build)
scripts/build-wasm.sh extension/src/wasm && (cd extension && pnpm install && pnpm build)
docker compose up -d --build                 # build and run the image locally
```

Requires Rust (stable, with the `wasm32-unknown-unknown` target), `wasm-bindgen-cli` matching the version in `Cargo.lock`, Node.js 24 and pnpm.

**Releasing:** set `version` in the root `Cargo.toml`, commit, then push a tag:

```bash
git tag v0.3.2 && git push origin v0.3.2
```

GitHub Actions publishes `ghcr.io/fahed-alhammadi/passauth:0.3.2`, moves `:latest` to it, and attaches the extension zip to a GitHub release.

---

## License

PassAuth is released under the [MIT License](LICENSE). © 2026 Fahed Alhammadi

Third-party components keep their own licenses:

- The passphrase word list is the [EFF Large Wordlist](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
- The web vault and extension use the [IBM Plex](https://github.com/IBM/plex) fonts, licensed under the [SIL Open Font License 1.1](https://openfontlicense.org).
- Rust and JavaScript dependencies are under their own licenses (mostly MIT or Apache-2.0); see `Cargo.lock` and the `pnpm-lock.yaml` files.
