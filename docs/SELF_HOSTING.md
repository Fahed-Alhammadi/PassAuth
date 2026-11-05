# Self-hosting PassAuth

This guide sets up a PassAuth server with Docker Compose: the server, the web vault and the admin page in one container. For what PassAuth is and which apps connect to it, see the [README](../README.md).

- [Install](#install)
- [HTTPS](#https)
- [Update](#update)
- [Back up](#back-up)
- [Configuration reference](#configuration-reference)

## Install

You need a Linux or macOS machine with **Docker** and **Docker Compose**. To use PassAuth from other devices you also need a domain name and HTTPS (see [HTTPS](#https)).

### 1. Get the files

Clone the repository, or copy `docker-compose.yml` and `.env.example` into an empty folder. The container image is public at `ghcr.io/fahed-alhammadi/passauth`:

```bash
git clone https://github.com/Fahed-Alhammadi/PassAuth.git passauth
cd passauth
cp .env.example .env
```

### 2. Edit `.env`

Open `.env` in a text editor and set at least:

| Setting | What to put |
|---|---|
| `DOMAIN` | The address people will open, without a trailing slash, e.g. `https://vault.example.com` (or `http://localhost:8080` to try it on this computer). Used in email links. |
| `PASSAUTH_VERSION` | `latest` to always run the newest release, or a version such as `0.3.2` to stay on it. |
| `PUID` / `PGID` | The user and group the container runs as (default `1000`). The container never runs as root. |
| `PASSAUTH_PORT` | Port on this machine (default `8080`). |

### 3. Create the data folder

Everything PassAuth stores (the database and cached website icons) goes into `./data`, which must belong to the `PUID:PGID` user:

```bash
mkdir -p data
sudo chown 1000:1000 data        # use your PUID:PGID if you changed them
```

On macOS you can instead set `PUID` and `PGID` in `.env` to the output of `id -u` and `id -g`, and skip `chown`.

### 4. Create an admin token

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

### 5. Email (optional, recommended)

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

### 6. Start PassAuth

```bash
docker compose up -d
docker compose logs -f passauth      # "PassAuth server listening" means it's ready
```

Open your `DOMAIN` (or `http://localhost:8080`) and create your account. Then open `/admin`, sign in with your admin token, and turn off **Allow new accounts to sign up** if only people you invite should join.

## HTTPS

Put PassAuth behind a reverse proxy that handles HTTPS and forwards to port 8080, including WebSocket connections to `/api/ws`. With [Caddy](https://caddyserver.com), which gets certificates automatically, the whole configuration is:

```
vault.example.com {
    reverse_proxy localhost:8080
}
```

Tell PassAuth which header carries each visitor's real address, so rate limits work per visitor:

- Caddy: `IP_HEADER=X-Forwarded-For`
- nginx: add `proxy_set_header X-Real-IP $remote_addr;` and set `IP_HEADER=X-Real-IP`

PassAuth believes that header only from proxies on the same machine or a private network (loopback, `10.x`, `172.16–31.x`, `192.168.x`, IPv6 ULA). If your proxy connects from another address, list it in `TRUSTED_PROXIES`.

When the proxy runs on the same host, publish PassAuth on loopback only so nobody can reach it around the proxy (Docker's published ports bypass host firewalls): set `PASSAUTH_PORT=127.0.0.1:8080` in `.env`.

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
| `ADMIN_TOKEN` | off | Hash of the admin token (see step 4). |
| `SIGNUPS_ALLOWED` | `true` | Starting value for open sign-ups; the admin page can change it. |
| `SIGNUPS_DOMAINS_WHITELIST` | any | Only these email domains may sign up, e.g. `example.com,example.org`. |
| `SIGNUPS_VERIFY` | on when email is set up | Require email verification before the first sign-in. |
| `IP_HEADER` | none | Header with the visitor's address when behind a proxy. |
| `TRUSTED_PROXIES` | loopback + private networks | Proxies whose `IP_HEADER` is believed, as IPs or CIDRs, e.g. `10.0.0.5,fd00::/8`. |
| `ICON_SERVICE` | `internal` | `off` stops the server fetching website icons. |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / text | Logging detail; `json` for structured logs. |
| `SMTP_*` | off | Email delivery (see step 5). |
