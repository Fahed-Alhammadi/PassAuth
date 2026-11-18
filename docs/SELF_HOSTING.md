# Self-hosting PassAuth

This guide sets up a PassAuth server with Docker Compose: the server, the web vault and the admin page in one container. For what PassAuth is and which apps connect to it, see the [README](../README.md).

- [Install](#install)
- [HTTPS](#https)
- [Update](#update) (and [moving to the short files](#move-to-the-short-files))
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

`.env` holds only what you have to decide:

```env
PUID=1000
PGID=1000
PASSAUTH_ADMIN_USERNAME=admin
PASSAUTH_ADMIN_PASSWORD=change-me-to-a-long-password
```

| Setting | What to put |
|---|---|
| `PUID` / `PGID` | The user and group PassAuth runs as and that owns `./data`. Use your own: the output of `id -u` and `id -g`. |
| `PASSAUTH_ADMIN_USERNAME` | The user name for the admin page. |
| `PASSAUTH_ADMIN_PASSWORD` | The password for the admin page, at least 12 characters, for example from `openssl rand -base64 24`. Until you change the example value the admin page stays off. If it contains `$`, put the whole value in single quotes. |

Below them, `.env.example` lists the optional settings, commented out. Remove the `#` from the ones you need:

- `DOMAIN`: the address people open, without a trailing slash, e.g. `https://vault.example.com`. Needed for links in emails and for security keys in two-step login, so behind a reverse proxy it must be the public `https://` address. Without it the server assumes `http://localhost:8080`.
- `DATABASE_URL`, `IP_HEADER`, `TRUSTED_PROXIES`: see [HTTPS](#https) and the [configuration reference](#configuration-reference).

`.env` holds a password: make it readable only by you with `chmod 600 .env`.

### 3. Check `docker-compose.yml`

You normally change nothing. The lines you might edit have a comment:

- `ports`: `"8080:8080"` publishes PassAuth on port 8080. Behind a reverse proxy on the same machine, use `"127.0.0.1:8080:8080"` (see [HTTPS](#https)).
- `volumes`: `./data` is where PassAuth keeps its database and website icons.

PassAuth starts as root only to create `./data` and give it to `PUID:PGID`, then switches to that user with no Linux capabilities left. `cap_add: [CHOWN, SETUID, SETGID]` is what it needs for that one step; the rest of the file keeps the container locked down (read-only, no new privileges).

### 4. Start PassAuth

```bash
docker compose up -d
docker compose logs -f passauth      # "PassAuth server listening" means it's ready
```

Open your `DOMAIN` (or `http://localhost:8080`) and create your account.

### 5. Admin page

Open `/admin` on your server (e.g. `https://vault.example.com/admin`) and sign in with `PASSAUTH_ADMIN_USERNAME` and `PASSAUTH_ADMIN_PASSWORD`. This sign-in is only for the admin page: it is not a vault account and can't open anyone's vault. There you can:

- manage users and send invitations,
- open or close sign-ups, or limit them to email domains,
- set up email delivery and send a test email,
- choose whether new accounts must confirm their email, whether the server fetches website icons, and how much it logs,
- empty the trash automatically after 30, 60 or 90 days (off by default: deleted items stay in the trash until someone empties it). In vaults that keep a record of their changes (every vault once the apps of all members who can edit it are up to date) the apps do this, not the server, so old trash stays until someone who can edit the vault opens it in an app; an app never empties sooner than 7 days after it first saw an item in the trash, whatever is set here,
- set limits: how long a sign-in lasts and how long a device may stay offline or skip two-step login, sign-in and two-step attempt limits, the largest item and import, an item or storage quota per user (off by default), live-sync connection checks, and how long deletions are kept for apps that sync only changes,
- see the server's activity log (sign-ins and failed attempts, admin actions, vault, sharing and item changes; ids only, never vault contents), kept 365 days by default (30 days to 10 years), and choose whether it records IP addresses (on by default; turning it off also erases the ones kept),
- keep earlier versions of items so users can restore them (10 per item by default, up to 100; 0 turns history off). Versions count toward storage quotas,
- let users share text through encrypted links that expire (Send, on by default): choose the longest time before a Send is deleted (30 days by default, up to 365); turning it off stops every link at once; Sends count toward storage quotas. The key is in the part of the link after `#`, which never reaches the server; a reverse proxy's access log sees only `/send/<id>`,
- set account policies: require two-step login (accounts without it can only set it up), require a Secret Key for new accounts and password changes, minimum key-derivation memory and passes, minimum master password length, the longest vault timeout the apps offer, and hiding vault export in the apps. Existing accounts can still sign in; the apps ask them to update,
- allow file attachments (on by default) and set the largest file (100 MB by default, up to 4096 MB) and the attachment storage per user (1 GB by default, 0 = no limit); set a per-user storage limit to cap disk use,
- keep a free-disk reserve (1024 MB by default, 0 = off): below it nothing new is stored, but sign-in, sync and deleting keep working, so you can free space safely. The overview shows the free space,
- allow emergency access (on by default): users can let a trusted contact on this server request view-only access to their personal vaults after a waiting period they choose (1–90 days). Confirming a contact gives them a key to those vaults only (not shared vaults, not Sends); removing a contact changes the keys of those vaults. The waiting period is enforced by the server, not by encryption, and an approved contact keeps what they had. Contacts confirmed before the server moved to these keys (database migration 13) have to be confirmed again; the apps say so. If emergency contacts were confirmed on 0.10.0 or earlier, backups made before the upgrade still hold the account keys sealed to them: delete those backups. The upgrade erases the keys from the database (on SQLite it also rebuilds the file once, with `VACUUM`, which needs free disk space about twice the size of the database plus the free-disk reserve; until there is enough, the log warns at each start and the rebuild waits); PostgreSQL keeps old row versions until it vacuums, so run `VACUUM` once on the PassAuth database after upgrading,
- turn the password breach check on or off (on by default: the web vault sends Have I Been Pwned only the first 5 characters of a password's hash, and only when the user asks; the server isn't involved).

These settings are saved in the database and take effect at once, without a restart.

**Protect the admin page.** Two extra locks, both recommended:

- **Two-step login:** in **Admin security**, choose **Set up two-step login**, scan the QR code with an authenticator app and enter the code it shows. Save the recovery codes you get. From then on, signing in needs the password and a 6-digit code (or a recovery code). If you lose your phone and your recovery codes, turn it off from the server's terminal:
  ```bash
  docker compose exec passauth passauth-server reset-admin-2fa
  ```
- **Allowed networks:** set `PASSAUTH_ADMIN_ALLOWED_NETWORKS` in `.env` to the networks the admin page may be opened from, e.g. `192.168.1.0/24` for your home network or your VPN's range (several separated by commas), then run `docker compose up -d`. Visitors from anywhere else get "not allowed". Behind a reverse proxy, also set `IP_HEADER` (see [HTTPS](#https)), or every visitor looks like the proxy.

To change the admin password, edit `.env` and run `docker compose up -d`; anyone signed in to the admin page is signed out. To turn the admin page off, remove both admin lines from `.env` and run `docker compose up -d`.

If someone loses every two-step method (phone, email access and recovery codes), use **Reset two-step login** next to their account on the admin page. It turns off all their two-step methods so they can sign in with their master password (and Secret Key) and set them up again, and emails them about it. Only do this once you're sure the request really comes from them.

### 6. Email (optional, recommended)

With email set up, PassAuth sends sign-up verification, new-device alerts, two-step codes by email and invitations. On the admin page, open **Email delivery** and enter your mail provider's SMTP server, encryption, port, user name, password and the address to send from. Save, then check it with **Send test email**.

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
- nginx and file attachments: nginx accepts only 1 MB request bodies by default. Set `client_max_body_size` to at least the admin page's largest file (100m by default) and preferably `proxy_request_buffering off;`, or uploads of larger files fail.

PassAuth believes that header only from proxies on the same machine or a private network (loopback, `10.x`, `172.16–31.x`, `192.168.x`, IPv6 ULA). If your proxy connects from another address, list it in `TRUSTED_PROXIES`.

When the proxy runs on the same host, publish PassAuth on loopback only so nobody can reach it around the proxy (Docker's published ports bypass host firewalls): in `docker-compose.yml`, change the port line to `"127.0.0.1:8080:8080"`.

## Update

```bash
docker compose pull
docker compose up -d
```

The image line ends in `:latest`, so this always brings you to the newest release. To stay on one version, write it instead, e.g. `ghcr.io/fahed-alhammadi/passauth:0.7.0`. Database changes are applied automatically when the new version starts.

Going back to an older version doesn't work once a newer one has upgraded the database: the older server refuses to start and says why. Start the newer version again, or restore the backup you made before upgrading.

### Move to the short files

Servers installed before version 0.8 have a longer `docker-compose.yml` with `${...}` variables and an `.env` with an `ADMIN_TOKEN` hash. They keep working as they are: `docker compose pull && docker compose up -d` runs the new version, and the admin page still asks for your admin token.

To switch to the short files (nothing is lost; your data in `./data` stays as it is):

1. Back up `./data` (see [Back up](#back-up)).
2. Replace `docker-compose.yml` with the [new one](../docker-compose.yml). If your old `.env` had `PASSAUTH_PORT=127.0.0.1:8080`, use `"127.0.0.1:8080:8080"` on the port line. If you pinned `PASSAUTH_VERSION`, write that version in the `image:` line.
3. Rewrite `.env` in the [new shape](../.env.example): keep your `PUID`, `PGID` and any of `DOMAIN`, `DATABASE_URL`, `IP_HEADER`, `TRUSTED_PROXIES` you set. Set `PASSAUTH_ADMIN_USERNAME` and `PASSAUTH_ADMIN_PASSWORD`, or keep your `ADMIN_TOKEN` line for now (it is ignored once an admin password is set).
4. Run `docker compose up -d`.

Your `SIGNUPS_*`, `SMTP_*`, `ICON_SERVICE` and `LOG_LEVEL` values are still read as starting values while they are in `.env`. Once you have saved the same settings on the admin page, you can delete those lines.

## Back up

All data is in `./data`. To back up the SQLite database while PassAuth keeps running:

```bash
docker compose exec passauth passauth-server backup /data/passauth-backup-$(date +%F).db
```

This writes a consistent copy into `./data` and never overwrites a file, plus a `passauth-backup-….db.attachments/` folder with the attachment files. Only the PUID user can read the copy. It holds the server's sign-in key and every account's encrypted vault, so store it as carefully as the server itself. With PostgreSQL, use `pg_dump` first, then copy the attachments folder (`/data/attachments` or `ATTACHMENTS_DIR`); files deleted between the two steps will be missing, extra ones are swept after a restore.

Or stop the container (`docker compose stop`), copy the `data` folder, and start it again.

To restore: stop the container, replace `data/passauth.db` with the backup and `data/attachments` with its `.attachments` folder (delete any `passauth.db-wal` and `passauth.db-shm` next to it), and start it again. After a restore from a `backup` copy, every app downloads its vaults in full once. After restoring a backup made any other way (a copied `data` folder, `pg_dump`), run this once before starting PassAuth, so apps don't trust what they synced after the backup was made:

```bash
docker compose run --rm passauth reset-sync
```

After any restore, apps that had synced something newer than the backup show a warning on the vaults concerned ("Your server's copy of this vault doesn't match its record of changes."). That is the check working: the server now holds an older state than those devices saw. Each user confirms "Use the server's copy" once on each device (every member can, also with view-only access; nothing is sent to the server for it). Tell your users before you restore.

### Vaults that don't start keeping a record of changes

A vault starts its record of changes (which lets the apps notice a missing, restored or outdated item) only when every signed-in app of every member who can edit it is recent enough: web vault 0.15.0, desktop app 0.13.0, browser extension 0.12.0, iOS and Android 0.12.0. Until then the vault works as before, without the record. One old device that is still signed in, of any member who can edit the vault, holds this off, and nobody is shown which device or whose it is: not the vault's owner, and not you on the admin page. Ask the vault's members to update their apps and to sign out devices they no longer use (Settings → Signed-in devices → Sign out, or "Sign out all other devices"). Sign-ins that have run out don't count; members with view-only access don't count either.

### Run one instance

PassAuth keeps some state in the server process: sign-ins in progress (password and two-step steps, re-authentication, security-key challenges), rate limits, live-sync connections, admin page sessions and the admin settings it applies. Run exactly one PassAuth container per database. Several instances behind a load balancer would break sign-ins that land on another instance, multiply the rate limits, and miss live-sync messages from the other instance. A restart is harmless: sign-ins in progress start again, the admin page asks you to sign in again, and rate-limit counters reset.

## Configuration reference

`.env` settings. Any secret can be read from a file instead by adding `_FILE` to its name, e.g. `PASSAUTH_ADMIN_PASSWORD_FILE=/run/secrets/admin`.

| Setting | Default | Meaning |
|---|---|---|
| `PUID` / `PGID` | `1000` | User and group PassAuth runs as; `./data` is given to them at start. |
| `PASSAUTH_ADMIN_USERNAME` | `admin` | User name for the admin page. |
| `PASSAUTH_ADMIN_PASSWORD` | off | Password for the admin page (at least 12 characters, not the example). Without it the admin page is off. |
| `PASSAUTH_ADMIN_ALLOWED_NETWORKS` | anywhere | Networks the admin page may be opened from, as IPs or CIDRs, e.g. `192.168.1.0/24,10.8.0.0/24`. |
| `DOMAIN` | `http://localhost:8080` | Public address of the server, e.g. `https://vault.example.com`. Also the origin security keys / passkeys are bound to: if it isn't the exact address people open in their browser, two-step login with a security key can't be set up (the server logs a warning and the setting is greyed out in the web vault). |
| `DATABASE_URL` | SQLite in `/data` | `postgres://user:pass@host:5432/db` to use PostgreSQL. |
| `ATTACHMENTS_DIR` | beside the database | Folder for attachment files. With PostgreSQL the default is `/data/attachments`, so keep the `./data:/data` volume or set this; without either, attachments are off. |
| `DATABASE_MAX_CONNECTIONS` | `10` | Database connections the server keeps open (1–1000). |
| `IP_HEADER` | none | Header with the visitor's address when behind a proxy. |
| `TRUSTED_PROXIES` | loopback + private networks | Proxies whose `IP_HEADER` is believed, as IPs or CIDRs, e.g. `10.0.0.5,fd00::/8`. |
| `LOG_FORMAT` | text | `json` for structured logs. |

Set on the admin page (saved in the database, no restart). The `.env` names still work and only set the starting value:

| Admin page | Old `.env` setting |
|---|---|
| Sign-ups: open, closed or limited to email domains | `SIGNUPS_ALLOWED`, `SIGNUPS_DOMAINS_WHITELIST` |
| New accounts must confirm their email address | `SIGNUPS_VERIFY` (default: on when email is set up) |
| Show website icons | `ICON_SERVICE` (`internal` or `off`), `ICON_CACHE_DIR` |
| Server log | `LOG_LEVEL` |
| Email delivery | `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_FROM_NAME` |
| Admin sign-in | `ADMIN_TOKEN` (an Argon2 hash from `passauth-server hash-admin-token`; used only when `PASSAUTH_ADMIN_PASSWORD` is not set) |

Limits and quotas (sign-in length, attempt limits, item and import size, per-user quotas, trash and deletion history, live-sync checks, activity log and item history, Send and account policies) exist only on the admin page.
