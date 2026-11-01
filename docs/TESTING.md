# Testing PassAuth (stage 1: server + Chrome extension)

## 1. Run the server

### Option A: build locally with Docker (Colima)
```bash
colima start                       # if Docker isn't running
cp .env.example .env               # set DOMAIN=http://localhost:8080 for local testing
mkdir -p data
docker compose up -d --build       # builds core -> WASM -> web vault -> server
docker compose logs -f passauth
```

On macOS with Colima, `./data` belongs to your Mac user, not uid 1000. Either set `PUID=$(id -u)` and `PGID=$(id -g)` in `.env`, or run `sudo chown 1000:1000 data`. The server refuses to start, with a clear message, if it can't write to `/data`.

### Option B: use a published image
Push a tag (see "Release" below), then set `PASSAUTH_VERSION=0.1.0` (or `latest`) in `.env` and run `docker compose up -d` without `--build`.

Open http://localhost:8080 and create an account.

## 2. Load the extension

```bash
scripts/build-wasm.sh extension/src/wasm
cd extension && pnpm install && pnpm build
```

1. In Chrome, open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and choose `extension/dist`.
3. Pin PassAuth and open it. Connect to `http://localhost:8080`. Plain http is allowed only for localhost; use an https address for a real server.

## 3. Checklist

### Web vault
- [ ] Register without a Secret Key, and then (in a new private window) with one: the Emergency Kit downloads.
- [ ] Add a login with a website and an authenticator key: the 6-digit code and its countdown ring update every second.
- [ ] Add a note, a card, an identity and an SSH key; edit; favorite; move to trash; restore; delete forever.
- [ ] Import a real export from Bitwarden/Vaultwarden (JSON, CSV, or password-protected JSON), 1Password (.1pux) and Passbolt (CSV or KDBX).
- [ ] Settings → Two-step login: set up an authenticator app, sign out, and sign in with a code. Then try a recovery code.
- [ ] Settings → Security: change the master password; other sessions are signed out.
- [ ] Settings → Vaults & sharing: create a second account, share a vault, compare the fingerprints, remove the member.
- [ ] Leave the tab idle for 15 minutes: the vault locks.
- [ ] `http://localhost:8080/#/admin` with `ADMIN_TOKEN`: users, invites, test email.

### Extension
- [ ] Sign in (with 2FA if enabled). Logins for the current site appear under "For <site>".
- [ ] **Fill** fills the username and password. **Cmd/Ctrl+Shift+L** fills when there's exactly one match.
- [ ] Sign in to a site with a new password: PassAuth offers to save or update it. "Never for this site" works.
- [ ] Passkeys: on https://webauthn.io, register and then authenticate. The confirmation window opens, and the passkey appears on the item in the web vault.
- [ ] "Use another device or security key" hands the request back to Chrome.
- [ ] Lock from the popup; restart Chrome. The extension is locked and asks for the master password.

### SMTP
Set the `SMTP_*` variables in `.env` and restart. Check: the verification email on sign-up, the new-device alert, email two-step codes, invites from the admin panel, and **Send test email**.

## Release
```bash
# bump version in Cargo.toml (workspace.package.version), commit, then:
git tag v0.1.0 && git push origin v0.1.0
```
GitHub Actions publishes `ghcr.io/fahed-alhammadi/passauth:0.1.0`, `:0.1` and `:latest`. It also creates a GitHub release with `passauth-extension-v0.1.0.zip` attached.
