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
Push a tag (see "Release" below), then set `PASSAUTH_VERSION=0.2.2` (or `latest`) in `.env` and run `docker compose up -d` without `--build`.

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
- [ ] `http://localhost:8080/admin` with `ADMIN_TOKEN`: users, invites, test email. Turn off "Allow new accounts": the sign-in page hides "Create an account" and only invited emails can register. Old `/#/...` links still work.

### Extension
- [ ] Sign in (with 2FA if enabled). Logins for the current site appear under "Autofill suggestions for <site>".
- [ ] With many items, the list scrolls while the header, search box and bottom tabs stay in place. Each login has a "⋯" menu to copy the username, password or verification code.
- [ ] **Fill** fills the username and password. **Cmd/Ctrl+Shift+L** fills when there's exactly one match.
- [ ] Filling a login that has an authenticator key copies the current code ("Verification code copied" appears on the page). Turn it off in Settings → Autofill.
- [ ] Inline menu: click into a login site's username or password field. The PassAuth icon appears in the field and a list of matching logins opens below it; choose one to fill. Esc closes it. Settings → Autofill switches it to "when I click the icon" or off. It never appears on PassAuth's own pages.
- [ ] Settings → Autofill → Default URI match detection (Base domain, Host, Starts with, Regular expression, Exact, Never) changes which logins are suggested. Websites set to "Default" in the web vault follow it.
- [ ] Settings → Account security: try each vault timeout (Immediately locks when the popup closes; Never keeps the vault unlocked after a browser restart) and the Log out action.
- [ ] Settings → Appearance → Show website icons: icons appear in the popup, the inline menu and the web vault (Settings → Account → Appearance there).
- [ ] Settings → Sync → Sync vault now shows "Sync complete" and the last sync time.
- [ ] Settings → Clipboard: copied values clear after the chosen delay, even after the popup closes.
- [ ] Sign in to a site with a new password: PassAuth offers to save or update it. "Never for this site" works.
- [ ] Passkeys: on https://webauthn.io, register and then authenticate. The confirmation window opens, and the passkey appears on the item in the web vault.
- [ ] "Use another device or security key" hands the request back to Chrome.
- [ ] Lock from the popup; restart Chrome. The extension is locked and asks for the master password.

### SMTP
Set the `SMTP_*` variables in `.env` and restart. Check: the verification email on sign-up, the new-device alert, email two-step codes, invites from the admin panel, and **Send test email**.

## Release
```bash
# bump version in Cargo.toml (workspace.package.version), commit, then:
git tag v0.2.2 && git push origin v0.2.2
```
GitHub Actions publishes `ghcr.io/fahed-alhammadi/passauth:0.2.2`, `:0.2` and `:latest`. It also creates a GitHub release with `passauth-extension-v0.2.2.zip` attached.
