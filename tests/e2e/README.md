# Browser end-to-end tests

Headless browser checks driven over the Chrome DevTools Protocol (no extra npm packages). Run them against a throwaway server, not your real vault.

```bash
# 1. Build the clients
scripts/build-wasm.sh web/src/wasm && (cd web && pnpm build)
scripts/build-wasm.sh extension/src/wasm && (cd extension && pnpm build)

# 2. Start a throwaway server and the test login site
mkdir -p /tmp/pa-e2e
DATABASE_URL="sqlite:///tmp/pa-e2e/passauth.db?mode=rwc" WEB_VAULT_DIR="$PWD/web/dist" \
  BIND=127.0.0.1:8091 DOMAIN=http://localhost:8091 ADMIN_TOKEN=e2e-admin-token-123 \
  cargo run -p passauth-server -- serve &
(cd tests/e2e/site && python3 -m http.server 8099 --bind 127.0.0.1) &

# 3. Run (screenshots go to the folder given as the last argument)
mkdir -p /tmp/pa-shots
node tests/e2e/web.mjs /tmp/pa-shots                                         # web vault (Google Chrome)
node tests/e2e/extension-basic.mjs "$PWD/extension/dist" /tmp/pa-shots       # fill, save prompt, passkeys
node tests/e2e/extension-settings.mjs "$PWD/extension/dist" /tmp/pa-shots    # inline menu, timeouts, URI match, sync, icons, accounts
node tests/e2e/store-screenshots.mjs "$PWD/extension/dist"                   # Chrome Web Store screenshots + promo tiles → docs/store/
```

- The extension tests need **Chromium** (branded Chrome ignores `--load-extension`). Override paths with `CHROMIUM=` / `CHROME=`.
- `PASSAUTH_URL` (default `http://localhost:8091`) points the tests at another server. The test site must stay on `http://localhost:8099`.
- Headless Chromium renders in dark mode; the settings test switches to light mode for its last screenshots.
