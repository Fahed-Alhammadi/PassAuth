# Chrome Web Store submission: PassAuth

Everything needed to publish the extension, in the order the Developer Dashboard asks for it. Text in blocks is ready to paste.

## Before you start

1. **Developer account.** Sign in at <https://chrome.google.com/webstore/devconsole> with the Google account that will own the listing. Google charges a one-time US$5 registration fee, and the account needs 2-Step Verification.
2. **A public PassAuth server for the reviewers.** The extension does nothing without a server, and it only accepts `https://` addresses (plain http works only for localhost). Run PassAuth on a public HTTPS address (e.g. `https://vault.example.com`) and create a demo account for the reviewers. Add a few demo items, including a login named "GitHub" for `https://github.com` with a made-up username and password and any authenticator key (e.g. `JBSWY3DPEHPK3PXP`), so the test instructions below work.
3. **Privacy policy URL.** Every PassAuth server serves the policy at `/privacy.html`, e.g. `https://vault.example.com/privacy.html`. Open it once to check it loads.
4. **The package.** Bump `version` (root `Cargo.toml`), tag `vX.Y.Z` and take `passauth-extension-vX.Y.Z.zip` from the GitHub release, or build it locally:
   ```bash
   scripts/build-wasm.sh extension/src/wasm
   cd extension && pnpm install && pnpm package   # → extension/passauth-extension.zip
   ```
   Every update you upload needs a higher `version` than the last one.

## Package tab
Upload the zip. The manifest is at its root.

## Store listing tab

**Name** (from the manifest): `PassAuth`

**Summary** (from the manifest, 132 characters max):
```
Fill passwords, one-time codes and passkeys from your self-hosted PassAuth vault.
```

**Description:**
```
PassAuth is a password manager you host yourself. The extension connects to your own PassAuth server and fills your logins on every site.

• Fill logins in one click from the toolbar, from a menu right under the login field, or with Ctrl+Shift+L (⌘⇧L on Mac).
• See how many saved logins match the current site on the PassAuth icon.
• Two-step verification codes: the current code counts down next to the password and is copied automatically after you fill.
• Passkeys: save and use passkeys on sites that support them.
• Save and update logins as you sign in, or add and edit items in the extension.
• Generate strong passwords and passphrases.
• Use up to five accounts, each on its own PassAuth server, and switch between them.
• Lock after a time you choose, on system lock, on browser restart or never; lock or log out.
• Optional: make PassAuth your default password manager by turning off Chrome's own password saving.

Your vault is encrypted on your device before anything is sent to your server, and the server never sees your master password. There are no ads, analytics or third-party services.

You need a PassAuth server to use this extension. Run your own with Docker, or ask the person who runs your organization's server for an account.
```

**Category:** Productivity (or "Privacy & Security" if the dashboard offers it).
**Language:** English.

**Graphic assets** (all in `docs/store/`):

| Field | File | Size |
|---|---|---|
| Store icon | `icon-128.png` | 128×128 |
| Screenshots (up to 5, in this order) | `screenshots/01-vault.png` … `05-control.png` | 1280×800 |
| Small promo tile | `promo-small-440x280.png` | 440×280 |
| Marquee promo tile (optional) | `promo-marquee-1400x560.png` | 1400×560 |

The screenshots use fictional demo data (Alex Morgan, "Copperleaf", "Harbor Bank"; no real brands). Regenerate them after UI changes with `node tests/e2e/store-screenshots.mjs "$PWD/extension/dist"` (see `tests/e2e/README.md` for the throwaway server it needs).

**Official URL / Homepage URL:** your public PassAuth server or project page (optional).
**Support URL:** a page or email where users can reach you (optional, recommended).

## Privacy practices tab

**Single purpose:**
```
PassAuth stores the user's logins, verification codes and passkeys in their self-hosted PassAuth vault and fills them into websites.
```

**Permission justifications:**

| Permission | Justification to paste |
|---|---|
| `storage` | Stores the user's settings, their PassAuth accounts (server address and sign-in tokens) and, while unlocked, the vault keys in memory-only session storage. |
| `alarms` | Locks the vault after the inactivity time the user chose (vault timeout). |
| `idle` | Locks the vault when the computer is locked, if the user chose the "On system lock" timeout. |
| `contextMenus` | Adds "Fill login with PassAuth" to the right-click menu on input fields. |
| `clipboardWrite` | Copies passwords, usernames and verification codes when the user asks, and clears the clipboard again after the delay the user chose. |
| `offscreen` | The clipboard copy and the timed clipboard clear run in an offscreen document, because the service worker has no DOM and the clear must happen after the popup closes. |
| `privacy` (optional, requested only when the user turns on "Make PassAuth your default password manager") | Turns off Chrome's built-in password saving and address/card autofill so they don't compete with PassAuth; turning the option off restores Chrome's settings. |
| Host permissions (`http://*/*`, `https://*/*`) and content scripts | A password manager must work on any site the user signs in to: detect login forms, fill a login the user chose (only on the site it was saved for), offer to save new or changed passwords, show the inline autofill menu, and answer passkey (WebAuthn) requests. Pages are only read for login form fields; nothing from them is stored or sent except the login the user chooses to save, which is encrypted first. |
| Web-accessible resource `inline-menu.html` | The inline autofill menu is an extension page shown in a frame under the login field, so the website can't read the logins listed in it. |

**Remote code:** No, I am not using remote code. (All code, including the WebAssembly crypto module, is in the package. The CSP's `wasm-unsafe-eval` only allows compiling that bundled module.)

**Data usage.** Tick these, because data is sent to the user's own PassAuth server:
- **Personally identifiable information:** email address (and optional name) for the user's PassAuth account.
- **Authentication information:** passwords, verification-code keys and passkeys the user saves (encrypted on the device first).
- **Website content:** the login form fields on the current page, read to fill them and offer to save a login.

Then certify all three statements:
- not sold to third parties;
- not used or transferred for purposes unrelated to the single purpose;
- not used or transferred to determine creditworthiness or for lending.

**Privacy policy URL:** `https://<your-server>/privacy.html`

## Distribution tab
Choose **Public** (anyone can find it) or **Unlisted** (only people with the link). Unlisted is a good first step while you're the only user. Pick the regions; all regions is the default.

## Test instructions (in the submission form)
```
PassAuth is a self-hosted password manager; the extension needs a PassAuth server.

1. Click the PassAuth icon. Server address: https://<your-server>  → Connect.
2. Sign in with: Email <demo email>  Master password <demo password>
3. Open https://github.com/login. The demo vault has a (fake) login saved for github.com, so the PassAuth icon shows "1". Click into the username field to see the inline menu and choose the login, or click "Fill" in the popup. The form is only filled, not submitted.
4. In the popup, open the "GitHub" item: it has a verification code that counts down and can be copied.

No payment or other accounts are needed.
```
Replace the placeholders before submitting. Reviewers usually take a few days; you get an email when the review finishes.

## After approval
- Publish updates by uploading a new zip with a higher version; reviews for updates are usually faster.
- Keep the privacy policy URL working for as long as the listing exists.
