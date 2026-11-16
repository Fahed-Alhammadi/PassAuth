/**
 * PassAuth's document_start content script (bridge.js, isolated world, every frame): only the passkey bridge, which
 * must be listening before the page's first WebAuthn call (the MAIN-world shim, page/webauthn.ts, falls back to the
 * browser when no bridge answers within 1.5 s). Everything else — filling, the inline menu, save prompts — is
 * content.js (index.ts), injected at document_idle so it costs page loads nothing.
 */
import { installPasskeyBridge } from "./passkey-bridge";

installPasskeyBridge();
