/**
 * Browser WebAuthn calls for two-step login with a security key or passkey.
 * The server (webauthn-rs) speaks the WebAuthn JSON form: binary fields are
 * base64url strings, which newer browsers convert natively
 * (`parseCreationOptionsFromJSON` / `toJSON`); older ones get the same shape by hand.
 */

export class WebAuthnError extends Error {
  constructor(
    message: string,
    public kind: "unsupported" | "cancelled" | "failed",
  ) {
    super(message);
  }
}

const UNSUPPORTED = "This browser can't use security keys here. Security keys need a browser with WebAuthn on an https address (or localhost).";

/** Whether this page can run WebAuthn ceremonies. */
export function webauthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    !!navigator.credentials?.create &&
    !!navigator.credentials?.get &&
    window.isSecureContext
  );
}

type Json = Record<string, unknown>;

function fromB64url(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(buf: ArrayBuffer | null): string | null {
  if (!buf) return null;
  let bin = "";
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Replace base64url ids with buffers in a descriptor list (`excludeCredentials` / `allowCredentials`). */
function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d) => ({ ...(d as Json), id: fromB64url((d as { id: string }).id) }) as PublicKeyCredentialDescriptor);
}

type PKC = typeof PublicKeyCredential & {
  parseCreationOptionsFromJSON?: (json: Json) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (json: Json) => PublicKeyCredentialRequestOptions;
};

function mapError(e: unknown, creating: boolean): WebAuthnError {
  const name = (e as { name?: string } | null)?.name;
  switch (name) {
    case "NotAllowedError":
    case "AbortError":
      return new WebAuthnError(
        creating ? "No security key was added. Touch your key or confirm on your device, then try again." : "The security key wasn't used. Try again, or use another method.",
        "cancelled",
      );
    case "InvalidStateError":
      return new WebAuthnError("This security key is already registered on your account.", "failed");
    case "NotSupportedError":
    case "SecurityError":
      return new WebAuthnError(UNSUPPORTED, "unsupported");
  }
  return new WebAuthnError(e instanceof Error && e.message ? e.message : "The security key didn't respond.", "failed");
}

/** Serialize a credential the way `PublicKeyCredential.toJSON()` does. */
function credentialJSON(cred: PublicKeyCredential): Json {
  const withToJSON = cred as PublicKeyCredential & { toJSON?: () => unknown };
  if (typeof withToJSON.toJSON === "function") return withToJSON.toJSON() as unknown as Json;
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: Json = { clientDataJSON: toB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toB64url(r.attestationObject);
    if (typeof r.getTransports === "function") response.transports = r.getTransports();
  } else {
    response.authenticatorData = toB64url(r.authenticatorData);
    response.signature = toB64url(r.signature);
    response.userHandle = toB64url(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** Register a new security key or passkey from the server's creation options; returns the JSON to send back. */
export async function createCredential(options: unknown): Promise<Json> {
  if (!webauthnSupported()) throw new WebAuthnError(UNSUPPORTED, "unsupported");
  const pk = (options as { publicKey: Json }).publicKey;
  const P = PublicKeyCredential as PKC;
  const publicKey: PublicKeyCredentialCreationOptions = P.parseCreationOptionsFromJSON
    ? P.parseCreationOptionsFromJSON(pk)
    : ({
        ...pk,
        challenge: fromB64url(pk.challenge as string),
        user: { ...(pk.user as Json), id: fromB64url((pk.user as { id: string }).id) },
        excludeCredentials: descriptors(pk.excludeCredentials),
      } as PublicKeyCredentialCreationOptions);
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (e) {
    throw mapError(e, true);
  }
  if (!cred) throw new WebAuthnError("No security key was added.", "cancelled");
  return credentialJSON(cred as PublicKeyCredential);
}

/** Sign the server's request options with a registered security key or passkey; returns the JSON to send back. */
export async function getCredential(options: unknown): Promise<Json> {
  if (!webauthnSupported()) throw new WebAuthnError(UNSUPPORTED, "unsupported");
  const pk = (options as { publicKey: Json }).publicKey;
  const P = PublicKeyCredential as PKC;
  const publicKey: PublicKeyCredentialRequestOptions = P.parseRequestOptionsFromJSON
    ? P.parseRequestOptionsFromJSON(pk)
    : ({
        ...pk,
        challenge: fromB64url(pk.challenge as string),
        allowCredentials: descriptors(pk.allowCredentials),
      } as PublicKeyCredentialRequestOptions);
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (e) {
    throw mapError(e, false);
  }
  if (!cred) throw new WebAuthnError("The security key wasn't used.", "cancelled");
  return credentialJSON(cred as PublicKeyCredential);
}
