// JSON message contract for PassAuth's WebAuthn (passkey) authenticator.
//
// Flow:  page (MAIN world, page/webauthn.ts)
//          --window.postMessage-->  bridge (isolated world, content/passkey-bridge.ts)
//          --chrome.runtime.sendMessage-->  background (uses background/passkeys.ts)
// and back the same way. Every binary value (BufferSource in the WebAuthn IDL)
// is carried as an unpadded base64url string. Types only: no runtime code here.

/** Unpadded base64url (RFC 4648 §5). */
export type Base64URLString = string;

/** Stored passkey. Mirrors `Passkey` in crates/core/src/item.rs and web/src/lib/types.ts. */
export interface Passkey {
  credential_id: Base64URLString;
  rp_id: string;
  rp_name: string;
  user_handle: Base64URLString;
  user_name: string;
  user_display_name: string;
  /** COSE algorithm; only -7 (ES256) is produced. */
  algorithm: number;
  /** base64url PKCS#8 private key. */
  private_key: Base64URLString;
  counter: number;
  discoverable: boolean;
  /** Unix seconds. */
  created_at: number;
}

export interface PublicKeyCredentialDescriptorJSON {
  id: Base64URLString;
  type: string; // "public-key"
  transports?: string[];
}

/** JSON-safe PublicKeyCredentialCreationOptions (`options.publicKey` of navigator.credentials.create). */
export interface CreateRequest {
  rp: { id?: string; name: string };
  user: { id: Base64URLString; name: string; displayName: string };
  challenge: Base64URLString;
  pubKeyCredParams: { type: string; alg: number }[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    residentKey?: string;
    requireResidentKey?: boolean;
    userVerification?: string;
  };
  hints?: string[];
  attestation?: string;
  attestationFormats?: string[];
  /** Extension inputs; any binary values inside are base64url strings. */
  extensions?: Record<string, unknown>;
}

/** JSON-safe PublicKeyCredentialRequestOptions (`options.publicKey` of navigator.credentials.get). */
export interface GetRequest {
  challenge: Base64URLString;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: string;
  hints?: string[];
  extensions?: Record<string, unknown>;
}

export interface ClientExtensionResultsJSON {
  credProps?: { rk: boolean };
  [name: string]: unknown;
}

/** WebAuthn L3 RegistrationResponseJSON (PublicKeyCredential.toJSON() after create). */
export interface RegistrationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: {
    clientDataJSON: Base64URLString;
    attestationObject: Base64URLString;
    authenticatorData: Base64URLString;
    transports: string[];
    /** DER SubjectPublicKeyInfo. */
    publicKey: Base64URLString;
    publicKeyAlgorithm: number;
  };
  clientExtensionResults: ClientExtensionResultsJSON;
}

/** WebAuthn L3 AuthenticationResponseJSON (PublicKeyCredential.toJSON() after get). */
export interface AuthenticationResponseJSON {
  id: Base64URLString;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment: "platform";
  response: {
    clientDataJSON: Base64URLString;
    authenticatorData: Base64URLString;
    /** DER-encoded ECDSA signature. */
    signature: Base64URLString;
    userHandle?: Base64URLString;
  };
  clientExtensionResults: ClientExtensionResultsJSON;
}

/** Error surfaced to the page as `new DOMException(message, name)`, e.g. NotAllowedError. */
export interface PasskeyErrorJSON {
  name: string;
  message: string;
}

export type PasskeyKind = "create" | "get";

// ---------------------------------------------------------------- page <-> bridge

/** page -> bridge, via window.postMessage. */
export type PageToBridgeMessage =
  | { source: "passauth-page"; id: string; kind: "create"; options: CreateRequest }
  | { source: "passauth-page"; id: string; kind: "get"; options: GetRequest };

/**
 * bridge -> page, via window.postMessage. Exactly one of `ack`, `result`,
 * `fallback`, `error` is set. `ack` is sent immediately on receipt so the page
 * can fall back to the browser quickly when no bridge is listening.
 */
export interface BridgeToPageMessage {
  source: "passauth-bridge";
  id: string;
  ack?: true;
  result?: RegistrationResponseJSON | AuthenticationResponseJSON;
  fallback?: true;
  error?: PasskeyErrorJSON;
}

// ---------------------------------------------------------------- bridge <-> background

/** bridge -> background, via chrome.runtime.sendMessage. `origin` is computed by the bridge from its own frame. */
export type PasskeyRuntimeMessage =
  | { type: "passkey:create"; options: CreateRequest; origin: string; topLevel: boolean }
  | { type: "passkey:get"; options: GetRequest; origin: string; topLevel: boolean };

/** background -> bridge reply. */
export type PasskeyRuntimeReply =
  | { result: RegistrationResponseJSON | AuthenticationResponseJSON }
  | { fallback: true }
  | { error: PasskeyErrorJSON };
