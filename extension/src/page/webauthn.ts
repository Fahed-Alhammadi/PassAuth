// PassAuth WebAuthn shim — MAIN world, document_start. Bundle as an IIFE.
//
// Wraps navigator.credentials.create/get for `publicKey` requests (except
// conditional mediation) and routes them to the PassAuth content-script bridge
// (content/passkey-bridge.ts) via window.postMessage. The bridge either returns
// a WebAuthn JSON result, an error, or asks us to fall back to the browser's
// native implementation. Nothing is exposed on `window`; the only data the page
// ever receives is a normal PublicKeyCredential-like result or DOMException.

import type {
  AuthenticationResponseJSON,
  BridgeToPageMessage,
  PasskeyKind,
  RegistrationResponseJSON,
} from "../shared/passkey-types";

(() => {
  const w = window;
  if (
    !w.isSecureContext ||
    typeof CredentialsContainer === "undefined" ||
    typeof PublicKeyCredential === "undefined" ||
    typeof AuthenticatorAttestationResponse === "undefined" ||
    typeof AuthenticatorAssertionResponse === "undefined"
  ) {
    return;
  }

  // Captured at document_start, before any page script can tamper with them.
  const containerProto = CredentialsContainer.prototype;
  const nativeCreate = containerProto.create;
  const nativeGet = containerProto.get;
  const post = w.postMessage.bind(w);
  const defineProperty = Object.defineProperty;
  const objectToString = Object.prototype.toString;
  const setTimer = w.setTimeout.bind(w);
  const clearTimer = w.clearTimeout.bind(w);

  const ACK_TIMEOUT_MS = 1500; // no bridge ack within this window → native
  const DEFAULT_TIMEOUT_MS = 120_000;
  const MIN_TIMEOUT_MS = 10_000;
  const MAX_TIMEOUT_MS = 600_000;
  const ERROR_NAMES = new Set([
    "NotAllowedError",
    "InvalidStateError",
    "SecurityError",
    "NotSupportedError",
    "AbortError",
    "ConstraintError",
    "UnknownError",
  ]);

  type PublicKeyOptions = Record<string, unknown> & { timeout?: unknown };
  type CredOptions = { publicKey?: PublicKeyOptions; mediation?: string; signal?: AbortSignal };
  type Reply = Omit<BridgeToPageMessage, "source" | "id">;

  // ---------------------------------------------------------------- encoding

  function isBufferSource(v: unknown): v is ArrayBuffer | ArrayBufferView {
    return ArrayBuffer.isView(v) || objectToString.call(v) === "[object ArrayBuffer]";
  }

  function toB64u(v: ArrayBuffer | ArrayBufferView): string {
    const bytes = ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength) : new Uint8Array(v);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64u(s: string): ArrayBuffer {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  /** Deep-copy options into JSON-safe data, BufferSource → base64url. */
  function jsonify(v: unknown, depth = 0): unknown {
    if (depth > 16) throw new TypeError("options too deep");
    if (isBufferSource(v)) return toB64u(v);
    if (Array.isArray(v)) return v.map((x) => jsonify(x, depth + 1));
    if (typeof v === "object" && v !== null) {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v)) {
        const x = jsonify((v as Record<string, unknown>)[k], depth + 1);
        if (x !== undefined) out[k] = x;
      }
      return out;
    }
    if (typeof v === "function" || typeof v === "symbol" || typeof v === "bigint") return undefined;
    return v;
  }

  // ---------------------------------------------------------------- result objects

  /** Own, non-enumerable, read-only properties that shadow the native prototype getters. */
  function define<T extends object>(target: T, props: Record<string, unknown>): T {
    for (const k of Object.keys(props)) {
      defineProperty(target, k, { value: props[k], enumerable: false, writable: false, configurable: true });
    }
    return target;
  }

  function toCredential(
    kind: PasskeyKind,
    json: RegistrationResponseJSON | AuthenticationResponseJSON,
  ): PublicKeyCredential {
    let response: AuthenticatorResponse;
    if (kind === "create") {
      const r = (json as RegistrationResponseJSON).response;
      const authData = fromB64u(r.authenticatorData);
      const publicKey = r.publicKey ? fromB64u(r.publicKey) : null;
      const transports = Array.isArray(r.transports) ? r.transports.map(String) : [];
      const alg = r.publicKeyAlgorithm;
      response = define(Object.create(AuthenticatorAttestationResponse.prototype) as AuthenticatorAttestationResponse, {
        clientDataJSON: fromB64u(r.clientDataJSON),
        attestationObject: fromB64u(r.attestationObject),
        getTransports: function getTransports() {
          return transports.slice();
        },
        getAuthenticatorData: function getAuthenticatorData() {
          return authData.slice(0);
        },
        getPublicKey: function getPublicKey() {
          return publicKey ? publicKey.slice(0) : null;
        },
        getPublicKeyAlgorithm: function getPublicKeyAlgorithm() {
          return alg;
        },
      });
    } else {
      const r = (json as AuthenticationResponseJSON).response;
      response = define(Object.create(AuthenticatorAssertionResponse.prototype) as AuthenticatorAssertionResponse, {
        clientDataJSON: fromB64u(r.clientDataJSON),
        authenticatorData: fromB64u(r.authenticatorData),
        signature: fromB64u(r.signature),
        userHandle: r.userHandle ? fromB64u(r.userHandle) : null,
      });
    }
    const extensions = json.clientExtensionResults ?? {};
    return define(Object.create(PublicKeyCredential.prototype) as PublicKeyCredential, {
      id: String(json.id),
      rawId: fromB64u(json.rawId),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: function getClientExtensionResults() {
        return structuredClone(extensions);
      },
      toJSON: function toJSON() {
        return structuredClone(json);
      },
    });
  }

  // ---------------------------------------------------------------- bridge transport

  const pending = new Map<string, (reply: Reply) => void>();

  // Capture-phase listener registered before any page script; replies are
  // swallowed so page message handlers never see PassAuth traffic.
  w.addEventListener(
    "message",
    (event: MessageEvent) => {
      if (event.source !== w) return;
      const data = event.data as Partial<BridgeToPageMessage> | null;
      if (!data || typeof data !== "object" || data.source !== "passauth-bridge") return;
      event.stopImmediatePropagation();
      const handler = typeof data.id === "string" ? pending.get(data.id) : undefined;
      if (handler) handler(data);
    },
    true,
  );

  function newId(): string {
    try {
      return crypto.randomUUID();
    } catch {
      return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
    }
  }

  function abortReason(signal: AbortSignal): unknown {
    return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
  }

  function timeoutFor(publicKey: PublicKeyOptions): number {
    const t = typeof publicKey.timeout === "number" && Number.isFinite(publicKey.timeout) ? publicKey.timeout : DEFAULT_TIMEOUT_MS;
    return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, t));
  }

  function intercept(
    kind: PasskeyKind,
    options: CredOptions,
    callNative: () => Promise<Credential | null>,
  ): Promise<Credential | null> {
    const publicKey = options.publicKey!;
    const signal = options.signal;
    if (signal?.aborted) return Promise.reject(abortReason(signal));

    let serialized: unknown;
    try {
      serialized = jsonify(publicKey);
    } catch {
      return callNative();
    }
    if (!serialized || typeof (serialized as { challenge?: unknown }).challenge !== "string") return callNative();

    const id = newId();
    return new Promise<Credential | null>((resolve, reject) => {
      let ackTimer: ReturnType<typeof setTimeout> | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;

      const finish = (): void => {
        pending.delete(id);
        if (ackTimer !== undefined) clearTimer(ackTimer);
        if (timer !== undefined) clearTimer(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      const fallback = (): void => {
        finish();
        callNative().then(resolve, reject);
      };
      function onAbort(): void {
        finish();
        reject(abortReason(signal!));
      }

      pending.set(id, (reply) => {
        if (reply.ack) {
          if (ackTimer !== undefined) clearTimer(ackTimer);
          ackTimer = undefined;
          return;
        }
        if (reply.result) {
          finish();
          try {
            resolve(toCredential(kind, reply.result));
          } catch {
            reject(new DOMException("The operation failed.", "NotAllowedError"));
          }
        } else if (reply.error) {
          finish();
          const name = ERROR_NAMES.has(String(reply.error.name)) ? String(reply.error.name) : "NotAllowedError";
          reject(new DOMException(String(reply.error.message ?? ""), name));
        } else {
          fallback();
        }
      });
      signal?.addEventListener("abort", onAbort);
      ackTimer = setTimer(fallback, ACK_TIMEOUT_MS);
      timer = setTimer(() => {
        finish();
        reject(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"));
      }, timeoutFor(publicKey));

      const targetOrigin = w.location.origin === "null" ? "*" : w.location.origin;
      post({ source: "passauth-page", id, kind, options: serialized }, targetOrigin);
    });
  }

  function shouldIntercept(options: unknown): options is CredOptions {
    if (!options || typeof options !== "object") return false;
    const o = options as CredOptions;
    return !!o.publicKey && typeof o.publicKey === "object" && o.mediation !== "conditional";
  }

  // ---------------------------------------------------------------- install

  const wrappers = {
    create: function create(this: CredentialsContainer, ...args: [CredentialCreationOptions?]) {
      const callNative = () => Reflect.apply(nativeCreate, this, args) as Promise<Credential | null>;
      const options: unknown = args[0];
      if (!(this instanceof CredentialsContainer) || !shouldIntercept(options)) return callNative();
      return intercept("create", options, callNative);
    },
    get: function get(this: CredentialsContainer, ...args: [CredentialRequestOptions?]) {
      const callNative = () => Reflect.apply(nativeGet, this, args) as Promise<Credential | null>;
      const options: unknown = args[0];
      if (!(this instanceof CredentialsContainer) || !shouldIntercept(options)) return callNative();
      return intercept("get", options, callNative);
    },
  };

  for (const name of ["create", "get"] as const) {
    const desc = Object.getOwnPropertyDescriptor(containerProto, name);
    defineProperty(containerProto, name, {
      value: wrappers[name],
      writable: desc?.writable ?? true,
      enumerable: desc?.enumerable ?? true,
      configurable: desc?.configurable ?? true,
    });
  }

  const uvpaa = Object.getOwnPropertyDescriptor(PublicKeyCredential, "isUserVerifyingPlatformAuthenticatorAvailable");
  defineProperty(PublicKeyCredential, "isUserVerifyingPlatformAuthenticatorAvailable", {
    value: function isUserVerifyingPlatformAuthenticatorAvailable() {
      return Promise.resolve(true);
    },
    writable: uvpaa?.writable ?? true,
    enumerable: uvpaa?.enumerable ?? true,
    configurable: uvpaa?.configurable ?? true,
  });
})();
