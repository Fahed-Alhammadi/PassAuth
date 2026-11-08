import { useEffect, useState } from "react";
import { emit } from "@tauri-apps/api/event";
import { App } from "@web/App";
import { LogoMark } from "@web/components/Logo";
import { Modal } from "@web/components/ui";
import { SESSION_KEY } from "@web/lib/api";
import { loadSecrets, secretStore } from "@web/lib/platform";
import { EMAIL_KEY, boot, rememberKey, secretKeyKey, useVault } from "@web/lib/vault";
import { AddCodeHost } from "./AddCode";
import { Connect } from "./Connect";
import { setSecretsHost } from "./secrets";
import { connectServer, rememberServer, savedServer } from "./server";
import { UpdateDialog } from "./updater";

const SLOW_BOOT_MS = 10_000;

type Stage = { kind: "connect"; previous?: string } | { kind: "booting"; base: string } | { kind: "app"; base: string };

/** Change-server requests come from the web vault (Login footer, Settings) and the menus, through the desktop hooks. */
const listeners = new Set<() => void>();
export function onChangeServer(fn: () => void) {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}
export const requestChangeServer = () => listeners.forEach((fn) => fn());

let askChangeServer: ((answer: boolean) => void) | null = null;
const confirmListeners = new Set<() => void>();
/** In-app confirmation; resolves true when the user wants to change server. */
export function confirmChangeServer(): Promise<boolean> {
  return new Promise((resolve) => {
    askChangeServer = (answer) => {
      askChangeServer = null;
      confirmListeners.forEach((fn) => fn());
      resolve(answer);
    };
    confirmListeners.forEach((fn) => fn());
  });
}

/** The keychain entries for this server, read before the web vault starts. */
async function preloadSecrets(host: string) {
  setSecretsHost(host);
  await loadSecrets([SESSION_KEY, EMAIL_KEY]);
  const email = secretStore.get(EMAIL_KEY);
  if (email) await loadSecrets([secretKeyKey(email), rememberKey(email)]);
}

export function Root() {
  const [stage, setStage] = useState<Stage>(() => {
    const base = savedServer();
    return base ? { kind: "booting", base } : { kind: "connect" };
  });

  useEffect(() => {
    if (stage.kind !== "booting") return;
    const { base } = stage;
    let cancelled = false;
    (async () => {
      await preloadSecrets(new URL(base).host).catch(() => {});
      await connectServer(base);
      await boot();
      if (!cancelled) setStage({ kind: "app", base });
    })();
    return () => {
      cancelled = true;
    };
  }, [stage]);

  useEffect(
    () =>
      onChangeServer(() => {
        const previous = savedServer() ?? undefined;
        rememberServer(null);
        setStage({ kind: "connect", previous });
      }),
    [],
  );

  return (
    <>
      {stage.kind === "connect" && (
        <Connect
          initial={stage.previous}
          onConnect={(base) => {
            rememberServer(base);
            setStage({ kind: "booting", base });
          }}
        />
      )}
      {stage.kind === "booting" && <Splash host={new URL(stage.base).host} />}
      {stage.kind === "app" && (
        <>
          <App key={stage.base} />
          <VaultStateForTray />
          <AddCodeHost />
        </>
      )}
      <ChangeServerDialog />
      <UpdateDialog />
    </>
  );
}

/** Loading screen; after 10 s it names the server and offers a way out. */
function Splash({ host }: { host: string }) {
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setSlow(true), SLOW_BOOT_MS);
    return () => clearTimeout(t);
  }, []);
  return (
    <div className="splash" role="status">
      <LogoMark size={56} />
      <span>{slow ? `Still connecting to ${host}…` : "Loading PassAuth…"}</span>
      {slow && (
        <button type="button" className="btn" onClick={requestChangeServer}>
          Change server
        </button>
      )}
    </div>
  );
}

/** The tray's "Lock Vault" is enabled only while the vault is unlocked. */
function VaultStateForTray() {
  const { status } = useVault();
  useEffect(() => {
    void emit("vault-state", status === "unlocked");
    return () => void emit("vault-state", false);
  }, [status]);
  return null;
}

function ChangeServerDialog() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const refresh = () => setOpen(askChangeServer !== null);
    confirmListeners.add(refresh);
    return () => {
      confirmListeners.delete(refresh);
    };
  }, []);
  if (!open) return null;
  return (
    <Modal title="Change server?" onClose={() => askChangeServer?.(false)}>
      <p className="card-text">You'll be signed out. Your vault stays on the server; sign in again to open it.</p>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <button type="button" className="btn" onClick={() => askChangeServer?.(false)} data-autofocus="">
          Cancel
        </button>
        <button type="button" className="btn btn-primary" onClick={() => askChangeServer?.(true)}>
          Change server
        </button>
      </div>
    </Modal>
  );
}
