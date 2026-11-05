/**
 * App updates: checked 10 s after launch (at most once a day) and on demand. The user always confirms
 * before anything is downloaded or installed; the dialog is the web vault's Modal, not a native one.
 */
import { useState, useSyncExternalStore } from "react";
import { relaunch } from "@tauri-apps/plugin-process";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { Modal } from "@web/components/ui";

const LAST_CHECK_KEY = "desktop.updateCheckedAt";
const AUTO_CHECK_DELAY_MS = 10_000;
const AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

type Phase =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "current" }
  | { kind: "available"; version: string }
  | { kind: "downloading"; version: string; downloaded: number; total: number | null }
  | { kind: "error"; message: string; detail: string };

let phase: Phase = { kind: "idle" };
let found: Update | null = null;
let running = false;
const subs = new Set<() => void>();

function setPhase(p: Phase) {
  phase = p;
  subs.forEach((fn) => fn());
}

const detailOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function scheduleUpdateCheck() {
  if (Date.now() - (Number(localStorage.getItem(LAST_CHECK_KEY)) || 0) < AUTO_CHECK_INTERVAL_MS) return;
  setTimeout(() => runCheck("silent").catch(() => {}), AUTO_CHECK_DELAY_MS);
}

/** Resolves with the available version or null; shows the dialog when an update exists or the check fails. */
export const checkForUpdates = (tellUpToDate: boolean) => runCheck(tellUpToDate ? "all" : "problems");

/** What the dialog reports: the daily check only an update, Settings also failures, the menus everything. */
async function runCheck(report: "silent" | "problems" | "all"): Promise<string | null> {
  if (running) return found?.version ?? null;
  running = true;
  if (report === "all") setPhase({ kind: "checking" });
  try {
    found = await check();
    localStorage.setItem(LAST_CHECK_KEY, String(Date.now()));
    if (found) setPhase({ kind: "available", version: found.version });
    else setPhase({ kind: report === "all" ? "current" : "idle" });
    return found?.version ?? null;
  } catch (e) {
    if (report !== "silent") setPhase({ kind: "error", message: "Couldn't check for updates. Check your connection and try again.", detail: detailOf(e) });
    throw e;
  } finally {
    running = false;
  }
}

/** Download and install the update from the last check (checking first if there is none), then restart. */
export async function installUpdate() {
  if (!found) {
    await runCheck("all");
    if (!found) return;
  }
  const update = found;
  let downloaded = 0;
  setPhase({ kind: "downloading", version: update.version, downloaded: 0, total: null });
  try {
    await update.downloadAndInstall((event) => {
      if (event.event === "Started") setPhase({ kind: "downloading", version: update.version, downloaded: 0, total: event.data.contentLength ?? null });
      else if (event.event === "Progress" && phase.kind === "downloading") {
        downloaded += event.data.chunkLength;
        setPhase({ ...phase, downloaded });
      }
    });
    await relaunch();
  } catch (e) {
    found = null;
    setPhase({ kind: "error", message: "Couldn't install the update. Try again later.", detail: detailOf(e) });
  }
}

const subscribe = (fn: () => void) => {
  subs.add(fn);
  return () => {
    subs.delete(fn);
  };
};

export function UpdateDialog() {
  const p = useSyncExternalStore(subscribe, () => phase);
  const [showDetail, setShowDetail] = useState(false);
  if (p.kind === "idle") return null;
  const close = () => {
    if (p.kind !== "downloading") setPhase({ kind: "idle" });
  };
  const title =
    p.kind === "checking"
      ? "Checking for updates…"
      : p.kind === "current"
        ? "You're on the latest version"
        : p.kind === "available"
          ? `PassAuth ${p.version} is available`
          : p.kind === "downloading"
            ? `Updating to PassAuth ${p.version}`
            : "Update check failed";
  const pct = p.kind === "downloading" && p.total ? Math.min(100, Math.round((p.downloaded / p.total) * 100)) : null;
  return (
    <Modal title={title} onClose={close}>
      {p.kind === "checking" && <p className="card-text muted">Looking for a newer version.</p>}
      {p.kind === "current" && (
        <>
          <p className="card-text muted">PassAuth checks again once a day.</p>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-primary" onClick={close} data-autofocus="">
              Done
            </button>
          </div>
        </>
      )}
      {p.kind === "available" && (
        <>
          <p className="card-text">PassAuth closes and reopens when it's done.</p>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn" onClick={close}>
              Not now
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void installUpdate()} data-autofocus="">
              Install and restart
            </button>
          </div>
        </>
      )}
      {p.kind === "downloading" && (
        <>
          <p className="card-text muted">PassAuth closes and reopens when it's done.</p>
          <progress className="update-bar" value={pct ?? undefined} max={100} aria-label="Download progress" />
          <p className="small muted">{pct === null ? "Downloading…" : `${pct}%`}</p>
        </>
      )}
      {p.kind === "error" && (
        <>
          <p className="card-text">{p.message}</p>
          <details className="update-detail" open={showDetail} onToggle={(e) => setShowDetail(e.currentTarget.open)}>
            <summary className="small muted">Details</summary>
            <pre className="small">{p.detail}</pre>
          </details>
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-primary" onClick={close} data-autofocus="">
              Close
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}
