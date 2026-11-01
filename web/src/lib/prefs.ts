/** Per-browser display preferences for the web vault (not synced). */
import { useSyncExternalStore } from "react";

const ICONS = "passauth.showIcons";
const listeners = new Set<() => void>();

export function getShowIcons() {
  try {
    return localStorage.getItem(ICONS) !== "0";
  } catch {
    return true;
  }
}

export function setShowIcons(show: boolean) {
  try {
    localStorage.setItem(ICONS, show ? "1" : "0");
  } catch {
    /* storage unavailable: keep the default */
  }
  listeners.forEach((l) => l());
}

export const useShowIcons = () =>
  useSyncExternalStore((cb) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
  }, getShowIcons);
