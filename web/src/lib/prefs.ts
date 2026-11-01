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

export type Theme = "system" | "light" | "dark";
const THEME = "passauth.theme";

export function getTheme(): Theme {
  try {
    const t = localStorage.getItem(THEME);
    return t === "light" || t === "dark" ? t : "system";
  } catch {
    return "system";
  }
}

/** Apply the theme to the page (html[data-theme]); "system" follows the OS. */
export function applyTheme(theme: Theme = getTheme()) {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: Theme) {
  try {
    localStorage.setItem(THEME, theme);
  } catch {
    /* storage unavailable: applies to this page only */
  }
  applyTheme(theme);
  listeners.forEach((l) => l());
}

export const useTheme = () =>
  useSyncExternalStore((cb) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
  }, getTheme);
