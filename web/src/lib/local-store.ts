/**
 * This browser's localStorage, tolerant of it being blocked or full: a read then answers null and a write does nothing.
 * `null` as the value removes the key.
 */
export function localGet(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function localSet(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
}
