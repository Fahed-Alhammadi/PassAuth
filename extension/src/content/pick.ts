/** Pure helpers for the save prompt (no DOM), unit-tested in test/urls.test.mjs. */

export interface PasswordFieldInfo {
  value: string;
  autocomplete: string;
}

/**
 * The password to offer to save from a submitted form.
 * - `autocomplete="new-password"` fields win (sign-up and change-password forms).
 * - Two or more filled fields: the last two match → new + confirm; otherwise the
 *   last one that isn't marked as the current password (current + new).
 * - One field: that one (a sign-in form).
 */
export function submittedPassword(fields: PasswordFieldInfo[]): string {
  const filled = fields.filter((f) => f.value);
  if (!filled.length) return "";
  const fresh = filled.filter((f) => /\bnew-password\b/i.test(f.autocomplete));
  if (fresh.length) return fresh[fresh.length - 1].value;
  if (filled.length === 1) return filled[0].value;
  const [a, b] = filled.slice(-2);
  if (a.value === b.value) return b.value;
  const notCurrent = filled.filter((f) => !/\bcurrent-password\b/i.test(f.autocomplete));
  return (notCurrent.at(-1) ?? b).value;
}
