/**
 * Password and passphrase options: character types, length, words, separator. Shared by the web vault's Generator
 * page and the extension, so it only renders `value` and reports changes; it imports no vault, API, platform or wasm
 * code. The settings type, defaults and `generatorRequest(value)` (the core generator's arguments) are in
 * `lib/generator.ts`, which has no imports, so the extension's background can use it too.
 */
import { useId } from "react";
import { PASSPHRASE_WORDS, PASSWORD_LENGTH, SEPARATORS, type PassphraseOptions, type PasswordOptions, type GeneratorSettings } from "../lib/generator";
import "../styles/generator.css";

type CharClass = "lowercase" | "uppercase" | "digits" | "symbols";
const CHAR_CLASSES: { key: CharClass; label: string }[] = [
  { key: "lowercase", label: "Lowercase letters (a-z)" },
  { key: "uppercase", label: "Uppercase letters (A-Z)" },
  { key: "digits", label: "Numbers (0-9)" },
  { key: "symbols", label: "Symbols (!@#$%^&*-_=+?)" },
];

/** A slider with a number box beside it, for the same whole number. */
function RangeField({ label, numberLabel, min, max, value, onChange }: { label: string; numberLabel: string; min: number; max: number; value: number; onChange: (n: number) => void }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id} className="field-label">
        {label}
      </label>
      <div className="range-row">
        <input id={id} type="range" min={min} max={max} value={value} onChange={(e) => onChange(Number(e.target.value))} />
        <input
          className="input"
          type="number"
          min={min}
          max={max}
          aria-label={numberLabel}
          value={value}
          onChange={(e) => {
            const n = Number(e.target.value);
            if (Number.isFinite(n)) onChange(Math.min(max, Math.max(min, Math.round(n))));
          }}
        />
      </div>
    </div>
  );
}

/** The options of `value.mode` (the caller shows the password/passphrase switch, the result and the actions). */
export function GeneratorOptions({ value, onChange }: { value: GeneratorSettings; onChange: (next: GeneratorSettings) => void }) {
  if (value.mode === "password") {
    const pw = value.password;
    const set = (patch: Partial<PasswordOptions>) => onChange({ ...value, password: { ...pw, ...patch } });
    const enabled = CHAR_CLASSES.filter((c) => pw[c.key]).length;
    return (
      <div className="stack">
        <RangeField label="Length" numberLabel="Length in characters" {...PASSWORD_LENGTH} value={pw.length} onChange={(length) => set({ length })} />
        <div className="check-grid">
          {CHAR_CLASSES.map((c) => (
            <label key={c.key} className="check">
              <input type="checkbox" checked={pw[c.key]} disabled={pw[c.key] && enabled === 1} onChange={(e) => set({ [c.key]: e.target.checked })} />
              <span>{c.label}</span>
            </label>
          ))}
          <label className="check">
            <input type="checkbox" checked={pw.avoid_ambiguous} onChange={(e) => set({ avoid_ambiguous: e.target.checked })} />
            <span>Avoid look-alike characters (I, l, 1, O, 0, o)</span>
          </label>
        </div>
        {enabled === 1 && <p className="small muted">At least one character type stays on.</p>}
      </div>
    );
  }
  const pp = value.passphrase;
  const set = (patch: Partial<PassphraseOptions>) => onChange({ ...value, passphrase: { ...pp, ...patch } });
  return (
    <div className="stack">
      <RangeField label="Number of words" numberLabel="Number of words" {...PASSPHRASE_WORDS} value={pp.words} onChange={(words) => set({ words })} />
      <label className="field field-narrow">
        <span>Separator</span>
        <select className="select" value={pp.separator} onChange={(e) => set({ separator: e.target.value })}>
          {SEPARATORS.map((s) => (
            <option key={s.label} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
      </label>
      <div className="check-grid">
        <label className="check">
          <input type="checkbox" checked={pp.capitalize} onChange={(e) => set({ capitalize: e.target.checked })} />
          <span>Capitalize each word</span>
        </label>
        <label className="check">
          <input type="checkbox" checked={pp.include_number} onChange={(e) => set({ include_number: e.target.checked })} />
          <span>Include a number</span>
        </label>
      </div>
      <p className="small muted">Words come from the EFF large wordlist, about 12.9 bits each.</p>
    </div>
  );
}
