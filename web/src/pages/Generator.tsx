import { useCallback, useEffect, useState } from "react";
import { copySecret, ErrorText, Icon } from "../components/ui";
import { errorMessage } from "../lib/api";
import { estimateBits, generatePassphrase, generatePassword } from "../lib/vault";
import "../styles/tools.css";

type Mode = "password" | "passphrase";

/** Mirrors `passauth_core::generator::PasswordOptions`. */
interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}

/** Mirrors `passauth_core::generator::PassphraseOptions`. */
interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

const BITS_PER_WORD = 12.9; // EFF large wordlist, 7776 words

const SEPARATORS: { value: string; label: string }[] = [
  { value: "-", label: "Hyphen ( - )" },
  { value: ".", label: "Period ( . )" },
  { value: "_", label: "Underscore ( _ )" },
  { value: ",", label: "Comma ( , )" },
  { value: " ", label: "Space" },
  { value: "", label: "None" },
];

const CHAR_CLASSES: { key: "lowercase" | "uppercase" | "digits" | "symbols"; label: string }[] = [
  { key: "lowercase", label: "Lowercase letters (a-z)" },
  { key: "uppercase", label: "Uppercase letters (A-Z)" },
  { key: "digits", label: "Numbers (0-9)" },
  { key: "symbols", label: "Symbols (!@#$%^&*-_=+?)" },
];

function strength(bits: number): { label: string; color: string; pct: number } {
  if (bits < 40) return { label: "Weak", color: "var(--danger)", pct: 25 };
  if (bits < 60) return { label: "Fair", color: "var(--brass)", pct: 50 };
  if (bits < 80) return { label: "Good", color: "var(--patina)", pct: 75 };
  return { label: "Strong", color: "var(--patina)", pct: 100 };
}

/** Colour digits and symbols so similar-looking characters are easier to tell apart. */
function Highlighted({ value }: { value: string }) {
  return (
    <>
      {Array.from(value).map((ch, i) =>
        /[0-9]/.test(ch) ? (
          <span key={i} className="d">
            {ch}
          </span>
        ) : /[^A-Za-z0-9\s]/.test(ch) ? (
          <span key={i} className="s">
            {ch}
          </span>
        ) : (
          ch
        ),
      )}
    </>
  );
}

export function GeneratorPage() {
  const [mode, setMode] = useState<Mode>("password");
  const [pw, setPw] = useState<PasswordOptions>({ length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false });
  const [pp, setPp] = useState<PassphraseOptions>({ words: 5, separator: "-", capitalize: true, include_number: true });
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const regenerate = useCallback(() => {
    try {
      setValue(mode === "password" ? generatePassword(pw) : generatePassphrase(pp));
      setError(null);
    } catch (e) {
      setValue("");
      setError(`Could not generate a ${mode}: ${errorMessage(e)}`);
    }
  }, [mode, pw, pp]);

  useEffect(regenerate, [regenerate]);

  const bits = !value ? 0 : mode === "password" ? estimateBits(value) : pp.words * BITS_PER_WORD;
  const s = strength(bits);
  const enabledClasses = CHAR_CLASSES.filter((c) => pw[c.key]).length;
  const noun = mode === "password" ? "Password" : "Passphrase";

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <h1>Generator</h1>
          <p>Create a strong password or an easy-to-type passphrase. Everything is generated in this browser.</p>
        </header>

        <div className="segmented" role="group" aria-label="What to generate">
          <button type="button" aria-pressed={mode === "password"} onClick={() => setMode("password")}>
            Password
          </button>
          <button type="button" aria-pressed={mode === "passphrase"} onClick={() => setMode("passphrase")}>
            Passphrase
          </button>
        </div>

        <section className="card" aria-label={`Generated ${mode}`}>
          <output className="gen-output" aria-live="polite" aria-label={`Generated ${mode}`}>
            <Highlighted value={value} />
          </output>
          <div className="stack-s">
            <div className="meter" aria-hidden="true">
              <i style={{ width: `${value ? s.pct : 0}%`, background: s.color }} />
            </div>
            <span className="small muted">
              Strength: {s.label}, about {Math.round(bits)} bits of entropy
            </span>
          </div>
          <ErrorText error={error} />
          <div className="row">
            <button type="button" className="btn btn-brass" disabled={!value} onClick={() => copySecret(value, `${noun} copied`)}>
              <Icon name="copy" /> Copy {mode}
            </button>
            <button type="button" className="btn" onClick={regenerate}>
              <Icon name="dice" /> Regenerate
            </button>
          </div>
        </section>

        {mode === "password" ? (
          <section className="card" aria-labelledby="pw-opts">
            <h2 id="pw-opts" className="section-title">
              Password options
            </h2>
            <div className="field">
              <label htmlFor="gen-length" className="field-label">
                Length
              </label>
              <div className="range-row">
                <input
                  id="gen-length"
                  type="range"
                  min={8}
                  max={128}
                  value={pw.length}
                  onChange={(e) => setPw({ ...pw, length: Number(e.target.value) })}
                />
                <input
                  className="input mono"
                  type="number"
                  min={8}
                  max={128}
                  aria-label="Length in characters"
                  value={pw.length}
                  onChange={(e) => {
                    const n = Number(e.target.value);
                    if (Number.isFinite(n)) setPw({ ...pw, length: Math.min(128, Math.max(8, Math.round(n))) });
                  }}
                />
              </div>
            </div>
            <div className="check-grid">
              {CHAR_CLASSES.map((c) => (
                <label key={c.key} className="check">
                  <input
                    type="checkbox"
                    checked={pw[c.key]}
                    disabled={pw[c.key] && enabledClasses === 1}
                    onChange={(e) => setPw({ ...pw, [c.key]: e.target.checked })}
                  />
                  <span>{c.label}</span>
                </label>
              ))}
              <label className="check">
                <input type="checkbox" checked={pw.avoid_ambiguous} onChange={(e) => setPw({ ...pw, avoid_ambiguous: e.target.checked })} />
                <span>Avoid look-alike characters (I, l, 1, O, 0, o)</span>
              </label>
            </div>
            {enabledClasses === 1 && <p className="small muted">At least one character type stays on.</p>}
          </section>
        ) : (
          <section className="card" aria-labelledby="pp-opts">
            <h2 id="pp-opts" className="section-title">
              Passphrase options
            </h2>
            <div className="field">
              <label htmlFor="gen-words" className="field-label">
                Number of words
              </label>
              <div className="range-row">
                <input id="gen-words" type="range" min={3} max={20} value={pp.words} onChange={(e) => setPp({ ...pp, words: Number(e.target.value) })} />
                <input
                  className="input mono"
                  type="number"
                  min={3}
                  max={20}
                  aria-label="Number of words"
                  value={pp.words}
                  onChange={(e) => {
                    const n = Number(e.target.value);
                    if (Number.isFinite(n)) setPp({ ...pp, words: Math.min(20, Math.max(3, Math.round(n))) });
                  }}
                />
              </div>
            </div>
            <label className="field" style={{ maxWidth: 260 }}>
              <span>Separator</span>
              <select className="select" value={pp.separator} onChange={(e) => setPp({ ...pp, separator: e.target.value })}>
                {SEPARATORS.map((s) => (
                  <option key={s.label} value={s.value}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="check-grid">
              <label className="check">
                <input type="checkbox" checked={pp.capitalize} onChange={(e) => setPp({ ...pp, capitalize: e.target.checked })} />
                <span>Capitalize each word</span>
              </label>
              <label className="check">
                <input type="checkbox" checked={pp.include_number} onChange={(e) => setPp({ ...pp, include_number: e.target.checked })} />
                <span>Include a number</span>
              </label>
            </div>
            <p className="small muted">Words come from the EFF large wordlist, about 12.9 bits each.</p>
          </section>
        )}
      </div>
    </div>
  );
}
