import { useCallback, useEffect, useState } from "react";
import { clientName } from "../lib/platform";
import { GeneratorOptions } from "../components/GeneratorOptions";
import { copySecret, ErrorText, Icon } from "../components/ui";
import { errorMessage } from "../lib/api";
import { DEFAULT_GENERATOR_SETTINGS, generatorRequest, passphraseBits, type GeneratorMode } from "../lib/generator";
import { WEAK_BITS } from "../lib/health";
import { estimateBits, generatePassphrase, generatePassword } from "../lib/vault";
import "../styles/tools.css";

function strength(bits: number): { label: string; color: string; pct: number } {
  if (bits < WEAK_BITS) return { label: "Weak", color: "var(--danger)", pct: 25 };
  if (bits < 60) return { label: "Fair", color: "var(--accent)", pct: 50 };
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
  const [settings, setSettings] = useState(DEFAULT_GENERATOR_SETTINGS);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const { mode } = settings;
  const setMode = (m: GeneratorMode) => setSettings((x) => ({ ...x, mode: m }));

  const regenerate = useCallback(() => {
    const req = generatorRequest(settings);
    try {
      setValue(req.mode === "password" ? generatePassword(req.options) : generatePassphrase(req.options));
      setError(null);
    } catch (e) {
      setValue("");
      setError(`Could not generate a ${req.mode}: ${errorMessage(e)}`);
    }
  }, [settings]);

  useEffect(regenerate, [regenerate]);

  const bits = !value ? 0 : mode === "password" ? estimateBits(value) : passphraseBits(settings.passphrase.words);
  const s = strength(bits);
  const noun = mode === "password" ? "Password" : "Passphrase";

  return (
    <div className="page">
      <div className="page-inner">
        <header className="page-head">
          <h1>Generator</h1>
          <p>Create a strong password or an easy-to-type passphrase. Everything is generated in {clientName()}.</p>
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
          <div className="card-actions">
            <button type="button" className="btn btn-accent" disabled={!value} onClick={() => copySecret(value, `${noun} copied`)}>
              <Icon name="copy" /> Copy {mode}
            </button>
            <button type="button" className="btn" onClick={regenerate}>
              <Icon name="dice" /> Regenerate
            </button>
          </div>
        </section>

        <section className="card" aria-labelledby="gen-opts">
          <h2 id="gen-opts">{mode === "password" ? "Password options" : "Passphrase options"}</h2>
          <GeneratorOptions value={settings} onChange={setSettings} />
        </section>
      </div>
    </div>
  );
}
