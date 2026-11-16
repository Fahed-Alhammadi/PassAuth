/**
 * Generator tab: the web vault's options (@web/components/GeneratorOptions: character types, look-alikes, passphrase
 * words, separator…), remembered in chrome.storage.local `generatorOptions` for the item editor's dice, the
 * right-click menu, the shortcut and the inline menu. Generating is debounced, and each request carries a number so a
 * late answer can't replace a newer value (C22).
 */

import { GeneratorOptions } from "@web/components/GeneratorOptions";
import { Icon, SheetActions } from "@web/components/ui";
import { type GeneratorSettings, generatorRequest } from "@web/lib/generator";
import { useEffect, useRef, useState } from "react";
import { readGeneratorSettings } from "../shared/generator-settings";
import { callPopup } from "../shared/protocol";
import { GENERATOR_OPTIONS_KEY } from "../shared/storage-keys";
import { PasswordChars } from "./chars";
import { type Ctx, msg } from "./ctx";
import { Account, Page, PopOut } from "./shell";

/** Generate with `s` through the background (the core). */
export function generateWith(s: GeneratorSettings): Promise<string> {
  const req = generatorRequest(s);
  return callPopup("generate", { mode: req.mode, options: { ...req.options } });
}

/** The item editor's dice: the generator's saved options. */
export async function generateWithSaved(): Promise<string> {
  return generateWith(await readGeneratorSettings());
}

let saveTimer: ReturnType<typeof setTimeout> | undefined;
/** Remember the options (a moment after the last change: a slider sends many). */
function saveSettings(s: GeneratorSettings) {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => void chrome.storage.local.set({ [GENERATOR_OPTIONS_KEY]: s }).catch(() => {}), 300);
}

export function GeneratorPage({ ctx }: { ctx: Ctx }) {
  const [settings, setSettings] = useState<GeneratorSettings | null>(null);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  // The newest request's number: an answer to an older one is dropped.
  const latest = useRef(0);
  const [again, setAgain] = useState(0);

  useEffect(() => {
    readGeneratorSettings().then(setSettings, () => setSettings(null));
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `again` asks for a new value with the same options
  useEffect(() => {
    if (!settings) return;
    const n = ++latest.current;
    const t = setTimeout(() => {
      generateWith(settings).then(
        (v) => {
          if (n !== latest.current) return;
          setValue(v);
          setError(null);
        },
        (e) => n === latest.current && setError(msg(e)),
      );
    }, 120);
    return () => clearTimeout(t);
  }, [settings, again]);

  const change = (next: GeneratorSettings) => {
    setSettings(next);
    saveSettings(next);
  };
  const mode = settings?.mode ?? "password";

  return (
    <Page
      title="Generator"
      brand
      actions={
        <>
          <PopOut />
          <Account state={ctx.state} onChange={ctx.reload} onSignOut={ctx.signOut} />
        </>
      }
    >
      {settings && (
        <div className="card-box gen">
          {/* biome-ignore lint/a11y/useSemanticElements: a segmented control; a fieldset would bring its own border and spacing */}
          <div className="segmented" role="group" aria-label="What to generate">
            <button type="button" aria-pressed={mode === "password"} onClick={() => change({ ...settings, mode: "password" })}>
              Password
            </button>
            <button type="button" aria-pressed={mode === "passphrase"} onClick={() => change({ ...settings, mode: "passphrase" })}>
              Passphrase
            </button>
          </div>
          <output className="gen-out" aria-live="polite" aria-label={`Generated ${mode}`}>
            <PasswordChars value={value} />
          </output>
          {error && <p className="small danger-text">{error}</p>}
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={() => setAgain((a) => a + 1)}>
                <Icon name="sync" size={16} /> Regenerate
              </button>
            }
          >
            <button type="button" className="btn btn-primary btn-block" disabled={!value} onClick={() => void ctx.copy({ text: value }, mode === "password" ? "Password" : "Passphrase")}>
              <Icon name="copy" /> Copy {mode}
            </button>
          </SheetActions>
          <hr />
          <GeneratorOptions value={settings} onChange={change} />
        </div>
      )}
    </Page>
  );
}
