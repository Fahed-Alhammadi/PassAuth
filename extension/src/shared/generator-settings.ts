/**
 * The generator's saved options (chrome.storage.local `generatorOptions`): written by the popup's generator, read by
 * the item editor's dice, the right-click menu, the "Copy a strong password" shortcut and the inline menu.
 */
import { DEFAULT_GENERATOR_SETTINGS, type GeneratorSettings } from "@web/lib/generator";
import { GENERATOR_OPTIONS_KEY } from "./storage-keys";

/** Saved options as stored (possibly by an older version, or damaged): missing parts take the defaults. `generatorRequest` tidies the values. */
export function tidyGeneratorSettings(stored: unknown): GeneratorSettings {
  const s = stored && typeof stored === "object" ? (stored as Partial<GeneratorSettings>) : {};
  const obj = (v: unknown) => (v && typeof v === "object" ? v : {});
  return {
    mode: s.mode === "passphrase" ? "passphrase" : "password",
    password: { ...DEFAULT_GENERATOR_SETTINGS.password, ...obj(s.password) },
    passphrase: { ...DEFAULT_GENERATOR_SETTINGS.passphrase, ...obj(s.passphrase) },
  };
}

export async function readGeneratorSettings(): Promise<GeneratorSettings> {
  const got: Record<string, unknown> = await chrome.storage.local.get(GENERATOR_OPTIONS_KEY).catch(() => ({}));
  return tidyGeneratorSettings(got[GENERATOR_OPTIONS_KEY]);
}
