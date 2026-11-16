/**
 * Generator settings and the arguments for the core generator, shared by the web vault and the extension. No imports:
 * safe for the extension's background worker. The options UI is `components/GeneratorOptions.tsx`.
 */

export type GeneratorMode = "password" | "passphrase";

/** Mirrors `passauth_core::generator::PasswordOptions`. */
export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}

/** Mirrors `passauth_core::generator::PassphraseOptions`. */
export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

/** What to generate, and the options of both kinds (switching back and forth keeps each kind's choices). */
export interface GeneratorSettings {
  mode: GeneratorMode;
  password: PasswordOptions;
  passphrase: PassphraseOptions;
}

/** The core's limits (it clamps to them too). */
export const PASSWORD_LENGTH = { min: 8, max: 128 } as const;
export const PASSPHRASE_WORDS = { min: 3, max: 20 } as const;

export const DEFAULT_GENERATOR_SETTINGS: GeneratorSettings = {
  mode: "password",
  password: { length: 20, lowercase: true, uppercase: true, digits: true, symbols: true, avoid_ambiguous: false },
  passphrase: { words: 5, separator: "-", capitalize: true, include_number: true },
};

export const SEPARATORS: { value: string; label: string }[] = [
  { value: "-", label: "Hyphen ( - )" },
  { value: ".", label: "Period ( . )" },
  { value: "_", label: "Underscore ( _ )" },
  { value: ",", label: "Comma ( , )" },
  { value: " ", label: "Space" },
  { value: "", label: "None" },
];

/** Entropy of a generated passphrase: words from the EFF large wordlist (7776 words) carry about 12.9 bits each. */
export const passphraseBits = (words: number) => words * 12.9;

/** `generatePassword(options)` or `generatePassphrase(options)` in the core; the extension's "generate" message has the same shape. */
export type GeneratorRequest = { mode: "password"; options: PasswordOptions } | { mode: "passphrase"; options: PassphraseOptions };

const whole = (n: unknown, min: number, max: number, fallback: number) =>
  typeof n === "number" && Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : fallback;

/**
 * The arguments for the core generator. Settings saved by an older version are tidied: missing options take their
 * defaults, numbers are rounded into range, at least one character type stays on, and only the separators offered
 * in `SEPARATORS` are used.
 */
export function generatorRequest(s: GeneratorSettings): GeneratorRequest {
  const d = DEFAULT_GENERATOR_SETTINGS;
  if (s.mode === "passphrase") {
    const p = { ...d.passphrase, ...s.passphrase };
    return {
      mode: "passphrase",
      options: {
        words: whole(p.words, PASSPHRASE_WORDS.min, PASSPHRASE_WORDS.max, d.passphrase.words),
        separator: SEPARATORS.some((x) => x.value === p.separator) ? p.separator : d.passphrase.separator,
        capitalize: !!p.capitalize,
        include_number: !!p.include_number,
      },
    };
  }
  const p = { ...d.password, ...s.password };
  const none = !p.lowercase && !p.uppercase && !p.digits && !p.symbols;
  return {
    mode: "password",
    options: {
      length: whole(p.length, PASSWORD_LENGTH.min, PASSWORD_LENGTH.max, d.password.length),
      lowercase: !!p.lowercase || none,
      uppercase: !!p.uppercase,
      digits: !!p.digits,
      symbols: !!p.symbols,
      avoid_ambiguous: !!p.avoid_ambiguous,
    },
  };
}
