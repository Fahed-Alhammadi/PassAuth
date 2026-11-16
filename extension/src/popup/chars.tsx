/**
 * A password shown character by character: digits and symbols get their own colour and a mark that doesn't rely on
 * colour (digits underlined, symbols on a tinted box), so "O" and "0" or "l" and "1" can be told apart.
 */
import { Modal } from "@web/components/ui";

export type CharKind = "letter" | "digit" | "symbol" | "space";

export function charKind(ch: string): CharKind {
  if (/\p{Nd}/u.test(ch)) return "digit";
  if (/\p{L}/u.test(ch)) return "letter";
  if (/\s/u.test(ch)) return "space";
  return "symbol";
}

/** Characters as the user sees them (a surrogate pair or an emoji with its modifiers stays one). */
export const graphemes = (value: string): string[] => {
  const Seg = (Intl as { Segmenter?: typeof Intl.Segmenter }).Segmenter;
  return Seg ? [...new Seg(undefined, { granularity: "grapheme" }).segment(value)].map((s) => s.segment) : [...value];
};

export function PasswordChars({ value }: { value: string }) {
  return (
    <span className="pw-chars">
      {graphemes(value).map((ch, n) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: the characters of one fixed value; the same character can repeat
        <span key={n} className={`ch-${charKind(ch)}`}>
          {ch === " " ? "␣" : ch}
        </span>
      ))}
    </span>
  );
}

/** The password in large type, one numbered cell per character (for reading it out or typing it on another device). */
export function LargeType({ title, value, onClose }: { title: string; value: string; onClose: () => void }) {
  const chars = graphemes(value);
  return (
    <Modal title="Large type" subtitle={title} icon="eye" onClose={onClose}>
      <ol className="large-type" aria-label={`${chars.length} characters`}>
        {chars.map((ch, n) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the characters of one fixed value; the same character can repeat
          <li key={n} className={`ch-${charKind(ch)}`}>
            <span className="glyph">{ch === " " ? "␣" : ch}</span>
            <span className="num" aria-hidden="true">
              {n + 1}
            </span>
          </li>
        ))}
      </ol>
      <p className="small muted">Digits are underlined; symbols sit on a tinted box.</p>
    </Modal>
  );
}
