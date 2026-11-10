/**
 * Parts of the "decision sheet" for PassAuth's own windows (the passkey
 * confirmation), top to bottom: brand bar, context row (what is being decided,
 * and for which site), one card of choices, verification, then one primary
 * action with the quiet ones on a row beneath it.
 *
 * The look is the shared one in @web/styles/app.css ("decision sheet"), the
 * same classes the web vault's dialogs use; dialogs inside the popup use the
 * shared <Modal> / <ConfirmDialog> directly.
 */
import { useId, type ReactNode } from "react";
import { LogoMark } from "@web/components/Logo";

/** Logo and name. The window has its own close button, so there is none here. */
export function BrandBar() {
  return (
    <div className="sheet-bar">
      <span className="sheet-brand">
        <span aria-hidden="true" className="row">
          <LogoMark size={18} />
        </span>
        PassAuth
      </span>
    </div>
  );
}

/** What is being decided (sentence case) and the site it is about. */
export function Context({ icon, title, sub }: { icon: ReactNode; title: string; sub?: ReactNode }) {
  return (
    <div className="sheet-context">
      {icon}
      <div className="grow">
        <h1 className="sheet-title">{title}</h1>
        {sub && <p className="sheet-sub">{sub}</p>}
      </div>
    </div>
  );
}

/** A row's tile: the first letter of `name`, or an icon. */
export function Tile({ name, children }: { name?: string; children?: ReactNode }) {
  return (
    <span className="tile" aria-hidden="true">
      {children ?? (name?.trim()[0] ?? "?").toUpperCase()}
    </span>
  );
}

export interface Choice {
  id: string;
  title: string;
  sub?: string;
  icon: ReactNode;
}

function ChoiceText({ choice }: { choice: Choice }) {
  return (
    <>
      {choice.icon}
      <span className="choice-text">
        <span className="choice-title">{choice.title}</span>
        {choice.sub && <span className="choice-sub">{choice.sub}</span>}
      </span>
    </>
  );
}

/**
 * One grouped card of rows to pick from. Native radio buttons: arrow keys move
 * the selection, Tab enters at the selected row, screen readers announce
 * "radio, 2 of 3"; the selected row is tinted and its radio is filled (never
 * colour alone).
 */
export function Choices({
  label,
  options,
  value,
  onChange,
  disabled,
  compact,
}: {
  label: string;
  options: Choice[];
  value: string | undefined;
  onChange: (id: string) => void;
  disabled?: boolean;
  compact?: boolean;
}) {
  const name = useId();
  return (
    <fieldset className="choice-group" disabled={disabled}>
      <legend className="field-label">{label}</legend>
      <div className={compact ? "choices choices-compact" : "choices"}>
        {options.map((o) => (
          <label key={o.id} className="choice">
            <ChoiceText choice={o} />
            <input type="radio" name={name} value={o.id} checked={value === o.id} onChange={() => onChange(o.id)} />
          </label>
        ))}
      </div>
    </fieldset>
  );
}

/** The same card with a single row and nothing to choose (e.g. the only passkey for a site). */
export function OnlyChoice({ label, choice }: { label: string; choice: Choice }) {
  return (
    <div className="choices" role="group" aria-label={label}>
      <div className="choice choice-static">
        <ChoiceText choice={choice} />
      </div>
    </div>
  );
}
