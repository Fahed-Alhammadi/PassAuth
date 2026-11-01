/** Generator tab. */
import { useCallback, useEffect, useState } from "react";
import { send } from "../shared/messages";
import type { Ctx } from "./ctx";
import { Account, Page, PopOut } from "./shell";

export function GeneratorPage({ ctx }: { ctx: Ctx }) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [value, setValue] = useState("");
  const gen = useCallback(
    () => send<string>({ type: "generate", mode, options: mode === "password" ? { length } : { words: Math.max(3, Math.round(length / 4)) } }).then(setValue),
    [mode, length],
  );
  useEffect(() => void gen(), [gen]);
  return (
    <Page title="Generator" brand actions={<><PopOut /><Account state={ctx.state} onChange={ctx.reload} /></>}>
      <div className="card-box gen">
      <div className="segmented">
        <button aria-pressed={mode === "password"} onClick={() => setMode("password")}>
          Password
        </button>
        <button aria-pressed={mode === "passphrase"} onClick={() => setMode("passphrase")}>
          Passphrase
        </button>
      </div>
      <div className="gen-out">{value}</div>
      <label className="field">
        <span>{mode === "password" ? `Length: ${length}` : `Words: ${Math.max(3, Math.round(length / 4))}`}</span>
        <input type="range" min={mode === "password" ? 8 : 12} max={mode === "password" ? 64 : 40} value={length} onChange={(e) => setLength(+e.target.value)} />
      </label>
      <div className="row">
        <button className="btn btn-accent grow" onClick={() => ctx.copy({ text: value }, mode === "password" ? "Password" : "Passphrase")}>
          Copy
        </button>
        <button className="btn grow" onClick={gen}>
          Regenerate
        </button>
      </div>
      </div>
    </Page>
  );
}
