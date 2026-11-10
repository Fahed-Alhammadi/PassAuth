import { useState } from "react";
import { downloadEmergencyKit, printEmergencyKit } from "../lib/kit";
import { isDesktop } from "../lib/platform";
import { ActionRow } from "./ui";

/** The ways to save the Emergency Kit, as one grouped card; each row shows when it has been used. */
export function KitActions({ email, secretKey, onSaved }: { email: string; secretKey: string | null; onSaved?: () => void }) {
  const [done, setDone] = useState<{ download?: boolean; print?: boolean }>({});
  const kit = { email, secretKey };
  const contents = secretKey ? "Server address, email and Secret Key" : "Server address and email";
  return (
    <div className="choices">
      <ActionRow
        icon="download"
        title="Download Emergency Kit"
        sub={`${contents} in one file`}
        done={done.download ? "Downloaded. Keep the file somewhere safe." : undefined}
        onClick={() => {
          downloadEmergencyKit(kit);
          setDone((d) => ({ ...d, download: true }));
          onSaved?.();
        }}
      />
      {/* The desktop WebView can't print; its download already saves the file. */}
      {!isDesktop() && (
        <ActionRow
          icon="printer"
          title="Print Emergency Kit"
          sub="With a line to write your master password on"
          done={done.print ? "Sent to your printer" : undefined}
          onClick={() => {
            printEmergencyKit(kit);
            setDone((d) => ({ ...d, print: true }));
            onSaved?.();
          }}
        />
      )}
    </div>
  );
}
