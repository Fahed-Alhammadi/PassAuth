/** The admin page's Features card shows the push notification switch and the relay address. */
import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  const none = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  Object.assign(globalThis, { location: new URL("https://vault.example.com/admin/features"), localStorage: none, sessionStorage: none });
});

import { SettingsCard } from "./Admin";

const SETTINGS = {
  log_level: "info",
  log_levels: ["info"],
  icons: true,
  signups_verify: false,
  smtp: null,
  breach_check: true,
  push_enabled: true,
  push_relay_url: "https://push.example.com",
  push_relay_default: "https://passauth-push.uaealhammadi.com",
};

const card = (settings: Record<string, unknown>) =>
  renderToString(<SettingsCard only={["icons", "breach", "push"]} settings={settings as never} call={async () => undefined as never} reload={async () => {}} />);

describe("admin features card", () => {
  it("shows the push switch, the relay address and what the relay sees", () => {
    const html = card(SETTINGS);
    expect(html).toContain("Push notifications for sign-in requests");
    expect(html).toContain("Push relay address");
    expect(html).toContain('value="https://push.example.com"');
    expect(html).toContain("only sees the phone&#x27;s push token and when to notify");
    expect(html).toContain("https://passauth-push.uaealhammadi.com");
    expect(html).toContain("PASSAUTH_PUSH");
  });
  it("leaves push out for servers that don't report it", () => {
    const { push_enabled: _a, push_relay_url: _b, push_relay_default: _c, ...older } = SETTINGS;
    const html = card(older);
    expect(html).not.toContain("Push notifications for sign-in requests");
    expect(html).not.toContain("PASSAUTH_PUSH");
  });
});
