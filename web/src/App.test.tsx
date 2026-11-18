/**
 * The web vault's addresses (user rule, 2026-11-18): sign-in lives at the site root, `/login` only redirects there, a
 * signed-out visit to any app page lands on the root with the page to return to, signed in the root opens the vault.
 * Rendered once on the server side of React (no DOM here): `<Navigate>` is replaced by a marker that shows where a
 * route sends the visitor and with which state, so every guard's decision is read off the markup.
 */
import { renderToString } from "react-dom/server";
import { createMemoryRouter, matchRoutes, MemoryRouter, RouterProvider } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
  // Before the app's modules load: they read the address and the stores when imported.
  const none = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  Object.assign(globalThis, { location: new URL("https://vault.example.test/"), localStorage: none, sessionStorage: none, history: { replaceState: () => {} } });
  return { status: "logged-out" as string };
});

vi.mock("react-router", async (importOriginal) => {
  const orig = await importOriginal<typeof import("react-router")>();
  return {
    ...orig,
    Navigate: (p: { to: string; replace?: boolean; state?: unknown }) => <i data-navigate={p.to} data-replace={String(!!p.replace)} data-state={JSON.stringify(p.state ?? null)} />,
  };
});

vi.mock("./lib/vault", async (importOriginal) => {
  const orig = await importOriginal<typeof import("./lib/vault")>();
  const state = () => ({ ...orig.getState(), status: h.status });
  return { ...orig, useVault: state, getState: state, holdsKeys: () => false, lastEmail: () => "" };
});


import { LoginRedirect, RequireUnlocked, RootPage, routes } from "./App";
import { HOME_PATH, SIGN_IN_PATH, afterSignIn, signedOutState } from "./lib/routes";
import { LoginPage } from "./pages/Login";

/** The markup of the app at `path` for a visitor in `status`. */
function at(path: string, status: string, state?: unknown): string {
  h.status = status;
  const router = createMemoryRouter(routes, { initialEntries: [{ pathname: path, state }] });
  return renderToString(<RouterProvider router={router} />);
}

/** Where the rendered route sends the visitor (null: it stays), with the state it passes on. */
function sent(html: string): { to: string; replace: boolean; state: unknown } | null {
  const m = /<i data-navigate="([^"]*)" data-replace="([^"]*)" data-state="([^"]*)"/.exec(html);
  if (!m) return null;
  const unescape = (t: string) => t.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, "&");
  return { to: unescape(m[1]), replace: m[2] === "true", state: JSON.parse(unescape(m[3])) };
}

const SIGN_IN_FORM = /Master password/;
const APP_PAGES = ["/vault", "/vault/all", "/vault/all/some-item", "/generator", "/health", "/sends", "/emergency/abc", "/import", "/export", "/settings", "/settings/security"];

beforeEach(() => {
  h.status = "logged-out";
});

describe("the sign-in page lives at the site root", () => {
  it("signed out, `/` IS the sign-in page: no redirect, and no route serves it anywhere else", () => {
    const html = at("/", "logged-out");
    expect(sent(html)).toBeNull();
    expect(html).toMatch(SIGN_IN_FORM);
    expect(SIGN_IN_PATH).toBe("/");
    expect(matchRoutes(routes, "/")?.at(-1)?.route.element).toMatchObject({ type: RootPage });
  });

  it("`/login` only redirects to `/` (old links), keeping where the visitor came from", () => {
    for (const status of ["logged-out", "locked", "unlocked", "loading"]) {
      const html = at("/login", status, { from: "/settings/security" });
      expect(html).not.toMatch(SIGN_IN_FORM);
      expect(sent(html)).toEqual({ to: "/", replace: true, state: { from: "/settings/security" } });
    }
    expect(sent(at("/login", "logged-out"))).toEqual({ to: "/", replace: true, state: null });
    expect(matchRoutes(routes, "/login")?.at(-1)?.route.element).toMatchObject({ type: LoginRedirect });
  });

  it("signed in (locked or unlocked), `/` opens the vault", () => {
    for (const status of ["locked", "unlocked", "two-step"]) expect(sent(at("/", status))).toMatchObject({ to: "/vault", replace: true });
    // While the session is still being looked up: neither the sign-in form nor a redirect.
    const loading = at("/", "loading");
    expect(sent(loading)).toBeNull();
    expect(loading).toMatch(/Loading PassAuth/);
    expect(loading).not.toMatch(SIGN_IN_FORM);
    const down = at("/", "unreachable");
    expect(sent(down)).toBeNull();
    expect(down).not.toMatch(SIGN_IN_FORM);
  });
});

describe("signed out on an app page (no session, or after Log out)", () => {
  it("every app page lands on `/` and carries the page to return to", () => {
    for (const path of APP_PAGES) {
      const html = at(path, "logged-out");
      expect(html).not.toMatch(SIGN_IN_FORM);
      expect(sent(html)).toEqual({ to: "/", replace: true, state: { from: path } });
      // Each of them is behind the guard that does this, so Log out on any of them moves the address to `/`.
      expect(matchRoutes(routes, path)?.[0].route.element).toMatchObject({ type: RequireUnlocked });
    }
  });

  it("an unknown address goes to the vault, and from there to `/` like any app page", () => {
    expect(sent(at("/nowhere/at/all", "logged-out"))).toMatchObject({ to: "/vault", replace: true });
    expect(sent(at("/vault", "logged-out"))).toEqual({ to: "/", replace: true, state: { from: "/vault" } });
  });

  it("locked, an app page keeps its address (the unlock screen shows in place)", () => {
    const html = at("/settings/security", "locked");
    expect(sent(html)).toBeNull();
    expect(html).not.toMatch(/Loading PassAuth/);
  });

  it("the other public pages are where they were", () => {
    for (const path of ["/register", "/verify-email", "/admin", "/admin/users", "/send/abc"]) {
      const match = matchRoutes(routes, path)?.at(-1)?.route;
      expect(match?.path).not.toBe("*");
      expect(match?.element).not.toMatchObject({ type: RequireUnlocked });
      expect(match?.element).not.toMatchObject({ type: RootPage });
    }
  });
});

describe("after signing in", () => {
  /** The sign-in page once the account is open, reached with `state`. */
  function signedIn(state: unknown) {
    h.status = "unlocked";
    return sent(
      renderToString(
        <MemoryRouter initialEntries={[{ pathname: "/", state }]}>
          <LoginPage />
        </MemoryRouter>,
      ),
    );
  }

  it("the visitor returns to the page that sent them to `/`", () => {
    expect(signedIn(signedOutState("/settings/security"))).toMatchObject({ to: "/settings/security", replace: true });
    expect(signedIn(signedOutState("/vault/all/some-item"))).toMatchObject({ to: "/vault/all/some-item" });
  });

  it("without one (or with the sign-in page itself, or anything outside the app) it is the vault", () => {
    for (const state of [null, undefined, {}, { from: "/" }, { from: "/login" }, { from: "/login/" }, { from: "//evil.example" }, { from: "https://evil.example/" }, { from: "/\\evil.example" }, { from: 5 }])
      expect(signedIn(state)).toMatchObject({ to: "/vault", replace: true });
  });

  it("`afterSignIn` (the rule itself)", () => {
    expect(HOME_PATH).toBe("/vault");
    expect(afterSignIn({ from: "/settings/security" })).toBe("/settings/security");
    expect(afterSignIn({ from: "/settings/vaults?x=1#y" })).toBe("/settings/vaults?x=1#y");
    expect(afterSignIn({ from: "/" })).toBe("/vault");
    expect(afterSignIn({ from: "/?next=1" })).toBe("/vault");
    expect(afterSignIn({ from: "/login" })).toBe("/vault");
    expect(afterSignIn({ from: "settings" })).toBe("/vault");
    expect(afterSignIn("/settings")).toBe("/vault");
    expect(afterSignIn(null)).toBe("/vault");
  });
});
