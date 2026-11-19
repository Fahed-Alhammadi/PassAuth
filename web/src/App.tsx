import { useEffect, useRef, useState } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation, type RouteObject } from "react-router";
import { LogoMark } from "./components/Logo";
import { SheetActions, ToastHost } from "./components/ui";
import { SERVER_UPDATE_NEEDED, usePolicies } from "./lib/api";
import { getDesktop } from "./lib/platform";
import { SIGN_IN_PATH, signedOutState } from "./lib/routes";
import { webLockMinutes } from "./lib/policies";
import { server } from "./lib/server";
import { boot, holdsKeys, lock, logout, useVault } from "./lib/vault";
import { AdminPage } from "./pages/Admin";
import { ExportPage } from "./pages/Export";
import { ImportPage } from "./pages/Import";
import { LoginPage } from "./pages/Login";
import { RegisterPage } from "./pages/Register";
import { SettingsPage } from "./pages/Settings";
import { Shell } from "./pages/Shell";
import { UnlockPage } from "./pages/Unlock";
import { VaultPage } from "./pages/Vault";
import { VerifyEmailPage } from "./pages/VerifyEmail";
import { GeneratorPage } from "./pages/Generator";
import { HealthPage } from "./pages/Health";
import { TwoStepRequiredPage } from "./pages/TwoStepRequired";
import { SendsPage } from "./pages/Sends";
import { SendViewPage } from "./pages/SendView";
import { EmergencyVaultPage } from "./pages/Emergency";
import { TwoStepKeyDonePage, TwoStepKeyPage } from "./pages/TwoStepKey";
import { KEY_DONE_PATH, KEY_PAGE_PATH } from "./lib/key-page";

/**
 * The site root. Signed out, it is the sign-in page: the web vault's sign-in lives at `https://<server>/`, never at
 * `/login`. Signed in (locked or unlocked), it opens the vault, as any unknown address does. Once the sign-in page is
 * up it stays until it leaves by itself, so the steps after the password (a two-step code, another device's approval)
 * aren't cut off when the account opens, and it returns to the page that sent the visitor here (`state.from`).
 */
export function RootPage() {
  const { status } = useVault();
  const loc = useLocation();
  const signingIn = useRef(false);
  if (status === "logged-out") signingIn.current = true;
  if (signingIn.current) return <LoginPage />;
  if (status === "unreachable") return <Unreachable />;
  if (status === "loading") return <Splash />;
  return <Navigate to="/vault" replace state={loc.state} />;
}

/** `/login`, the sign-in page's address before: old links and bookmarks go to the root, with where they came from. */
export function LoginRedirect() {
  const loc = useLocation();
  return <Navigate to={SIGN_IN_PATH} replace state={loc.state} />;
}

function Splash() {
  return (
    <div className="splash" role="status">
      <LogoMark size={56} />
      <span>Loading PassAuth…</span>
    </div>
  );
}

/**
 * Routes that need an unlocked vault. Signed out (a visit without a session, or after Log out), the address becomes
 * the root, where the sign-in page is, and sign-in returns to the page asked for.
 */
export function RequireUnlocked() {
  const { status } = useVault();
  const loc = useLocation();
  const { maxVaultTimeoutMinutes } = usePolicies();
  // The keys may stay in memory behind the two-step screen: the idle lock covers them there too.
  useAutoLock(status === "unlocked" || (status === "two-step" && holdsKeys()), webLockMinutes(maxVaultTimeoutMinutes));
  if (status === "logged-out") return <Navigate to={SIGN_IN_PATH} replace state={signedOutState(loc.pathname)} />;
  if (status === "two-step") return <TwoStepRequiredPage />;
  if (status === "locked") return <UnlockPage />;
  if (status === "unreachable") return <Unreachable />;
  if (status === "loading") return <Splash />;
  return <Outlet />;
}

/**
 * The server couldn't be reached at startup, or it answered but is too old for this app (`serverOutdated`): keep the
 * session and offer a retry.
 */
function Unreachable() {
  const [busy, setBusy] = useState(false);
  const { serverOutdated } = useVault();
  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          {serverOutdated ? (
            <>
              <h1>{SERVER_UPDATE_NEEDED}</h1>
              <p className="muted">
                {server.host()} runs a version of PassAuth that is too old for this app, so your vault wasn't loaded. Ask the server's admin to update it, then try
                again. You're still signed in.
              </p>
            </>
          ) : (
            <>
              <h1>Can't reach your PassAuth server</h1>
              <p className="muted">
                {server.host()} isn't answering. Check your connection or VPN, or wait for the server to finish restarting. You're still signed in.
              </p>
            </>
          )}
        </div>
        <div className="auth-panel stack">
          <SheetActions
            quiet={
              <button type="button" className="btn btn-text" onClick={logout}>
                Sign out
              </button>
            }
          >
            <button
              type="button"
              className="btn btn-accent btn-block"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                await boot();
                setBusy(false);
              }}
            >
              {busy ? "Trying again…" : "Try again"}
            </button>
          </SheetActions>
        </div>
      </div>
    </main>
  );
}

/**
 * Lock after `minutes` without interaction (this tab only): 15, or the server's longest vault timeout when that is
 * shorter (policy). The desktop app's own vault timeout replaces it.
 */
function useAutoLock(active: boolean, minutes: number) {
  useEffect(() => {
    if (!active || getDesktop()?.vaultTimeout) return;
    const ms = minutes * 60_000;
    const idleLock = () => lock(false);
    let timer = window.setTimeout(idleLock, ms);
    const reset = () => {
      clearTimeout(timer);
      timer = window.setTimeout(idleLock, ms);
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [active, minutes]);
}

// Links from before 0.2.2 used hash routes (/#/admin); keep them working.
if (location.hash.startsWith("#/")) history.replaceState(null, "", location.hash.slice(1));

/** The web vault's addresses (the desktop app uses the same ones inside its window). */
export const routes: RouteObject[] = [
  // Sign-in lives at the root; `/login` only redirects there.
  { path: SIGN_IN_PATH, element: <RootPage /> },
  { path: "/login", element: <LoginRedirect /> },
  { path: "/register", element: <RegisterPage /> },
  { path: "/verify-email", element: <VerifyEmailPage /> },
  { path: "/admin", element: <AdminPage /> },
  { path: "/admin/:section", element: <AdminPage /> },
  // Public: anyone with a Send's link opens it here, with or without an account (never signed in for it).
  { path: "/send/:id", element: <SendViewPage /> },
  // Public: an app (desktop, extension, phone) opens the server's key page in a browser for a security key's two-step login.
  { path: KEY_PAGE_PATH, element: <TwoStepKeyPage /> },
  { path: KEY_DONE_PATH, element: <TwoStepKeyDonePage /> },
  {
    element: <RequireUnlocked />,
    children: [
      {
        element: <Shell />,
        children: [
          { path: "/vault", element: <VaultPage /> },
          { path: "/vault/:filter", element: <VaultPage /> },
          { path: "/vault/:filter/:itemId", element: <VaultPage /> },
          { path: "/generator", element: <GeneratorPage /> },
          { path: "/health", element: <HealthPage /> },
          { path: "/sends", element: <SendsPage /> },
          { path: "/emergency/:id", element: <EmergencyVaultPage /> },
          { path: "/import", element: <ImportPage /> },
          { path: "/export", element: <ExportPage /> },
          { path: "/settings", element: <SettingsPage /> },
          { path: "/settings/:tab", element: <SettingsPage /> },
        ],
      },
    ],
  },
  { path: "*", element: <Navigate to="/vault" replace /> },
];

/** Made at the first render (it reads the browser's address), so the route table above can be loaded without a page. */
let router: ReturnType<typeof createBrowserRouter> | null = null;

export function App() {
  router ??= createBrowserRouter(routes);
  return (
    <>
      <RouterProvider router={router} />
      <ToastHost />
    </>
  );
}
