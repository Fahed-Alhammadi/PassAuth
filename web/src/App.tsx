import { useEffect, useState } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router";
import { LogoMark } from "./components/Logo";
import { SheetActions, ToastHost } from "./components/ui";
import { SERVER_UPDATE_NEEDED, usePolicies } from "./lib/api";
import { getDesktop } from "./lib/platform";
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

/** Routes that need an unlocked vault. */
function RequireUnlocked() {
  const { status } = useVault();
  const loc = useLocation();
  const { maxVaultTimeoutMinutes } = usePolicies();
  // The keys may stay in memory behind the two-step screen: the idle lock covers them there too.
  useAutoLock(status === "unlocked" || (status === "two-step" && holdsKeys()), webLockMinutes(maxVaultTimeoutMinutes));
  if (status === "logged-out") return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
  if (status === "two-step") return <TwoStepRequiredPage />;
  if (status === "locked") return <UnlockPage />;
  if (status === "unreachable") return <Unreachable />;
  if (status === "loading")
    return (
      <div className="splash" role="status">
        <LogoMark size={56} />
        <span>Loading PassAuth…</span>
      </div>
    );
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

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  { path: "/register", element: <RegisterPage /> },
  { path: "/verify-email", element: <VerifyEmailPage /> },
  { path: "/admin", element: <AdminPage /> },
  { path: "/admin/:section", element: <AdminPage /> },
  // Public: anyone with a Send's link opens it here, with or without an account (never signed in for it).
  { path: "/send/:id", element: <SendViewPage /> },
  {
    element: <RequireUnlocked />,
    children: [
      {
        element: <Shell />,
        children: [
          { index: true, element: <Navigate to="/vault" replace /> },
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
]);

export function App() {
  return (
    <>
      <RouterProvider router={router} />
      <ToastHost />
    </>
  );
}
