import { useEffect, useState } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router";
import { LogoMark } from "./components/Logo";
import { ToastHost } from "./components/ui";
import { server } from "./lib/server";
import { boot, lock, logout, useVault } from "./lib/vault";
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

const AUTO_LOCK_MS = 15 * 60 * 1000;

/** Routes that need an unlocked vault. */
function RequireUnlocked() {
  const { status } = useVault();
  const loc = useLocation();
  useAutoLock(status === "unlocked");
  if (status === "logged-out") return <Navigate to="/login" replace state={{ from: loc.pathname }} />;
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

/** The server couldn't be reached at startup: keep the session and offer a retry. */
function Unreachable() {
  const [busy, setBusy] = useState(false);
  return (
    <main className="auth">
      <div className="auth-card">
        <div className="auth-head">
          <LogoMark size={56} />
          <h1>Can't reach your PassAuth server</h1>
          <p className="muted">
            {server.host()} isn't answering. Check your connection or VPN, or wait for the server to finish restarting. You're still signed in.
          </p>
        </div>
        <div className="auth-panel stack">
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
          <button type="button" className="btn btn-ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      </div>
    </main>
  );
}

/** Lock after 15 minutes without interaction (this tab only). */
function useAutoLock(active: boolean) {
  useEffect(() => {
    if (!active) return;
    const idleLock = () => lock(false);
    let timer = window.setTimeout(idleLock, AUTO_LOCK_MS);
    const reset = () => {
      clearTimeout(timer);
      timer = window.setTimeout(idleLock, AUTO_LOCK_MS);
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [active]);
}

// Links from before 0.2.2 used hash routes (/#/admin); keep them working.
if (location.hash.startsWith("#/")) history.replaceState(null, "", location.hash.slice(1));

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  { path: "/register", element: <RegisterPage /> },
  { path: "/verify-email", element: <VerifyEmailPage /> },
  { path: "/admin", element: <AdminPage /> },
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
