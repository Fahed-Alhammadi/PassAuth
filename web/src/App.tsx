import { useEffect } from "react";
import { createHashRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router";
import { ToastHost } from "./components/ui";
import { lock, useVault } from "./lib/vault";
import { AdminPage } from "./pages/Admin";
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
  if (status === "loading") return null;
  return <Outlet />;
}

/** Lock after 15 minutes without interaction. */
function useAutoLock(active: boolean) {
  useEffect(() => {
    if (!active) return;
    let timer = window.setTimeout(lock, AUTO_LOCK_MS);
    const reset = () => {
      clearTimeout(timer);
      timer = window.setTimeout(lock, AUTO_LOCK_MS);
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [active]);
}

const router = createHashRouter([
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
