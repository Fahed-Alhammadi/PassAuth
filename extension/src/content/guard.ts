/**
 * Clickjacking defences for PassAuth UI shown inside web pages (inline menu,
 * save prompt). A page can't read our closed shadow roots, but it can style
 * or cover the host element so the user clicks PassAuth without seeing it.
 */

type VisibleEntry = IntersectionObserverEntry & { isVisible?: boolean };

/**
 * Clicks count only after `target` has been fully visible — not covered, not
 * transparent, not filtered, in any parent frame (IntersectionObserver v2) —
 * for at least `ms`.
 */
export function visibilityGate(target: Element, ms = 500) {
  let since = 0;
  let supported = true;
  let io: IntersectionObserver | null = null;
  try {
    io = new IntersectionObserver(
      (entries) => {
        for (const e of entries as VisibleEntry[]) {
          if (e.isVisible === undefined) {
            supported = false;
            return;
          }
          since = e.isVisible ? since || performance.now() : 0;
        }
      },
      { trackVisibility: true, delay: 100 } as IntersectionObserverInit,
    );
    io.observe(target);
  } catch {
    supported = false;
  }
  return {
    ok: () => !supported || (since > 0 && performance.now() - since >= ms),
    stop: () => io?.disconnect(),
  };
}

/** Styles a page may put on our host element (or on the whole page) to hide PassAuth UI while it's clicked. */
export function tampered(host: Element): boolean {
  // PassAuth adds its hosts to <body> (or <html>); a page that moved one into its own (transparent) container is hiding it.
  const parent = host.parentElement;
  if (parent && parent !== document.body && parent !== document.documentElement) return true;
  const s = getComputedStyle(host);
  if (parseFloat(s.opacity) < 1 || s.filter !== "none" || s.clipPath !== "none" || s.visibility !== "visible" || s.mixBlendMode !== "normal") return true;
  for (const el of [document.documentElement, document.body]) {
    if (!el) continue;
    const p = getComputedStyle(el);
    if (parseFloat(p.opacity) < 1 || p.visibility === "hidden") return true;
  }
  return false;
}
