/**
 * Clickjacking defences for PassAuth UI shown inside web pages (inline menu,
 * save prompt). A page can't read our closed shadow roots, but it can style
 * or cover the host element, or move it under the pointer, so the user clicks
 * PassAuth without meaning to.
 */

type VisibleEntry = IntersectionObserverEntry & { isVisible?: boolean };

/** A touch or pen tap as the gate keeps it: when (performance.now()), where the frame was on the screen, and on what. */
export interface Tap {
  at: number;
  /** Screen minus client point: the frame's offset on the screen (the same for every point of an unmoved frame). */
  dx: number;
  dy: number;
  /** The control tapped (`controlOf`): a confirm tap counts only on the same one. */
  control?: unknown;
}

/** A confirm tap comes at least this long after the first (two taps in a row are a double tap, not a decision)… */
export const CONFIRM_MIN_MS = 500;
/** …and at most this long after it. */
export const CONFIRM_MAX_MS = 5000;
/** How far the frame's offset on the screen may differ between the taps (rounding of fractional touch points). */
export const CONFIRM_SLOP_PX = 3;

/**
 * Whether `tap` confirms the `first` one: on the same control, 0.5–5 s after it, with the frame at the same place on
 * the screen (offsets within a few pixels), and the frame fully visible without a break since before the first tap
 * (`visibleSince`, 0 while it isn't). The gate forgets the first tap whenever the frame moves or is resized, so a
 * page can't line up PassAuth's frame under a tap meant for something else; and a first tap on one control ("New
 * card", "Unlock") never confirms a tap on another (a card row). Pure.
 */
export function confirmsTap(first: Tap | null, tap: Tap, visibleSince: number, min = CONFIRM_MIN_MS): boolean {
  if (!first || !visibleSince || visibleSince > first.at) return false;
  if ((first.control ?? null) !== (tap.control ?? null)) return false;
  const gap = tap.at - first.at;
  return gap >= min && gap <= CONFIRM_MAX_MS && Math.abs(tap.dx - first.dx) <= CONFIRM_SLOP_PX && Math.abs(tap.dy - first.dy) <= CONFIRM_SLOP_PX;
}

/** What kind of input activated a control: a key, a mouse, or a touch screen or pen (the gate's hint names it). */
export function inputKind(e: Event): "key" | "mouse" | "touch" {
  if (e instanceof KeyboardEvent) return "key";
  const type = e instanceof MouseEvent ? ((e as PointerEvent).pointerType ?? "") : "";
  if (type === "touch" || type === "pen") return "touch";
  return e instanceof MouseEvent && (e.detail > 0 || type !== "") ? "mouse" : "key";
}

/**
 * The control an event activated, as confirm taps compare it: a row by its item id (`data-id`: rows are drawn again
 * when their codes refresh), else the element whose listener asks (`currentTarget`).
 */
export function controlOf(e: Event): unknown {
  const t = e.currentTarget;
  if (t instanceof HTMLElement && t.dataset.id) return `id:${t.dataset.id}`;
  return t ?? null;
}

/** The hint for an action that didn't count yet: "Press Enter again", "Tap again" or "Click again". */
export const againHint = (e: Event): string => ({ key: "Press Enter again", touch: "Tap again", mouse: "Click again" })[inputKind(e)];

/**
 * In PassAuth's framed pages: a click counts only once
 * - the frame has been fully visible — not covered, transparent, filtered or
 *   transformed, in any parent frame (IntersectionObserver v2) — for `ms`;
 *   where the browser can't tell (no IntersectionObserver v2), never;
 * - and, for a mouse click, the pointer has been inside the frame for `ms`
 *   since it came in or the frame last moved or changed size (`moved`, sent
 *   by the content script that placed it, or seen here: a pointer event at the
 *   same screen point as the last one but elsewhere in the frame means the
 *   page moved the frame under the pointer);
 * - for a touch or pen tap, which has no resting pointer (Chrome sends
 *   `pointerleave` before the tap's `click`): a confirm tap, a second tap
 *   0.5–5 s after the first with the frame at the same place on the screen and
 *   no move, resize or loss of visibility in between (`confirmsTap`; the first
 *   tap gets "Tap again"). A pen resting over the frame for `ms` counts like a
 *   mouse. The content script checks the frame for tampering every animation
 *   frame while it is open, and closes it at once if the page touches it.
 * Keyboard activation of a focused control has no pointer: besides the
 * visibility rule it counts only while the keyboard is armed — after the
 * content script asked for the focus with the frame's nonce (`armKeys`), or
 * after a click or tap in the frame that passed the checks above — and the
 * frame losing the focus disarms it. So a page that got the frame focused some
 * other way can't have a key press it asked for (Enter) choose something.
 */
export function clickGate(target: Element, ms = 500) {
  const now = () => performance.now();
  let visibleSince = 0;
  let supported = true;
  let pointerSince = 0;
  /** Keyboard activation is accepted (see above). */
  let keys = false;
  /** When PassAuth asked for the focus before it had arrived (the two travel separately): the focus that follows arms. */
  let armAsked = 0;
  /** The last trusted pointer event in this frame: where it was on the screen and in the frame. */
  let last: { sx: number; sy: number; cx: number; cy: number } | null = null;
  /** Touch and pen: the tap that asked for a confirm tap, while it can still be confirmed. */
  let firstTap: Tap | null = null;
  let io: IntersectionObserver | null = null;
  try {
    io = new IntersectionObserver(
      (entries) => {
        for (const e of entries as VisibleEntry[]) {
          if (e.isVisible === undefined) {
            supported = false;
            return;
          }
          visibleSince = e.isVisible ? visibleSince || now() : 0;
          if (!e.isVisible) firstTap = null;
        }
      },
      { trackVisibility: true, delay: 100 } as IntersectionObserverInit,
    );
    io.observe(target);
  } catch {
    supported = false;
  }
  const restart = () => {
    if (pointerSince) pointerSince = now();
    // A tap before the frame moved (or was resized) confirms nothing after it.
    firstTap = null;
  };
  const visibleLongEnough = () => supported && visibleSince > 0 && now() - visibleSince >= ms;
  const rested = () => pointerSince > 0 && now() - pointerSince >= ms;
  /**
   * The pointer stayed at the same place on the screen but not in this frame: the frame moved under a resting
   * pointer. The page did that (PassAuth's own moves send `moved`), e.g. with a transform on an ancestor, which the
   * content script's tamper check sees only at its next run; the click that follows must not count, so the
   * pointer's time inside starts again.
   */
  const track = (e: PointerEvent) => {
    if (!e.isTrusted) return;
    const at = { sx: e.screenX, sy: e.screenY, cx: e.clientX, cy: e.clientY };
    if (last && at.sx === last.sx && at.sy === last.sy && (at.cx !== last.cx || at.cy !== last.cy)) restart();
    last = at;
  };
  const enter = (e: PointerEvent) => {
    track(e);
    if (e.isTrusted && !pointerSince) pointerSince = now();
  };
  const leave = () => {
    pointerSince = 0;
    last = null;
  };
  /** A mouse click anywhere in the frame that would pass the checks (also on controls that aren't guarded, "⋯") arms the keyboard. */
  const noteClick = (e: MouseEvent) => {
    if (e.isTrusted && inputKind(e) === "mouse" && visibleLongEnough() && rested()) keys = true;
  };
  const disarm = () => {
    keys = false;
    armAsked = 0;
  };
  const focused = () => {
    if (armAsked && now() - armAsked < 1000) keys = true;
    armAsked = 0;
  };
  window.addEventListener("pointerover", enter, true);
  window.addEventListener("pointermove", enter, true);
  window.addEventListener("pointerdown", track, true);
  window.addEventListener("pointerup", track, true);
  window.addEventListener("click", noteClick, true);
  document.documentElement.addEventListener("pointerleave", leave);
  window.addEventListener("resize", restart);
  window.addEventListener("blur", disarm);
  window.addEventListener("focus", focused);
  return {
    ok(e?: Event): boolean {
      const kind = e ? inputKind(e) : "key";
      if (kind === "touch" && e instanceof MouseEvent) {
        const tap: Tap = { at: now(), dx: e.screenX - e.clientX, dy: e.screenY - e.clientY, control: controlOf(e) };
        if (visibleLongEnough() && (rested() || confirmsTap(firstTap, tap, visibleSince, ms))) {
          firstTap = null;
          keys = true;
          return true;
        }
        // Not yet: this tap asks for a confirm tap (only while the frame can be seen).
        firstTap = supported && visibleSince > 0 ? tap : null;
        return false;
      }
      if (kind === "key" && !keys) return false;
      if (!visibleLongEnough()) return false;
      if (kind === "mouse" && !rested()) return false;
      if (kind === "mouse") keys = true;
      return true;
    },
    /** Whether a key press may activate a control now (`ok` also needs the frame visible long enough). */
    keysArmed: () => keys,
    /**
     * The content script gave this frame the focus, asking with its nonce (frame-channel.ts `onFocusRequest`): keys
     * count while the frame keeps it. When the request comes just before the focus itself, the focus that follows
     * within a second arms them.
     */
    armKeys() {
      if (document.hasFocus()) keys = true;
      else armAsked = now();
    },
    /** The frame was moved or resized: the pointer's time inside starts again. */
    moved: restart,
    stop() {
      io?.disconnect();
      window.removeEventListener("pointerover", enter, true);
      window.removeEventListener("pointermove", enter, true);
      window.removeEventListener("pointerdown", track, true);
      window.removeEventListener("pointerup", track, true);
      window.removeEventListener("click", noteClick, true);
      document.documentElement.removeEventListener("pointerleave", leave);
      window.removeEventListener("resize", restart);
      window.removeEventListener("blur", disarm);
      window.removeEventListener("focus", focused);
    },
  };
}

/** Where PassAuth put a frame, in viewport pixels. */
export interface Placement {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** Placements more than a pixel and a half apart (rounding aside, something moved). */
export const placementDiffers = (a: Placement, b: Placement) =>
  Math.abs(a.left - b.left) > 1.5 || Math.abs(a.top - b.top) > 1.5 || Math.abs(a.width - b.width) > 1.5 || Math.abs(a.height - b.height) > 1.5;

/**
 * Styles on the host, `<html>` or `<body>` that hide or disguise what is under them without the browser's visibility
 * check (IntersectionObserver v2, in the frame) noticing: an outline drawn over the frame (a wide one with a negative
 * offset) and masks. On `<html>` and `<body>` an outline only counts when it is wider than a focus ring.
 */
function hidesFrame(s: CSSStyleDeclaration, host: boolean): boolean {
  const outline = s.outlineStyle;
  if (outline && outline !== "none" && (host || parseFloat(s.outlineWidth) > 3)) return true;
  for (const p of ["mask-image", "-webkit-mask-image", "-webkit-mask-box-image-source"]) {
    const v = s.getPropertyValue(p);
    if (v && v !== "none") return true;
  }
  return false;
}

/**
 * In the content script: whether the page has tampered with PassAuth UI to hide
 * it while it's clicked or to move it under the pointer. `frame` and `expected`:
 * the frame and where PassAuth placed it (or the places it may be); any
 * difference — the host's inset, margin or size changed, or a transform, zoom
 * or containing block on an ancestor moved it — counts. The host's own styles
 * are pinned (`HOST_CSS`), so these checks are a second line.
 */
export function tampered(host: HTMLElement, frame?: Element | null, expected?: Placement | readonly Placement[] | null): boolean {
  if (!host.isConnected) return true;
  // PassAuth adds its hosts to <body> (or <html>); a page that moved one into its own (transparent) container is hiding it.
  const parent = host.parentElement;
  if (parent && parent !== document.body && parent !== document.documentElement) return true;
  const s = getComputedStyle(host);
  if (parseFloat(s.opacity) < 1 || s.filter !== "none" || s.clipPath !== "none" || s.visibility !== "visible" || s.mixBlendMode !== "normal") return true;
  if (s.position !== "fixed" || s.pointerEvents === "none" || s.display === "none" || (s.contentVisibility && s.contentVisibility !== "visible")) return true;
  if (s.transform !== "none" || s.translate !== "none" || s.scale !== "none" || s.rotate !== "none" || (s.zoom !== "" && parseFloat(s.zoom) !== 1)) return true;
  if ([s.marginTop, s.marginRight, s.marginBottom, s.marginLeft].some((m) => parseFloat(m) !== 0)) return true;
  if (hidesFrame(s, true)) return true;
  for (const el of [document.documentElement, document.body]) {
    if (!el) continue;
    const p = getComputedStyle(el);
    if (parseFloat(p.opacity) < 1 || p.visibility === "hidden" || hidesFrame(p, false)) return true;
  }
  if (frame && expected) {
    const r = frame.getBoundingClientRect();
    const at = { left: r.left, top: r.top, width: r.width, height: r.height };
    if ((Array.isArray(expected) ? expected : [expected]).every((x: Placement) => placementDiffers(at, x))) return true;
  }
  return false;
}

/**
 * Host styles that keep a page's own CSS off PassAuth's host elements. Inside the closed shadow root an `!important`
 * declaration beats every declaration of the page, even its `!important` ones and the host's own style attribute, so
 * `all: initial !important` resets every property the page could use (outline, mask, content, filters, transitions,
 * animations, inherited ones…) and the few PassAuth needs are set again below it. The placement comes from custom
 * properties PassAuth sets on the host (`placeHost`): `all` doesn't reach those, and a page that changes them only
 * moves the frame, which `tampered` sees.
 */
export const HOST_CSS = `:host { all: initial !important; display: block !important; position: fixed !important; z-index: 2147483647 !important;
  left: var(--pa-left, auto) !important; top: var(--pa-top, auto) !important; width: var(--pa-width, auto) !important; height: var(--pa-height, auto) !important;
  opacity: 1 !important; filter: none !important; clip-path: none !important; visibility: visible !important; mix-blend-mode: normal !important;
  pointer-events: auto !important; transform: none !important; translate: none !important; scale: none !important; rotate: none !important;
  zoom: 1 !important; margin: 0 !important; padding: 0 !important; border: 0 !important; outline: none !important; mask: none !important;
  -webkit-mask: none !important; -webkit-mask-box-image: none !important; content-visibility: visible !important; }`;

/**
 * Put a host where `at` says (viewport pixels), through the custom properties `HOST_CSS` reads. `!important` in the
 * style attribute: the page's style sheets can't override it (a script can, which moves the frame: `tampered`).
 */
export function placeHost(el: HTMLElement, at: Placement) {
  el.style.setProperty("--pa-left", `${at.left}px`, "important");
  el.style.setProperty("--pa-top", `${at.top}px`, "important");
  el.style.setProperty("--pa-width", `${at.width}px`, "important");
  el.style.setProperty("--pa-height", `${at.height}px`, "important");
}

/** A host element for PassAuth UI: a plain <div> (a page can't predefine it as a custom element) with a closed shadow root. */
export function shadowHost(css: string): { el: HTMLDivElement; shadow: ShadowRoot } {
  const el = document.createElement("div");
  const shadow = el.attachShadow({ mode: "closed" });
  shadow.innerHTML = `<style>${HOST_CSS} ${css}</style>`;
  return { el, shadow };
}
