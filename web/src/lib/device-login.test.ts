import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ACCESS_CODE_BYTES,
  CLAIM_MAX,
  CODE_FORMAT,
  DENY_BODY,
  EMPTY_QUEUE,
  PHRASE_CHOICES,
  PHRASE_MISMATCH,
  REQUEST_TTL_MS,
  UNEXPECTED_ANSWER,
  accessCode,
  answerErrorOutcome,
  approval,
  base64url,
  checkCode,
  claimedText,
  codeDigits,
  countdown,
  freezeRequest,
  groupedCode,
  isPhraseMismatch,
  phraseChoices,
  secretKeyToKeep,
  wrongCodeText,
  phraseWords,
  pollDelay,
  readCreated,
  readPollAnswer,
  readSignInRequests,
  requestDeadline,
  requestOrigin,
  requestPhrase,
  requestToShow,
  runDeviceLogin,
  settleQueue,
  sleep,
  type Approval,
  type ApprovalQueue,
  type DeviceLoginDeps,
  type DeviceLoginState,
  type DeviceSession,
  type NewRequestBody,
  type PollOutcome,
  type RequestKey,
  type SignInRequest,
} from "./device-login";

const OUR_WORDS = "acrobat bucket clover dimple ember";
const SERVER_WORDS = "server chose these words instead";
const T0 = 1_700_000_000_000;

const session: DeviceSession = {
  user_id: "user-1",
  email: "sam@example.com",
  access_token: "access",
  refresh_token: "refresh",
  bundle: { account_id: "user-1", kdf: {}, secret_key_enabled: false },
  sealed_key: "sealed",
};
const sessionAnswer = { status: "approved", ...session, expires_in: 900, remember_token: null };
const answer = (body: unknown): PollOutcome => ({ kind: "answer", body });

class FakeKey implements RequestKey {
  freed = 0;
  publicKey = () => "PUBLIC-KEY";
  phrase = () => OUR_WORDS;
  free = () => {
    this.freed++;
  };
}

type Step = PollOutcome | ((ctx: { run: { cancel(): void }; now: number }) => PollOutcome);

/** A run against a fake server whose polls answer `script` in turn, on a clock that `sleep` moves forward. */
function setup(script: Step[], more: Partial<DeviceLoginDeps<FakeKey>> = {}) {
  let clock = T0;
  const key = new FakeKey();
  const states: DeviceLoginState[] = [];
  const sleeps: number[] = [];
  const created: NewRequestBody[] = [];
  const finished: { approval: Approval; key: FakeKey; id: string }[] = [];
  const discarded: DeviceSession[] = [];
  let polls = 0;
  let handle: { cancel(): void } = { cancel: () => {} };
  const deps: DeviceLoginDeps<FakeKey> = {
    newKey: () => key,
    randomBytes: (n) => new Uint8Array(n).map((_, i) => i * 7),
    device: { id: "device-1", name: "Chrome on macOS", kind: "web" },
    rememberToken: null,
    create: async (body) => {
      created.push(body);
      return { id: "req-1", fingerprint_phrase: SERVER_WORDS, expires_at: Math.floor(clock / 1000) + 900 };
    },
    poll: async (id, code) => {
      expect(id).toBe("req-1");
      // The code it sent with the request (tests that replace `create` don't record it).
      if (created.length) expect(code).toBe(created[0].access_code);
      const step = script[Math.min(polls++, script.length - 1)];
      return typeof step === "function" ? step({ run: handle, now: clock }) : step;
    },
    finish: async (approval, k, id) => {
      finished.push({ approval, key: k, id });
    },
    discard: (s) => discarded.push(s),
    now: () => clock,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
    ...more,
  };
  const run = runDeviceLogin("sam@example.com", deps, (s) => states.push(s));
  handle = run;
  return { run, key, states, sleeps, created, finished, discarded, polls: () => polls, clock: () => clock };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("access codes", () => {
  it("are base64url without padding", () => {
    expect(base64url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    const code = accessCode(new Uint8Array(ACCESS_CODE_BYTES).fill(0xff));
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(code.length).toBeGreaterThanOrEqual(22);
    expect(code.length).toBeLessThanOrEqual(128);
  });

  it("need at least 128 random bits", () => {
    expect(() => accessCode(new Uint8Array(15))).toThrow();
    expect(accessCode(new Uint8Array(16))).toHaveLength(22);
  });
});

describe("reading the server", () => {
  it("reads a new request without the server's words", () => {
    const created = readCreated({ id: "req-1", fingerprint_phrase: SERVER_WORDS, expires_at: 1900 });
    expect(created).toEqual({ id: "req-1", expiresAt: 1900 });
    expect(JSON.stringify(created)).not.toContain("server");
    expect(readCreated({ id: "req-1" })).toBeNull();
    expect(readCreated({ id: "", expires_at: 1 })).toBeNull();
    expect(readCreated(null)).toBeNull();
  });

  it("reads poll answers", () => {
    for (const status of ["pending", "denied", "expired", "used"] as const) expect(readPollAnswer({ status })).toEqual({ status });
    expect(readPollAnswer(sessionAnswer)).toEqual({ status: "session", session });
    expect(readPollAnswer({ ...sessionAnswer, remember_token: "keep" })).toEqual({ status: "session", session: { ...session, remember_token: "keep" } });
    expect(readPollAnswer({ status: "approved", two_factor_required: true, two_factor_token: "tf", providers: ["totp", 7, "recovery"] })).toEqual({
      status: "two-step",
      token: "tf",
      providers: ["totp", "recovery"],
    });
  });

  it("refuses answers that aren't whole", () => {
    expect(readPollAnswer({ status: "approved", ...session, sealed_key: undefined })).toBeNull();
    expect(readPollAnswer({ status: "approved", ...session, bundle: "x" })).toBeNull();
    expect(readPollAnswer({ status: "approved", two_factor_required: true })).toBeNull();
    expect(readPollAnswer({ status: "maybe" })).toBeNull();
    expect(readPollAnswer("pending")).toBeNull();
  });
});

describe("timing", () => {
  it("counts down to the server's expiry unless this clock is far off", () => {
    expect(requestDeadline(T0 / 1000 + 600, T0)).toBe(T0 + 600_000);
    expect(requestDeadline(T0 / 1000 + 900, T0)).toBe(T0 + REQUEST_TTL_MS);
    // This clock is hours ahead or behind: the request's own lifetime from now.
    expect(requestDeadline(T0 / 1000 - 7200, T0)).toBe(T0 + REQUEST_TTL_MS);
    expect(requestDeadline(T0 / 1000 + 7200, T0)).toBe(T0 + REQUEST_TTL_MS);
  });

  it("polls every few seconds, slower as time passes", () => {
    expect(pollDelay(0, 0)).toBe(3000);
    expect(pollDelay(119_000, 0)).toBe(3000);
    expect(pollDelay(2 * 60_000, 0)).toBe(5000);
    expect(pollDelay(5 * 60_000, 0)).toBe(10_000);
  });

  it("backs off after failures and follows Retry-After", () => {
    expect([1, 2, 3, 4, 9].map((n) => pollDelay(0, n))).toEqual([6000, 12_000, 24_000, 30_000, 30_000]);
    expect(pollDelay(0, 1, 45_000)).toBe(45_000);
    expect(pollDelay(0, 1, 600_000)).toBe(60_000);
    expect(pollDelay(6 * 60_000, 1)).toBe(10_000);
  });

  it("formats what is left", () => {
    expect(countdown(REQUEST_TTL_MS)).toBe("15:00");
    expect(countdown(61_000)).toBe("1:01");
    expect(countdown(1)).toBe("0:01");
    expect(countdown(-5)).toBe("0:00");
  });

  it("sleeps until the time is up or it is woken", async () => {
    vi.useFakeTimers();
    let woke = false;
    const wake = new AbortController();
    void sleep(10_000, wake.signal).then(() => (woke = true));
    await vi.advanceTimersByTimeAsync(5000);
    expect(woke).toBe(false);
    wake.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(woke).toBe(true);
    const aborted = new AbortController();
    aborted.abort();
    await expect(sleep(10_000, aborted.signal)).resolves.toBeUndefined();
  });
});

describe("a sign-in request", () => {
  it("sends the request and shows this device's own words, never the server's", async () => {
    const t = setup([answer({ status: "denied" })], { rememberToken: "remember-me" });
    await t.run.done;
    expect(t.created).toHaveLength(1);
    const body = t.created[0];
    expect(body).toMatchObject({ email: "sam@example.com", public_key: "PUBLIC-KEY", device_id: "device-1", device_name: "Chrome on macOS", device_kind: "web", remember_token: "remember-me" });
    expect(body.access_code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const waiting = t.states.find((s) => s.step === "waiting");
    expect(waiting).toEqual({ step: "waiting", id: "req-1", phrase: OUR_WORDS, deadline: T0 + 900_000 });
    expect(JSON.stringify(t.states)).not.toContain(SERVER_WORDS);
  });

  it("leaves the remember token out when there is none", async () => {
    const t = setup([answer({ status: "denied" })]);
    await t.run.done;
    expect("remember_token" in t.created[0]).toBe(false);
  });

  it("hands an approved session and the key to finish, then is done", async () => {
    const t = setup([answer({ status: "pending" }), answer({ status: "pending" }), answer(sessionAnswer)]);
    expect(await t.run.done).toEqual({ step: "done", email: "sam@example.com" });
    expect(t.states.map((s) => s.step)).toEqual(["waiting", "signing-in", "done"]);
    expect(t.finished).toEqual([{ approval: { kind: "session", session }, key: t.key, id: "req-1" }]);
    // The key now belongs to finish, which frees it.
    expect(t.key.freed).toBe(0);
    expect(t.sleeps).toEqual([3000, 3000, 3000]);
  });

  it("ends waiting for the approving app's code when finish says the approval needs it", async () => {
    const t = setup([answer(sessionAnswer)], { finish: async () => "confirm" });
    expect(await t.run.done).toEqual({ step: "confirm", email: "sam@example.com" });
    expect(t.states.map((s) => s.step)).toEqual(["waiting", "signing-in", "confirm"]);
    // Final: cancelling now changes nothing (the page drops the approval itself).
    t.run.cancel();
    expect(t.states.map((s) => s.step)).toEqual(["waiting", "signing-in", "confirm"]);
  });

  it("hands over to two-step login when the account asks for it", async () => {
    const t = setup([answer({ status: "approved", two_factor_required: true, two_factor_token: "tf", providers: ["totp", "recovery"] })]);
    expect(await t.run.done).toEqual({ step: "two-step", token: "tf", providers: ["totp", "recovery"] });
    expect(t.finished).toEqual([{ approval: { kind: "two-step", token: "tf", providers: ["totp", "recovery"] }, key: t.key, id: "req-1" }]);
    expect(t.key.freed).toBe(0);
  });

  it.each(["denied", "expired", "used"] as const)("ends when the request was %s, and drops the key", async (status) => {
    const t = setup([answer({ status: "pending" }), answer({ status })]);
    expect(await t.run.done).toEqual({ step: status });
    expect(t.key.freed).toBe(1);
    expect(t.finished).toEqual([]);
  });

  it("counts a request the server no longer knows as expired", async () => {
    const t = setup([{ kind: "gone" }]);
    expect(await t.run.done).toEqual({ step: "expired" });
    expect(t.key.freed).toBe(1);
  });

  it("backs off while the server can't be reached, then polls at the steady pace again", async () => {
    const t = setup([{ kind: "retry" }, { kind: "retry", afterMs: 45_000 }, answer({ status: "pending" }), answer({ status: "denied" })]);
    await t.run.done;
    expect(t.sleeps).toEqual([3000, 6000, 45_000, 3000]);
  });

  it("slows down the longer it waits", async () => {
    const t = setup([...Array.from({ length: 45 }, () => answer({ status: "pending" })), answer({ status: "denied" })]);
    await t.run.done;
    // Two minutes of 3 s waits, then 5 s.
    expect(t.sleeps.slice(0, 40).every((ms) => ms === 3000)).toBe(true);
    expect(t.sleeps.slice(40)).toEqual([5000, 5000, 5000, 5000, 5000, 5000]);
  });

  it("gives up after the request's lifetime when the server can't say", async () => {
    const t = setup([{ kind: "retry" }]);
    expect(await t.run.done).toEqual({ step: "expired" });
    expect(t.clock() - T0).toBeGreaterThanOrEqual(REQUEST_TTL_MS);
    expect(t.clock() - T0).toBeLessThan(REQUEST_TTL_MS + 2 * 60_000);
    expect(t.key.freed).toBe(1);
  });

  it("keeps polling past this device's countdown until the server says it expired", async () => {
    // This clock is 5 minutes ahead of the server's: the countdown ends after 10 minutes, the request after 15.
    let pollsAfterCountdown = 0;
    const t = setup(
      [
        ({ now }) => {
          if (now > T0 + 10 * 60_000) pollsAfterCountdown++;
          return answer({ status: now < T0 + 15 * 60_000 ? "pending" : "expired" });
        },
      ],
      { create: async () => ({ id: "req-1", expires_at: T0 / 1000 + 600 }) },
    );
    expect(await t.run.done).toEqual({ step: "expired" });
    expect(t.states.find((s) => s.step === "waiting")).toMatchObject({ deadline: T0 + 600_000 });
    expect(pollsAfterCountdown).toBeGreaterThan(20);
  });

  it("stops and drops the key when cancelled", async () => {
    const t = setup([
      ({ run }) => {
        run.cancel();
        return answer({ status: "pending" });
      },
    ]);
    await t.run.done;
    expect(t.states.at(-1)).toEqual({ step: "cancelled" });
    expect(t.polls()).toBe(1);
    expect(t.key.freed).toBe(1);
  });

  it("signs out a session that arrives after it was cancelled", async () => {
    const t = setup([
      ({ run }) => {
        run.cancel();
        return answer(sessionAnswer);
      },
    ]);
    await t.run.done;
    expect(t.discarded).toEqual([session]);
    expect(t.finished).toEqual([]);
    expect(t.states.map((s) => s.step)).toEqual(["waiting", "cancelled"]);
  });

  it("cancelling after it ended changes nothing", async () => {
    const t = setup([answer({ status: "denied" })]);
    await t.run.done;
    t.run.cancel();
    expect(t.states.at(-1)).toEqual({ step: "denied" });
    expect(t.key.freed).toBe(1);
  });

  it("fails when the server refuses the request, dropping the key", async () => {
    const refused = new Error("too many");
    const t = setup([], { create: async () => Promise.reject(refused) });
    expect(await t.run.done).toEqual({ step: "failed", error: refused });
    expect(t.key.freed).toBe(1);
  });

  it("fails on an answer it can't read", async () => {
    const t = setup([], { create: async () => ({ fingerprint_phrase: SERVER_WORDS }) });
    const end = await t.run.done;
    expect(end.step).toBe("failed");
    expect((end as { error: Error }).error.message).toBe(UNEXPECTED_ANSWER);
    const u = setup([answer({ status: "approved" })]);
    expect(((await u.run.done) as { error: Error }).error.message).toBe(UNEXPECTED_ANSWER);
    expect(u.key.freed).toBe(1);
  });

  it("fails when the approved key can't be used", async () => {
    const unusable = new Error("doesn't match");
    const t = setup([answer(sessionAnswer)], {
      finish: async () => Promise.reject(unusable),
    });
    expect(await t.run.done).toEqual({ step: "failed", error: unusable });
    expect(t.states.map((s) => s.step)).toEqual(["waiting", "signing-in", "failed"]);
  });

  it("fails on errors that aren't worth asking again", async () => {
    const disabled = new Error("turned off");
    const t = setup([], { poll: async () => Promise.reject(disabled) });
    expect(await t.run.done).toEqual({ step: "failed", error: disabled });
    expect(t.key.freed).toBe(1);
  });

  it("polls at once when woken", async () => {
    vi.useFakeTimers({ now: T0 });
    let polls = 0;
    const key = new FakeKey();
    const run = runDeviceLogin(
      "sam@example.com",
      {
        newKey: () => key,
        randomBytes: (n) => new Uint8Array(n),
        device: { id: "d", name: "n", kind: "web" },
        create: async () => ({ id: "req-1", expires_at: T0 / 1000 + 900 }),
        poll: async () => (++polls === 1 ? answer({ status: "pending" }) : answer({ status: "denied" })),
        finish: async () => {},
        discard: () => {},
        now: () => Date.now(),
        sleep,
      },
      () => {},
    );
    await vi.advanceTimersByTimeAsync(0);
    expect(polls).toBe(0);
    run.pollNow();
    await vi.advanceTimersByTimeAsync(0);
    expect(polls).toBe(1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(await run.done).toEqual({ step: "denied" });
    expect(Date.now() - T0).toBe(3000);
  });
});

// ------------------------------------------------------- approving apps

const raw = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  public_key: `pk-${id}`,
  fingerprint_phrase: SERVER_WORDS,
  challenge: `challenge-${id}`,
  device_name: " Chrome on macOS ",
  device_kind: "web",
  client: "web/0.9.0",
  ip: "203.0.113.7",
  created_at: 1000,
  expires_at: 1900,
  ...extra,
});

describe("listing requests", () => {
  it("reads them in the server's order, without the server's words", () => {
    const list = readSignInRequests({ requests: [raw("b"), raw("a", { client: null, ip: null, device_name: "" }), { id: "broken" }] });
    expect(list).toEqual<SignInRequest[]>([
      { id: "b", publicKey: "pk-b", challenge: "challenge-b", deviceName: "Chrome on macOS", deviceKind: "web", client: "web/0.9.0", ip: "203.0.113.7", createdAt: 1000, expiresAt: 1900 },
      { id: "a", publicKey: "pk-a", challenge: "challenge-a", deviceName: "", deviceKind: "web", client: null, ip: null, createdAt: 1000, expiresAt: 1900 },
    ]);
    expect(JSON.stringify(list)).not.toContain(SERVER_WORDS);
    expect(readSignInRequests({ requests: "none" })).toEqual([]);
    expect(readSignInRequests(null)).toEqual([]);
  });

  it("shows the words worked out from the request's own key", () => {
    const [req] = readSignInRequests({ requests: [raw("a")] });
    const seen: string[] = [];
    const phrase = requestPhrase(req, (pk) => (seen.push(pk), OUR_WORDS));
    expect(seen).toEqual(["pk-a"]);
    expect(phrase).toBe(OUR_WORDS);
    expect(phrase).not.toBe(SERVER_WORDS);
    expect(phraseWords(phrase!)).toEqual(["acrobat", "bucket", "clover", "dimple", "ember"]);
    expect(
      requestPhrase(req, () => {
        throw new Error("bad key");
      }),
    ).toBeNull();
  });

  it("picks the request to bring up", () => {
    const list = readSignInRequests({ requests: [raw("new"), raw("old")] });
    expect(requestToShow(list, new Set(), null)?.id).toBe("new");
    expect(requestToShow(list, new Set(["new"]), null)?.id).toBe("old");
    expect(requestToShow(list, new Set(["new", "old"]), null)).toBeNull();
    expect(requestToShow(list, new Set(), "old")?.id).toBe("old");
    expect(requestToShow(list, new Set(), "gone")?.id).toBe("new");
    expect(requestToShow([], new Set(), null)).toBeNull();
  });

  it("shows what the device says about itself as one clean, short line", () => {
    const [req] = readSignInRequests({
      requests: [
        raw("a", {
          device_name: "Your\u202E MacBook\n– PassAuth security check " + "x".repeat(80),
          client: "desktop\u200B/0.7.0",
          device_kind: "\u2066web\u2069",
          ip: "203.0.113.7\u202E",
        }),
      ],
    });
    expect(req.deviceName.startsWith("Your MacBook – PassAuth security check xx")).toBe(true);
    expect(Array.from(req.deviceName)).toHaveLength(CLAIM_MAX);
    expect(req.deviceName.endsWith("…")).toBe(true);
    expect(req.client).toBe("desktop/0.7.0");
    expect(req.deviceKind).toBe("web");
    expect(req.ip).toBe("203.0.113.7");
    // Not strings, or nothing left once cleaned: left out.
    const [bare] = readSignInRequests({ requests: [raw("b", { device_name: 42, client: "\u200B", device_kind: null, ip: {} })] });
    expect(bare).toMatchObject({ deviceName: "", client: null, deviceKind: "web", ip: null });
    expect(claimedText("  Pixel 9  ")).toBe("Pixel 9");
  });

  it("says who asks, from where and when", () => {
    expect(requestOrigin({ deviceName: "Chrome on macOS", ip: "203.0.113.7" }, "Web", "9:14 PM")).toBe("Chrome on macOS (Web), 203.0.113.7, 9:14 PM");
    expect(requestOrigin({ deviceName: "", ip: null }, null, "9:14 PM")).toBe("Unknown device, 9:14 PM");
  });
});

describe("the approval sheet's queue", () => {
  const list = (...reqs: ReturnType<typeof raw>[]) => readSignInRequests({ requests: reqs });
  const NOW = 1500;
  const settle = (q: ApprovalQueue, quiet?: (id: string) => boolean, now = NOW) => settleQueue(q, now, quiet);
  const open = (requests: SignInRequest[]) => settle({ ...EMPTY_QUEUE, requests }).queue;

  it("brings up the newest request, frozen as it was then", () => {
    const q = open(list(raw("new"), raw("old")));
    expect(q.shown?.id).toBe("new");
    expect(Object.isFrozen(q.shown)).toBe(true);
    expect(() => {
      (q.shown as { publicKey: string }).publicKey = "swapped";
    }).toThrow();
    expect(freezeRequest(q.requests[1])).toEqual(q.requests[1]);
    expect(open([]).shown).toBeNull();
  });

  it("keeps the shown request exactly as it was while its key and challenge stay the same", () => {
    const q = open(list(raw("a")));
    const renamed = list(raw("a", { device_name: "Someone else", ip: "198.51.100.1", expires_at: 99999 }));
    const { queue, ended } = settle({ ...q, requests: renamed });
    expect(ended).toBeNull();
    expect(queue.notice).toBeNull();
    expect(queue.shown).toBe(q.shown);
    expect(queue.shown?.deviceName).toBe("Chrome on macOS");
  });

  it("never replaces the shown request with a newer one: it waits until the shown one is handled", () => {
    let q = open(list(raw("a")));
    q = settle({ ...q, requests: list(raw("b", { created_at: 1100 }), raw("a")) }).queue;
    expect(q.shown?.id).toBe("a");
    // The user asks to review "b" meanwhile: it still waits.
    q = settle({ ...q, preferred: "b" }).queue;
    expect(q.shown?.id).toBe("a");
    // "a" answered here (or put off): "b" comes up.
    q = settle({ ...q, requests: list(raw("b")), shown: null }).queue;
    expect(q.shown?.id).toBe("b");
  });

  it("keeps the sheet open when a listing seals the same request's challenge again (same key, other text)", () => {
    const q = open(list(raw("a"), raw("b")));
    // The server seals the challenge anew for every listing: new ciphertext, same content.
    for (const n of [1, 2, 3]) {
      const { queue, ended } = settle({ ...q, requests: list(raw("a", { challenge: `challenge-a-resealed-${n}` }), raw("b")) });
      expect(ended).toBeNull();
      expect(queue.notice).toBeNull();
      expect(queue.putOff.has("a")).toBe(false);
      // Still the frozen request, with the challenge it was frozen with: that one is opened for the proof.
      expect(queue.shown).toBe(q.shown);
      expect(queue.shown?.challenge).toBe("challenge-a");
    }
  });

  it("closes the sheet when a listing gives the shown request another key, and puts it off", () => {
    const q = open(list(raw("a"), raw("b")));
    const swapped = raw("a", { public_key: "pk-server", challenge: "challenge-server" });
    const { queue, ended } = settle({ ...q, requests: list(swapped, raw("b")) });
    expect(ended).toBeNull();
    expect(queue.shown).toBeNull();
    expect(queue.notice).toEqual({ kind: "changed" });
    expect(queue.putOff.has("a")).toBe(true);
    // Nothing else comes up while the note is up, not even "b"…
    expect(settle({ ...queue, requests: list(raw("c"), swapped, raw("b")) }).queue.shown).toBeNull();
    // …and once it is read, the changed request doesn't come up again by itself.
    const after = settle({ ...queue, notice: null }).queue;
    expect(after.shown?.id).toBe("b");
    expect(after.shown?.publicKey).toBe("pk-b");
  });

  it("closes the sheet when the shown request leaves the list: expired, changed, or quietly when this app answered it", () => {
    const q = open(list(raw("a"), raw("b")));
    const gone = { ...q, requests: list(raw("b")) };
    // Before its expiry by this device's clock: treated as changed.
    expect(settle(gone).queue).toMatchObject({ shown: null, notice: { kind: "changed" } });
    // After it: expired, and the next request comes up.
    const late = settle(gone, undefined, 1900);
    expect(late.ended).toBe("expired");
    expect(late.queue.notice).toBeNull();
    expect(late.queue.shown?.id).toBe("b");
    // Answered by this app: no note.
    const quiet = settle(gone, (id) => id === "a");
    expect(quiet.ended).toBeNull();
    expect(quiet.queue.notice).toBeNull();
    expect(quiet.queue.shown?.id).toBe("b");
  });

  it("keeps the code (or the note that the words didn't match) up before the next request", () => {
    for (const notice of [{ kind: "code", code: "123456" }, { kind: "mismatch" }] as const) {
      const q = settle({ ...EMPTY_QUEUE, requests: list(raw("b")), notice }).queue;
      expect(q.shown).toBeNull();
      expect(settle({ ...q, notice: null }).queue.shown?.id).toBe("b");
    }
  });

  it("brings up a request put off before only when the user asks to review it", () => {
    let q = settle({ ...EMPTY_QUEUE, requests: list(raw("a")), putOff: new Set(["a"]) }).queue;
    expect(q.shown).toBeNull();
    q = settle({ ...q, putOff: new Set(), preferred: "a" }).queue;
    expect(q.shown?.id).toBe("a");
  });
});

describe("answering", () => {
  const WORDS = "acrobat bucket clover dimple ember";
  function account(refuseSecretKey = false) {
    const calls: unknown[][] = [];
    return {
      calls,
      approveLoginRequest(pk: string, id: string, chosen: string, sk?: string | null) {
        calls.push(["approve", pk, id, chosen, sk]);
        if (chosen !== WORDS) throw new Error(PHRASE_MISMATCH);
        if (sk && refuseSecretKey) throw new Error("invalid secret key");
        return { sealed: `sealed(${pk},${id},${sk ?? "-"})`, code: "042917" };
      },
      openLoginChallenge(challenge: string, id: string) {
        calls.push(["open", challenge, id]);
        return `proof(${challenge},${id})`;
      },
    };
  }
  const [req] = readSignInRequests({ requests: [raw("r1")] });

  it("offers the request's own words among decoys, worked out from its own key", () => {
    const seen: unknown[][] = [];
    const choices = phraseChoices(req, (pk, n) => (seen.push([pk, n]), ["one two three four five", WORDS, "six seven eight nine ten"]));
    expect(seen).toEqual([["pk-r1", PHRASE_CHOICES]]);
    expect(PHRASE_CHOICES).toBe(3);
    expect(choices).toContain(WORDS);
    // A key the core can't read, or an answer that isn't a list of words: nothing to choose (only "None of these").
    expect(
      phraseChoices(req, () => {
        throw new Error("expected a string");
      }),
    ).toEqual([]);
    expect(phraseChoices(req, () => [WORDS])).toEqual([]);
    expect(phraseChoices(req, () => [WORDS, 5 as unknown as string])).toEqual([]);
  });

  it("seals the account key to the request's key for its own words, proves it holds the account's keys, and gives the code", () => {
    const acct = account();
    expect(approval(acct, req, WORDS, null)).toEqual({
      body: { approve: true, sealed_key: "sealed(pk-r1,r1,-)", proof: "proof(challenge-r1,r1)" },
      code: "042917",
    });
    expect(acct.calls).toEqual([
      ["approve", "pk-r1", "r1", WORDS, undefined],
      ["open", "challenge-r1", "r1"],
    ]);
    expect(groupedCode("042917")).toBe("042 917");
  });

  it("refuses words that aren't the request's: nothing is sealed", () => {
    const acct = account();
    let thrown: unknown;
    try {
      approval(acct, req, "decoy words that look alike", "PA1-ABCDEF");
    } catch (e) {
      thrown = e;
    }
    expect(isPhraseMismatch(thrown)).toBe(true);
    // Not tried again without the Secret Key, and the challenge isn't opened.
    expect(acct.calls).toHaveLength(1);
  });

  it("sends the Secret Key along when this app knows it", () => {
    expect(approval(account(), req, WORDS, "PA1-ABCDEF").body).toMatchObject({ sealed_key: "sealed(pk-r1,r1,PA1-ABCDEF)" });
  });

  it("approves without a saved Secret Key the core can't read", () => {
    const acct = account(true);
    expect(approval(acct, req, WORDS, "not a key").body).toMatchObject({ sealed_key: "sealed(pk-r1,r1,-)" });
    expect(acct.calls.filter((c) => c[0] === "approve")).toHaveLength(2);
  });

  it("fails when the request's key can't be sealed to, or the core's answer isn't whole", () => {
    const refusing = {
      approveLoginRequest: () => {
        throw new Error("low-order key");
      },
      openLoginChallenge: () => "proof",
    };
    expect(() => approval(refusing, req, WORDS, null)).toThrow("low-order key");
    const odd = { approveLoginRequest: () => ({ sealed: "s", code: "12345" }), openLoginChallenge: () => "proof" };
    expect(() => approval(odd, req, WORDS, null)).toThrow();
  });

  it("denies with nothing else", () => {
    expect(DENY_BODY).toEqual({ approve: false });
  });

  it("tells a request that ended from a real error", () => {
    expect(answerErrorOutcome(409, "conflict")).toBe("answered");
    expect(answerErrorOutcome(400, "expired")).toBe("expired");
    expect(answerErrorOutcome(404, "not_found")).toBe("gone");
    expect(answerErrorOutcome(400, "bad_request")).toBeNull();
    expect(answerErrorOutcome(403, "forbidden")).toBeNull();
    expect(answerErrorOutcome(500, "internal")).toBeNull();
  });
});

describe("the code on the new device", () => {
  /** An approval like the core's: `right` confirms; 3 wrong codes refuse it for good. */
  function approvalFor(right: string) {
    let left = 3;
    let refused = false;
    return {
      typed: [] as string[],
      get attemptsLeft() {
        return refused ? 0 : left;
      },
      confirm(code: string) {
        this.typed.push(code);
        if (refused) throw new Error("too_many_wrong_codes");
        if (code === right) return;
        left--;
        if (left === 0) {
          refused = true;
          throw new Error("too_many_wrong_codes");
        }
        throw new Error("wrong_code");
      },
    };
  }

  it("takes 6 digits, with spaces or a hyphen between them", () => {
    expect(codeDigits("123 456")).toBe("123456");
    expect(codeDigits(" 123-456 ")).toBe("123456");
    expect(codeDigits("12345")).toBeNull();
    expect(codeDigits("1234567")).toBeNull();
    expect(codeDigits("12a456")).toBeNull();
  });

  it("confirms the right code; says how many tries are left after a wrong one; stops after the third", () => {
    const a = approvalFor("123456");
    expect(checkCode(a, "111 111")).toEqual({ kind: "wrong", attemptsLeft: 2 });
    expect(wrongCodeText(2)).toBe("That code doesn't match. 2 tries left.");
    expect(wrongCodeText(1)).toBe("That code doesn't match. 1 try left.");
    expect(checkCode(a, "222222")).toEqual({ kind: "wrong", attemptsLeft: 1 });
    expect(checkCode(a, "333333")).toEqual({ kind: "stopped" });
    // Refused for good: even the right code doesn't help now.
    expect(checkCode(a, "123456")).toEqual({ kind: "stopped" });
    expect(checkCode(approvalFor("123456"), "123-456")).toEqual({ kind: "confirmed" });
  });

  it("doesn't count anything but 6 digits as a try", () => {
    const a = approvalFor("123456");
    expect(() => checkCode(a, "12")).toThrow(CODE_FORMAT);
    expect(a.typed).toEqual([]);
    expect(a.attemptsLeft).toBe(3);
  });

  it("keeps a Secret Key that came along only for the email typed here, never in place of a different one", () => {
    expect(secretKeyToKeep("Sam@Example.com ", "sam@example.com", "PA1-NEW", null)).toBe("PA1-NEW");
    expect(secretKeyToKeep("sam@example.com", "sam@example.com", "PA1-NEW", "PA1-NEW")).toBe("PA1-NEW");
    expect(secretKeyToKeep("sam@example.com", "sam@example.com", "PA1-NEW", "PA1-OLD")).toBeNull();
    expect(secretKeyToKeep("sam@example.com", "someone@example.com", "PA1-NEW", null)).toBeNull();
    expect(secretKeyToKeep("sam@example.com", "sam@example.com", null, null)).toBeNull();
  });
});
