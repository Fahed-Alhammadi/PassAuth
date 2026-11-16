import { describe, expect, it, vi } from "vitest";
import {
  analyze,
  BreachCheckError,
  createBreachChecker,
  isWeak,
  parseRange,
  PWNED_PARALLEL,
  PWNED_RANGE_URL,
  sha1Hex,
  WEAK_BITS,
  type HealthEntry,
  type RangeFetch,
} from "./health";

// ------------------------------------------------------------------ helpers

let nextId = 0;
function login(password: string, extra: Partial<HealthEntry> = {}): HealthEntry {
  return { id: `item-${++nextId}`, deletedAt: null, item: { login: { password } }, ...extra };
}

/** Strength estimate stub: bits per password, 100 for anything not listed. */
const bitsFrom = (table: Record<string, number>) => (password: string) => table[password] ?? 100;

/** A 40-character uppercase hex hash from a 5-character prefix and a suffix seed. */
const hash = (prefix: string, seed: string) => (prefix + seed.repeat(35)).slice(0, 40).toUpperCase();

/** Digest stub: fixed hashes per password, so tests choose which passwords share a prefix. */
const digestFrom = (table: Record<string, string>) => async (password: string) => {
  const h = table[password];
  if (!h) throw new Error(`no hash for ${password}`);
  return h;
};

/** `count` padding lines (count 0), as Have I Been Pwned adds them. */
const padding = (count: number, seed = 0) =>
  Array.from({ length: count }, (_, i) => `${(seed * 1000 + i).toString(16).toUpperCase().padStart(35, "F")}:0`);

interface Call {
  url: string;
  init: RequestInit;
}

/** A stubbed `fetch` that answers each prefix with `answer(prefix)` and records every call. */
function stubFetch(answer: (prefix: string, init: RequestInit) => string | Response | Promise<string | Response>) {
  const calls: Call[] = [];
  const fetch = vi.fn<RangeFetch>(async (url, init) => {
    calls.push({ url, init });
    const reply = await answer(url.slice(PWNED_RANGE_URL.length), init);
    return typeof reply === "string" ? new Response(reply, { status: 200, headers: { "content-type": "text/plain" } }) : reply;
  });
  return { fetch, calls, prefixes: () => calls.map((c) => c.url.slice(PWNED_RANGE_URL.length)) };
}

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ weak

describe("weak passwords", () => {
  it("uses one threshold of 50 bits", () => {
    expect(WEAK_BITS).toBe(50);
    expect(isWeak("short", () => 49.99)).toBe(true);
    expect(isWeak("longer", () => 50)).toBe(false);
    expect(isWeak("longest", () => 80)).toBe(false);
  });

  it("never calls an empty password weak", () => {
    const estimate = vi.fn(() => 0);
    expect(isWeak("", estimate)).toBe(false);
    expect(estimate).not.toHaveBeenCalled();
  });

  it("reports the logins below the threshold", () => {
    const weak = login("abc");
    const edge = login("edge");
    const strong = login("strong");
    const report = analyze([weak, edge, strong], bitsFrom({ abc: 15, edge: WEAK_BITS, strong: 90 }));
    expect(report.weak).toEqual([weak]);
    expect(report.logins).toEqual([weak, edge, strong]);
  });
});

// ------------------------------------------------------------------ reuse

describe("reused passwords", () => {
  it("groups identical passwords, the largest group first", () => {
    const a1 = login("same-a");
    const b1 = login("same-b");
    const a2 = login("same-a");
    const b2 = login("same-b");
    const a3 = login("same-a");
    const alone = login("only-once");
    const report = analyze([a1, b1, a2, b2, a3, alone], bitsFrom({}));
    expect(report.reused).toEqual([
      [a1, a2, a3],
      [b1, b2],
    ]);
    expect(report.reuseCount.get(a1.id)).toBe(2);
    expect(report.reuseCount.get(b2.id)).toBe(1);
    expect(report.reuseCount.has(alone.id)).toBe(false);
  });

  it("compares passwords exactly", () => {
    const report = analyze([login("Secret"), login("secret"), login("secret "), login(" secret")], bitsFrom({}));
    expect(report.reused).toEqual([]);
  });

  it("skips empty passwords, items in the trash and items that aren't logins", () => {
    const empty1 = login("");
    const empty2 = login("");
    const kept = login("shared-password");
    const trashed = login("shared-password", { deletedAt: 1_700_000_000 });
    const note: HealthEntry = { id: "note", deletedAt: null, item: { login: null } };
    const report = analyze([empty1, empty2, kept, trashed, note], bitsFrom({ "": 0 }));
    expect(report.reused).toEqual([]);
    expect(report.logins).toEqual([kept]);
    expect(report.weak).toEqual([]);
  });

  it("counts a trashed copy of a weak password out", () => {
    const trashed = login("abc", { deletedAt: 1 });
    expect(analyze([trashed], bitsFrom({ abc: 10 })).weak).toEqual([]);
  });
});

// ------------------------------------------------------------------ ranges

describe("range answers", () => {
  it("reads suffix:count lines and leaves padding out", () => {
    const body = ["0018A45C4D1DEF81644B54AB7F969B88D65:1", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2", ...padding(3)].join("\r\n");
    const range = parseRange(body)!;
    expect([...range]).toEqual([
      ["0018A45C4D1DEF81644B54AB7F969B88D65", 1],
      ["00D4F6E8FA6EECAD2A3AA415EEC418D38EC", 2],
    ]);
  });

  it("accepts lowercase hex, plain newlines and stray blank lines", () => {
    const range = parseRange("\n0018a45c4d1def81644b54ab7f969b88d65:12\n\n")!;
    expect(range.get("0018A45C4D1DEF81644B54AB7F969B88D65")).toBe(12);
  });

  it("ignores lines of the wrong shape", () => {
    const range = parseRange(["SHORT:1", "0018A45C4D1DEF81644B54AB7F969B88D65", "ZZ18A45C4D1DEF81644B54AB7F969B88D65:3", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:4"].join("\n"))!;
    expect([...range.keys()]).toEqual(["00D4F6E8FA6EECAD2A3AA415EEC418D38EC"]);
  });

  it("treats an answer without a single range line as no answer", () => {
    expect(parseRange("<!doctype html><title>Sign in to this network</title>")).toBeNull();
    expect(parseRange("")).toBeNull();
    // Only padding is still a real answer: nothing found.
    expect(parseRange(padding(2).join("\r\n"))?.size).toBe(0);
  });
});

// ------------------------------------------------------------------ breaches

describe("breach check", () => {
  it("hashes with SHA-1 (uppercase hex, UTF-8)", async () => {
    expect(await sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    expect(await sha1Hex("")).toBe("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    expect(await sha1Hex("pässwörd")).toMatch(/^[0-9A-F]{40}$/);
  });

  it("sends only the first 5 characters of the hash and matches the 35-character suffix", async () => {
    // SHA-1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    const suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
    const { fetch, calls } = stubFetch(() => [...padding(5), `${suffix}:3861`, ...padding(5, 1)].join("\r\n"));
    const result = await createBreachChecker(fetch).check(["password"]);

    expect(result.get("password")).toBe(3861);
    expect(calls).toHaveLength(1);
    const { url, init } = calls[0];
    expect(url).toBe(`${PWNED_RANGE_URL}5BAA6`);
    expect(url).not.toContain(suffix);
    expect(init.body).toBeUndefined();
    expect(init.method).toBe("GET");
    expect(new Headers(init.headers).get("Add-Padding")).toBe("true");
    expect(init.credentials).toBe("omit");
    expect(init.referrerPolicy).toBe("no-referrer");
    expect(init.cache).toBe("no-store");
  });

  it("reports 0 for passwords that are missing or only listed as padding", async () => {
    const digest = digestFrom({ listed: hash("ABCDE", "1"), padded: hash("ABCDE", "2"), missing: hash("ABCDE", "3") });
    const { fetch } = stubFetch(() => [`${"1".repeat(35)}:7`, `${"2".repeat(35)}:0`, ...padding(3)].join("\r\n"));
    const result = await createBreachChecker(fetch, { digest }).check(["listed", "padded", "missing"]);
    expect(Object.fromEntries(result)).toEqual({ listed: 7, padded: 0, missing: 0 });
  });

  it("requests each prefix once, skips empty and repeated passwords, and keeps answers until cleared", async () => {
    const digest = digestFrom({ one: hash("AAAAA", "1"), two: hash("AAAAA", "2"), three: hash("BBBBB", "3") });
    const { fetch, prefixes } = stubFetch((prefix) => (prefix === "AAAAA" ? `${"2".repeat(35)}:5` : padding(4).join("\r\n")));
    const checker = createBreachChecker(fetch, { digest });

    const first = await checker.check(["one", "two", "", "three", "one", "two"]);
    expect(prefixes().sort()).toEqual(["AAAAA", "BBBBB"]);
    expect(Object.fromEntries(first)).toEqual({ one: 0, two: 5, three: 0 });

    const again = await checker.check(["two", "three"]);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(Object.fromEntries(again)).toEqual({ two: 5, three: 0 });

    checker.clear();
    await checker.check(["three"]);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(prefixes()[2]).toBe("BBBBB");
  });

  it("checks nothing when there are no passwords", async () => {
    const { fetch } = stubFetch(() => "");
    const progress = vi.fn();
    const result = await createBreachChecker(fetch).check(["", ""], progress);
    expect(result.size).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
    expect(progress).toHaveBeenCalledWith(0, 0);
  });

  it(`runs at most ${PWNED_PARALLEL} requests at a time`, async () => {
    const table: Record<string, string> = {};
    for (let i = 0; i < 40; i++) table[`p${i}`] = hash(i.toString(16).padStart(5, "0"), "C");
    let inFlight = 0;
    let most = 0;
    const { fetch, prefixes } = stubFetch(async () => {
      inFlight++;
      most = Math.max(most, inFlight);
      await tick(Math.random() * 4);
      inFlight--;
      return padding(3).join("\r\n");
    });
    const checker = createBreachChecker(fetch, { digest: digestFrom(table) });
    const names = Object.keys(table);
    // Two overlapping checks share the same limit.
    await Promise.all([checker.check(names.slice(0, 25)), checker.check(names.slice(25))]);
    expect(most).toBe(PWNED_PARALLEL);
    expect(new Set(prefixes()).size).toBe(40);
    expect(prefixes()).toHaveLength(40);
  });

  it("honours a lower limit", async () => {
    const table = Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`p${i}`, hash(`0000${i}`, "D")]));
    let inFlight = 0;
    let most = 0;
    const { fetch } = stubFetch(async () => {
      most = Math.max(most, ++inFlight);
      await tick(1);
      inFlight--;
      return padding(1).join("\n");
    });
    await createBreachChecker(fetch, { digest: digestFrom(table), parallel: 2 }).check(Object.keys(table));
    expect(most).toBe(2);
  });

  it("reports progress in distinct passwords", async () => {
    const digest = digestFrom({ a: hash("11111", "1"), b: hash("11111", "2"), c: hash("22222", "3") });
    const { fetch } = stubFetch(() => padding(2).join("\r\n"));
    const progress: [number, number][] = [];
    await createBreachChecker(fetch, { digest }).check(["a", "b", "c", "a"], (done, total) => progress.push([done, total]));
    expect(progress[0]).toEqual([0, 3]);
    expect(progress.at(-1)).toEqual([3, 3]);
    expect(progress.map(([d]) => d)).toEqual([...progress.map(([d]) => d)].sort((x, y) => x - y));
  });

  it("fails with the HTTP status, and doesn't keep the failed prefix", async () => {
    let fail = true;
    const { fetch } = stubFetch(() => (fail ? new Response("busy", { status: 503 }) : padding(2).join("\r\n")));
    const checker = createBreachChecker(fetch);
    const error = await checker.check(["password"]).catch((e) => e);
    expect(error).toBeInstanceOf(BreachCheckError);
    expect(error).toMatchObject({ reason: "http", status: 503 });

    fail = false;
    expect((await checker.check(["password"])).get("password")).toBe(0);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("calls a request that never got an answer a network failure", async () => {
    const fetch = vi.fn<RangeFetch>(async () => {
      throw new TypeError("Failed to fetch");
    });
    const error = await createBreachChecker(fetch).check(["password"]).catch((e) => e);
    expect(error).toMatchObject({ reason: "network" });
    expect((error as Error).cause).toBeInstanceOf(TypeError);
  });

  it("calls an answer that isn't a range list invalid", async () => {
    const { fetch } = stubFetch(() => "<html>Sign in to continue</html>");
    await expect(createBreachChecker(fetch).check(["password"])).rejects.toMatchObject({ reason: "invalid" });
  });

  it("gives up on a request after the timeout", async () => {
    const fetch = vi.fn<RangeFetch>(
      (_url, init) => new Promise((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    );
    await expect(createBreachChecker(fetch, { timeoutMs: 10 }).check(["password"])).rejects.toMatchObject({ reason: "timeout" });
  });

  it("skips the check's remaining requests after the first failure", async () => {
    const table = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`p${i}`, hash(`9999${i}`, "E")]));
    const { fetch } = stubFetch(async () => {
      await tick(1);
      return new Response("", { status: 429 });
    });
    const error = await createBreachChecker(fetch, { digest: digestFrom(table), parallel: 1 })
      .check(Object.keys(table))
      .catch((e) => e);
    expect(error).toMatchObject({ reason: "http", status: 429 });
    await tick(20);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("stops a running check when cleared", async () => {
    const table = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`p${i}`, hash(i.toString(16).padStart(5, "7"), "F")]));
    const { fetch } = stubFetch(
      (_prefix, init) =>
        new Promise<string>((resolve, reject) => {
          const timer = setTimeout(() => resolve(padding(1).join("\n")), 50);
          init.signal?.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const checker = createBreachChecker(fetch, { digest: digestFrom(table) });
    const running = checker.check(Object.keys(table));
    await tick(5);
    checker.clear();
    await expect(running).rejects.toMatchObject({ name: "AbortError" });
    await tick(80);
    // Only the first slots were ever sent; the queued prefixes never went out.
    expect(fetch).toHaveBeenCalledTimes(PWNED_PARALLEL);
  });
});
