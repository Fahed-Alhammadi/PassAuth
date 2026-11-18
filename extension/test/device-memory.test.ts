// What this browser remembers to notice a rollback, as one stored record (background/device-memory.ts): reading
// ("missing" and "unreadable" are different things), and the record written (manifest memory merged with what is
// stored, never lowered; nothing written over a record that can't be read).

import { expect, test } from "vitest";
import { DEVICE_MEMORY_VERSION, type DeviceMemory, mergedDeviceMemory, readDeviceMemory } from "../src/background/device-memory";
import { emptyRevMemory } from "../src/background/item-revs";

const A = "a".repeat(43);
const B = "b".repeat(43);

const memory = (): DeviceMemory => {
  const revs = emptyRevMemory();
  revs.revs.set("i1", 3);
  revs.rolledBack.set("i1", "kept");
  return { revs, manifests: new Map([["v1", { version: 4, link: A }]]), trashSeen: new Map([["i2", 1000]]) };
};

test("reading: none stored is 'missing'; a record of this version is the memory; anything else is 'unreadable', never nothing", () => {
  for (const none of [undefined, null]) expect(readDeviceMemory(none)).toBe("missing");
  for (const bad of ["text", 7, [], {}, { v: 2, itemRevs: {} }, { itemRevs: { a: 1 } }]) expect(readDeviceMemory(bad), JSON.stringify(bad)).toBe("unreadable");
  const stored = mergedDeviceMemory(undefined, memory());
  expect(stored).toStrictEqual({ v: DEVICE_MEMORY_VERSION, itemRevs: { i1: 3 }, rolledBack: { i1: "kept" }, manifests: { v1: { version: 4, link: A } }, trashSeen: { i2: 1000 } });
  expect(readDeviceMemory(JSON.parse(JSON.stringify(stored)))).toStrictEqual(memory());
  // Entries that aren't ones are left out (the first format's bare manifest version is nothing remembered).
  const read = readDeviceMemory({ v: 1, itemRevs: { a: 2, b: -1 }, manifests: { old: 3, half: { version: 2 }, ok: { version: 2, link: B } }, trashSeen: { x: "y", z: 5 } });
  expect(read).not.toBe("unreadable");
  const m = read as DeviceMemory;
  expect([...m.revs.revs]).toStrictEqual([["a", 2]]);
  expect([...m.manifests]).toStrictEqual([["ok", { version: 2, link: B }]]);
  expect([...m.trashSeen]).toStrictEqual([["z", 5]]);
  expect(mergedDeviceMemory(null, { revs: emptyRevMemory(), manifests: new Map(), trashSeen: new Map() })).toStrictEqual({ v: 1 });
});

test("writing: the manifest memory is merged with what is stored (higher version; a link never replaced at its version); a record that can't be read is never overwritten", () => {
  const stored = { v: 1, itemRevs: { old: 9 }, manifests: { v1: { version: 4, link: B }, v2: { version: 7, link: B }, v3: { version: 1, link: B } }, trashSeen: { old: 1 } };
  const mine = memory();
  mine.manifests.set("v2", { version: 6, link: A });
  mine.manifests.set("v3", { version: 2, link: A });
  const next = mergedDeviceMemory(stored, mine) as { manifests: unknown; itemRevs: unknown; trashSeen: unknown };
  expect(next.manifests).toStrictEqual({
    v1: { version: 4, link: B }, // the same version: the stored link stays
    v2: { version: 7, link: B }, // never lowered
    v3: { version: 2, link: A }, // raised
  });
  // The counters and the trash times are this worker's own (it is the only writer).
  expect(next.itemRevs).toStrictEqual({ i1: 3 });
  expect(next.trashSeen).toStrictEqual({ i2: 1000 });
  for (const unreadable of ["garbage", { v: 9 }, []]) expect(mergedDeviceMemory(unreadable, mine)).toBe(unreadable);
});

test("ROUND 2: an acceptance ('Use the server's copy') lowers what is stored, and a copy from before it can't bring the old version back; a forgotten vault stays forgotten", () => {
  const stored = { v: 1, manifests: { v1: { version: 9, link: B }, v2: { version: 4, link: B, accepts: 1 }, v3: { accepts: 2 } } };
  const mine: DeviceMemory = {
    revs: emptyRevMemory(),
    manifests: new Map([
      ["v1", { version: 2, link: A, accepts: 1 }], // accepted here: replaces the stored 9
      ["v2", { version: 7, link: A }], // this worker's copy from before the stored acceptance
      ["v3", { version: 5, link: A, accepts: 1 }], // forgotten since, with a later acceptance
    ]),
    trashSeen: new Map(),
  };
  const next = mergedDeviceMemory(stored, mine) as { manifests: unknown };
  expect(next.manifests).toStrictEqual({ v1: { version: 2, link: A, accepts: 1 }, v2: { version: 4, link: B, accepts: 1 }, v3: { accepts: 2 } });
  // Read back: the forgotten vault is nothing remembered, with its counter.
  const read = readDeviceMemory(JSON.parse(JSON.stringify(next))) as DeviceMemory;
  expect([...read.manifests]).toStrictEqual([
    ["v1", { version: 2, link: A, accepts: 1 }],
    ["v2", { version: 4, link: B, accepts: 1 }],
    ["v3", { accepts: 2 }],
  ]);
});
