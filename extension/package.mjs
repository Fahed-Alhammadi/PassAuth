// Packs dist/ into passauth-extension.zip (pnpm package) reproducibly: every file gets the same timestamp and
// permissions, entries are sorted, there are no directory entries, and `zip -X` leaves out extra attributes (owner
// ids, extended timestamps). The same build gives the same bytes on any machine.
import { execFileSync } from "node:child_process";
import { chmodSync, readdirSync, rmSync, utimesSync } from "node:fs";
import { join, relative, sep } from "node:path";

const DIST = "dist";
const OUT = "passauth-extension.zip";
// SOURCE_DATE_EPOCH (reproducible-builds.org) when set, else a fixed moment. Zip stores local time: TZ=UTC below.
const epoch = Number(process.env.SOURCE_DATE_EPOCH ?? 946684800); // 2000-01-01T00:00:00Z
if (!Number.isInteger(epoch) || epoch < 315532800) throw new Error("SOURCE_DATE_EPOCH must be a whole number of seconds after 1980");
const time = new Date(epoch * 1000);

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));
const files = walk(DIST)
  .map((f) => relative(DIST, f).split(sep).join("/"))
  .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
if (!files.includes("manifest.json")) throw new Error("dist/ has no manifest.json: build first (node build.mjs)");

for (const f of files) {
  chmodSync(join(DIST, f), 0o644);
  utimesSync(join(DIST, f), time, time);
}
rmSync(OUT, { force: true });
execFileSync("zip", ["-X", "-D", "-q", join("..", OUT), "-@"], { cwd: DIST, input: `${files.join("\n")}\n`, env: { ...process.env, TZ: "UTC" }, stdio: ["pipe", "inherit", "inherit"] });
console.log(`packed ${files.length} files into ${OUT}`);
