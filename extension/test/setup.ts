// Every test file starts with a fresh fake `chrome` (modules that register listeners at import time need it first),
// and the real core (src/wasm, a browser build of crates/core-wasm) loaded: the site logic the worker calls is the
// core's, never a stand-in. Files that replace the core's crypto with test/fake-core.ts keep its site functions.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { initSync } from "../src/wasm/passauth_core";
import { installChrome } from "./chrome";

// A path, not a URL object: DOM test environments bring their own URL class, which Node's fs doesn't take.
initSync({ module: readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../src/wasm/passauth_core_bg.wasm")) });
installChrome();
