# Building the PassAuth Firefox add-on from source

This archive is the source of the PassAuth add-on uploaded to addons.mozilla.org. It is a subset of the public
repository https://github.com/Fahed-Alhammadi/PassAuth at the release tag named in `BUILD_INFO.txt`, which also lists
the exact tool versions the release was built with.

The add-on is TypeScript + React, bundled with Vite. Its cryptography is a Rust library (`crates/core`) compiled to
WebAssembly (`crates/core-wasm`) with `wasm-bindgen`. Nothing is downloaded at run time.

## Tools

- Rust (stable, version in `BUILD_INFO.txt`) with the `wasm32-unknown-unknown` target:
  `rustup target add wasm32-unknown-unknown`
- `wasm-bindgen` CLI, the version in `Cargo.lock`:
  `cargo install wasm-bindgen-cli --version <version> --locked`
- Node.js 26 and pnpm 10.34.9 (`npm install -g pnpm@10.34.9`)
- `zip`

`wasm-opt` is not used for the release build (the build script skips it when it isn't installed).

## Build

From the top folder of this archive:

```bash
scripts/build-wasm.sh web/src/wasm extension/src/wasm
(cd web && pnpm install --frozen-lockfile)
cd extension
pnpm install --frozen-lockfile
pnpm package:firefox
```

The add-on is `passauth-extension-firefox.zip`; its unpacked files are in `extension/dist-firefox/`. The zip is
reproducible: same file times, sorted entries (`extension/package.mjs`).

`web/` is needed because the add-on reuses the web vault's React components (imported as `@web/...`).

## Where things are

- `extension/src/background/` the background (event page in Firefox): vault, sync, fill, menus
- `extension/src/content/` content scripts (field detection, inline menu, save prompt)
- `extension/src/page/webauthn.ts` the passkey shim that runs in the page (`world: "MAIN"`)
- `extension/src/popup/` the toolbar popup
- `extension/firefox-manifest.mjs` makes the Firefox manifest from `extension/public/manifest.json`
- `crates/core/` the Rust core (encryption, site matching), `crates/core-wasm/` its WebAssembly bindings
