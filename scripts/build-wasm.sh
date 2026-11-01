#!/usr/bin/env bash
# Build passauth-core for the browser and generate JS bindings.
# Usage: scripts/build-wasm.sh <out-dir> [<out-dir> ...]
set -euo pipefail
cd "$(dirname "$0")/.."
[ $# -ge 1 ] || { echo "usage: $0 <out-dir>..." >&2; exit 1; }

want="$(grep -A3 'name = "wasm-bindgen"' Cargo.lock | grep -m1 version | cut -d'"' -f2)"
have="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$want" != "$have" ]; then
  echo "wasm-bindgen CLI $want required (found ${have:-none}): cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi

cargo build --release --locked -p passauth-core-wasm --target wasm32-unknown-unknown
for out in "$@"; do
  mkdir -p "$out"
  wasm-bindgen --target web --out-dir "$out" --out-name passauth_core \
    target/wasm32-unknown-unknown/release/passauth_core_wasm.wasm
  if command -v wasm-opt >/dev/null; then
    wasm-opt -O3 --enable-bulk-memory --enable-nontrapping-float-to-int \
      "$out/passauth_core_bg.wasm" -o "$out/passauth_core_bg.wasm"
  fi
done
