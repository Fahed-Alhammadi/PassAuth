#!/usr/bin/env bash
# The source archive addons.mozilla.org needs next to each Firefox upload (the add-on is bundled and has a Rust core):
# only the files the build reads, as git has them (tracked + new, not ignored), plus BUILD_INFO.txt with the exact
# tool versions. Build steps: extension/FIREFOX_SOURCE.md (copied to the archive's top folder as README.md).
# Usage: scripts/firefox-source.sh <out.zip> [<release tag>]
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
tag="${2:-$(git describe --tags --always)}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

git ls-files -co --exclude-standard -- \
  Cargo.toml Cargo.lock .cargo crates scripts/build-wasm.sh testdata LICENSE web extension \
  | grep -v -E '(^|/)\.DS_Store$' \
  | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done > "$stage/files"
rsync -a --files-from="$stage/files" . "$stage/src/"
cp extension/FIREFOX_SOURCE.md "$stage/src/README.md"
{
  echo "Release: $tag ($(git rev-parse HEAD))"
  echo "Built on: $(uname -sm)"
  echo "rustc: $(rustc --version)"
  echo "cargo: $(cargo --version)"
  echo "wasm-bindgen: $(wasm-bindgen --version)"
  echo "wasm-opt: $(command -v wasm-opt >/dev/null && wasm-opt --version || echo 'not installed (not used)')"
  echo "node: $(node --version)"
  echo "pnpm: $(pnpm --version)"
  echo "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:-unset (zip times fixed at 2000-01-01)}"
} > "$stage/src/BUILD_INFO.txt"
rm -f "$out"
(cd "$stage/src" && zip -X -q -r "$out" .)
echo "source archive: $out ($(du -h "$out" | cut -f1))"
