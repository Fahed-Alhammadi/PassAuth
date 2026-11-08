#!/usr/bin/env bash
# Build the PassAuth core for macOS (the desktop app's AutoFill extension) and generate its
# Swift bindings, like scripts/build-ios-core.sh does for iOS.
#   scripts/build-macos-core.sh            # release build, universal (arm64 + x86_64)
#   PROFILE=debug scripts/build-macos-core.sh
# Needs: Xcode and Rust with the aarch64-apple-darwin and x86_64-apple-darwin targets.
# Output (gitignored): desktop/macos/Core/PassAuthCoreFFI.xcframework (universal static library
#         + C header and module map) and desktop/macos/Core/Sources/PassAuthCore.swift.
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
OUT=desktop/macos/Core
flag=(); [ "$PROFILE" = release ] && flag=(--release)
export MACOSX_DEPLOYMENT_TARGET=14.0

for t in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target list --installed | grep -qx "$t" || rustup target add "$t"
  cargo build -p passauth-core-ffi --lib --target "$t" ${flag[@]+"${flag[@]}"}
done

# Bindings come from an unstripped host (debug) build, as for iOS and Android.
cargo build -p passauth-core-ffi
gen="$(mktemp -d)"
trap 'rm -rf "$gen"' EXIT
cargo run -q -p passauth-core-ffi --features cli --bin uniffi-bindgen -- \
  generate --library target/debug/libpassauth_ffi.dylib --language swift --out-dir "$gen"

headers="$gen/headers"
mkdir -p "$headers" "$OUT/Sources"
cp "$gen"/*FFI.h "$headers/"
# The framework's module is named after the header (PassAuthCoreFFI), which the Swift file imports.
cp "$gen"/*FFI.modulemap "$headers/module.modulemap"
cp "$gen/PassAuthCore.swift" "$OUT/Sources/PassAuthCore.swift"

lipo -create \
  "target/aarch64-apple-darwin/$PROFILE/libpassauth_ffi.a" \
  "target/x86_64-apple-darwin/$PROFILE/libpassauth_ffi.a" \
  -output "$gen/libpassauth_ffi.a"

rm -rf "$OUT/PassAuthCoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$gen/libpassauth_ffi.a" -headers "$headers" \
  -output "$OUT/PassAuthCoreFFI.xcframework" >/dev/null
echo "macOS core ready: $OUT/PassAuthCoreFFI.xcframework, $OUT/Sources/PassAuthCore.swift"
