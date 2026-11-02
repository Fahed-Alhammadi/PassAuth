#!/usr/bin/env bash
# Build the PassAuth core for iOS and generate its Swift bindings.
#   scripts/build-ios-core.sh            # release build (device arm64 + simulator arm64)
#   PROFILE=debug scripts/build-ios-core.sh
# Needs: Xcode and Rust with aarch64-apple-ios and aarch64-apple-ios-sim targets.
# Output: ios/Core/PassAuthCoreFFI.xcframework (static library + C header and module map)
#         ios/Core/Sources/PassAuthCore.swift (the generated Swift API).
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
OUT=ios/Core
flag=(); [ "$PROFILE" = release ] && flag=(--release)
export IPHONEOS_DEPLOYMENT_TARGET=17.0

for t in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build -p passauth-core-ffi --lib --target "$t" "${flag[@]}"
done

# Bindings come from an unstripped host (debug) build, as for Android.
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

rm -rf "$OUT/PassAuthCoreFFI.xcframework"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/$PROFILE/libpassauth_ffi.a" -headers "$headers" \
  -library "target/aarch64-apple-ios-sim/$PROFILE/libpassauth_ffi.a" -headers "$headers" \
  -output "$OUT/PassAuthCoreFFI.xcframework" >/dev/null
echo "iOS core ready: $OUT/PassAuthCoreFFI.xcframework, $OUT/Sources/PassAuthCore.swift"
