#!/usr/bin/env bash
# Build the PassAuth core for Android and generate its Kotlin bindings.
#   scripts/build-android-core.sh            # release build (arm64-v8a + x86_64)
#   PROFILE=debug scripts/build-android-core.sh
# Needs: Rust with aarch64-linux-android and x86_64-linux-android targets,
# cargo-ndk, and an Android NDK (ANDROID_NDK_HOME or the newest one in $ANDROID_HOME/ndk).
set -euo pipefail
cd "$(dirname "$0")/.."

ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "$ANDROID_NDK_HOME" ] || { echo "Android NDK not found; set ANDROID_NDK_HOME" >&2; exit 1; }
export ANDROID_NDK_HOME

PROFILE="${PROFILE:-release}"
JNI=android/core/src/main/jniLibs
KOTLIN=android/core/src/main/kotlin
flag=(); [ "$PROFILE" = release ] && flag=(--release)

cargo ndk -t arm64-v8a -t x86_64 -P 34 -o "$JNI" build -p passauth-core-ffi "${flag[@]}"

# Bindings come from the host build of the same crate (library mode reads its metadata).
cargo build -p passauth-core-ffi "${flag[@]}"
lib="target/$PROFILE/libpassauth_ffi.dylib"; [ -f "$lib" ] || lib="target/$PROFILE/libpassauth_ffi.so"
rm -rf "$KOTLIN/io/passauth/core"
cargo run -q -p passauth-core-ffi --features cli --bin uniffi-bindgen -- \
  generate --library "$lib" --language kotlin --out-dir "$KOTLIN" --no-format
echo "Android core ready: $JNI, $KOTLIN/io/passauth/core"
