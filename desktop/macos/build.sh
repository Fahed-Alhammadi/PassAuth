#!/usr/bin/env bash
# Build PassAuth AutoFill for macOS (Release, universal arm64 + x86_64) into
#   desktop/macos/build/PassAuthAutoFill.appex
# for embedding in the desktop app at PassAuth.app/Contents/PlugIns/.
#
# Signing (optional):
#   MACOS_SIGN_IDENTITY   codesign identity, e.g. "Developer ID Application: … (JEXQBK3SQ5)"
#   MACOS_AUTOFILL_PROFILE path to the Developer ID provisioning profile for
#                          io.passauth.desktop.autofill (required with MACOS_SIGN_IDENTITY: the
#                          AutoFill and Keychain-group entitlements are restricted; the profile
#                          names the certificate it accepts: sign with that one)
#   MACOS_SIGN_KEYCHAIN    optional keychain holding the identity (e.g. a temporary CI keychain)
# Without MACOS_SIGN_IDENTITY the bundle is signed ad hoc with only the sandbox entitlements
# (builds and loads for UI checks, but macOS won't offer it for AutoFill).
# Needs: Xcode, XcodeGen, Rust (scripts/build-macos-core.sh runs if the core is missing;
# FORCE_CORE=1 rebuilds it).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cd "$here"

if [ "${FORCE_CORE:-0}" = 1 ] || [ ! -d Core/PassAuthCoreFFI.xcframework ] || [ ! -f Core/Sources/PassAuthCore.swift ]; then
  "$root/scripts/build-macos-core.sh"
fi

xcodegen generate --quiet

out="$here/build"
dd="$out/DerivedData"
rm -rf "$out/PassAuthAutoFill.appex"
mkdir -p "$out"
xcodebuild -project PassAuthAutoFill.xcodeproj -scheme PassAuthAutoFill -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath "$dd" \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO \
  build -quiet
ditto "$dd/Build/Products/Release/PassAuthAutoFill.appex" "$out/PassAuthAutoFill.appex"
appex="$out/PassAuthAutoFill.appex"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  profile="${MACOS_AUTOFILL_PROFILE:?MACOS_AUTOFILL_PROFILE must point to the provisioning profile}"
  [ -f "$profile" ] || { echo "build.sh: no provisioning profile at $profile" >&2; exit 1; }
  cp "$profile" "$appex/Contents/embedded.provisionprofile"
  kc=(); [ -n "${MACOS_SIGN_KEYCHAIN:-}" ] && kc=(--keychain "$MACOS_SIGN_KEYCHAIN")
  codesign --force --timestamp --options runtime ${kc[@]+"${kc[@]}"} \
    --entitlements "$here/AutoFill/AutoFill.entitlements" \
    --sign "$MACOS_SIGN_IDENTITY" "$appex"
else
  codesign --force --sign - --entitlements "$here/AutoFill/AutoFill-adhoc.entitlements" "$appex"
fi
codesign --verify --strict "$appex"

lipo -info "$appex/Contents/MacOS/PassAuthAutoFill"
echo "PassAuth AutoFill ready: $appex"
