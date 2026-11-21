#!/usr/bin/env bash
# Build the desktop app's macOS extensions (Release, universal arm64 + x86_64) into
#   desktop/macos/build/PassAuthAutoFill.appex   (AutoFill: passwords, passkeys, codes)
#   desktop/macos/build/PassAuthSafari.appex     (the Safari extension; only when extension/dist-safari
#                                                 exists: `cd extension && pnpm build:safari`)
# for embedding in the desktop app at PassAuth.app/Contents/PlugIns/.
#
# Signing (optional):
#   MACOS_SIGN_IDENTITY   codesign identity, e.g. "Developer ID Application: … (JEXQBK3SQ5)"
#   MACOS_AUTOFILL_PROFILE path to the Developer ID provisioning profile for
#                          io.passauth.desktop.autofill (required with MACOS_SIGN_IDENTITY: the
#                          AutoFill and Keychain-group entitlements are restricted; the profile
#                          names the certificate it accepts: sign with that one)
#   MACOS_SAFARI_PROFILE   path to the Developer ID provisioning profile for io.passauth.desktop.safari
#                          (its Keychain group, to read the desktop app's hand-off, is restricted too);
#                          without it a signed build leaves the Safari extension out
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

# The Safari extension (sandboxed, like every app extension; Safari lists it from the desktop app).
safari="$out/PassAuthSafari.appex"
rm -rf "$safari"
if [ ! -f "$root/extension/dist-safari/manifest.json" ]; then
  echo "build.sh: extension/dist-safari is missing: no Safari extension (cd extension && pnpm build:safari)"
  exit 0
fi
if [ -n "${MACOS_SIGN_IDENTITY:-}" ] && [ ! -f "${MACOS_SAFARI_PROFILE:-/nonexistent}" ]; then
  echo "build.sh: MACOS_SAFARI_PROFILE is not set: no Safari extension in this signed build"
  exit 0
fi
xcodebuild -project PassAuthAutoFill.xcodeproj -scheme PassAuthSafari -configuration Release \
  -destination 'generic/platform=macOS' -derivedDataPath "$dd" \
  ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO \
  build -quiet
ditto "$dd/Build/Products/Release/PassAuthSafari.appex" "$safari"
if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  cp "$MACOS_SAFARI_PROFILE" "$safari/Contents/embedded.provisionprofile"
  codesign --force --timestamp --options runtime ${kc[@]+"${kc[@]}"} \
    --entitlements "$here/Safari/Safari.entitlements" \
    --sign "$MACOS_SIGN_IDENTITY" "$safari"
else
  codesign --force --sign - --entitlements "$here/Safari/Safari-adhoc.entitlements" "$safari"
fi
codesign --verify --strict "$safari"
lipo -info "$safari/Contents/MacOS/PassAuthSafari"
echo "PassAuth Safari extension ready: $safari"
