#!/bin/sh
# Build phase of the PassAuthSafari target: copies the Safari build of the extension
# (extension/dist-safari, made by `cd extension && pnpm build:safari`) into the extension bundle's
# Resources, where Safari reads manifest.json.
set -eu
src="$SRCROOT/../extension/dist-safari"
if [ ! -f "$src/manifest.json" ]; then
  echo "error: extension/dist-safari is missing. Run: cd extension && pnpm build:safari" >&2
  exit 1
fi
dest="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
mkdir -p "$dest"
# On iOS the resources folder is the bundle root (flat bundle): copy over, never delete.
cp -R "$src/." "$dest/"
