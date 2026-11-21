#!/bin/sh
# Build phase of the PassAuthSafari target (desktop/macos/project.yml): copies the Safari build of the
# extension (extension/dist-safari, made by `cd extension && pnpm build:safari`) into the extension
# bundle's Resources, where Safari reads manifest.json. PA_EXTENSION_DIST (a build setting) says where.
set -eu
src="${PA_EXTENSION_DIST:?the target sets PA_EXTENSION_DIST}"
if [ ! -f "$src/manifest.json" ]; then
  echo "error: extension/dist-safari is missing. Run: cd extension && pnpm build:safari" >&2
  exit 1
fi
dest="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH"
mkdir -p "$dest"
# Contents/Resources: copy over, never delete.
cp -R "$src/." "$dest/"
