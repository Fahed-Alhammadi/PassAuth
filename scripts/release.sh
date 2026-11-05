#!/usr/bin/env bash
# Bump one part's version, commit only its version files, and tag it locally.
#
#   scripts/release.sh server    X.Y.Z   Cargo.toml (+ Cargo.lock) + web/package.json  -> server-X.Y.Z    (GHCR X.Y.Z + latest; notes added to CHANGELOG.md)
#   scripts/release.sh extension X.Y.Z   extension/package.json + manifest.json        -> extension-X.Y.Z (Chrome Web Store)
#   scripts/release.sh ios       X.Y.Z   ios/VERSION                                    -> ios-X.Y.Z       (TestFlight)
#   scripts/release.sh android   X.Y.Z   android/VERSION                                -> android-X.Y.Z   (Play internal testing)
#
# ios/android also need updated "What's new" notes, committed before running this:
# ios/whatsnew/en-US.txt (TestFlight "What to Test", ≤4000 chars) and
# android/whatsnew/whatsnew-en-US (Play release notes, ≤500 chars).
#
# Then: git push origin main, wait for CI, git push origin <tag>.
# The new version must be higher than the current one (stores reject lower build numbers).
set -euo pipefail
cd "$(dirname "$0")/.."

part=${1:-} version=${2:-}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 server|extension|ios|android X.Y.Z" >&2; exit 1; }

json_version() { node -p "require('./$1').version"; }
# Replace only the top-level "version" value, keeping the file's formatting.
set_json_version() {
  node -e "const fs=require('fs'),f='$1',s=fs.readFileSync(f,'utf8'),t=s.replace(/^(  \"version\": )\"[^\"]*\"/m,'\$1\"$2\"');
    if(t===s||JSON.parse(t).version!=='$2')throw new Error('no top-level version in '+f);fs.writeFileSync(f,t)"
}

case "$part" in
  server)
    current=$(awk '/^\[workspace\.package\]/{s=1;next} /^\[/{s=0} s && /^version *=/{gsub(/[" ]/,"");sub(/version=/,"");print;exit}' Cargo.toml)
    files=(Cargo.toml Cargo.lock web/package.json) ;;
  extension)
    current=$(json_version extension/package.json)
    files=(extension/package.json extension/public/manifest.json) ;;
  ios | android)
    current=$(tr -d '[:space:]' < "$part/VERSION")
    files=("$part/VERSION") ;;
  *) echo "usage: $0 server|extension|ios|android X.Y.Z" >&2; exit 1 ;;
esac

if [ "$(printf '%s\n%s\n' "$current" "$version" | sort -V | tail -1)" != "$version" ] || [ "$current" = "$version" ]; then
  echo "$part is at $current; the new version must be higher (got $version)" >&2
  exit 1
fi
tag="$part-$version"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && { echo "tag $tag already exists" >&2; exit 1; }

# Mobile releases carry "What's new" notes (TestFlight "What to Test", Play release notes):
# committed, non-empty, within the store limit, and changed since the previous release.
case "$part" in
  ios) notes=ios/whatsnew/en-US.txt max=4000 ;;
  android) notes=android/whatsnew/whatsnew-en-US max=500 ;;
  *) notes="" ;;
esac
if [ -n "$notes" ]; then
  [ -s "$notes" ] || { echo "write the release notes in $notes first" >&2; exit 1; }
  len=$(LC_ALL=en_US.UTF-8 wc -m < "$notes" | tr -d ' ')
  [ "$len" -le "$max" ] || { echo "$notes is $len characters; the store limit is $max" >&2; exit 1; }
  git diff --quiet HEAD -- "$notes" || { echo "commit $notes first" >&2; exit 1; }
  prev=$(scripts/release-notes.sh --tags "$part" | tail -1)
  if [ -n "$prev" ] && git cat-file -e "$prev:$notes" 2>/dev/null && git diff --quiet "$prev" HEAD -- "$notes"; then
    echo "$notes is unchanged since $prev: update it for $version" >&2
    exit 1
  fi
fi
[ "$part" != server ] || grep -q '^<!-- scripts/release.sh' CHANGELOG.md || { echo "CHANGELOG.md has no insertion marker" >&2; exit 1; }
if ! git diff --quiet -- "${files[@]}" CHANGELOG.md || ! git diff --cached --quiet; then
  echo "commit or stash changes to ${files[*]} (and anything staged) first" >&2
  exit 1
fi

case "$part" in
  server)
    awk -v v="$version" '/^\[workspace\.package\]/{s=1} /^\[/ && !/^\[workspace\.package\]/{s=0}
      s && /^version *=/ && !done {sub(/"[^"]*"/, "\"" v "\""); done=1} {print}' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
    cargo update --workspace --quiet
    set_json_version web/package.json "$version" ;;
  extension)
    set_json_version extension/package.json "$version"
    set_json_version extension/public/manifest.json "$version" ;;
  ios | android)
    echo "$version" > "$part/VERSION" ;;
esac

git add -- "${files[@]}"
git commit -q -m "Release $part $version"
git tag "$tag"

# Server: add this version's changes (commits since the previous server tag touching server
# paths) to CHANGELOG.md, in the same release commit.
if [ "$part" = server ]; then
  entry=$(mktemp)
  {
    echo "## $version ($(date -u +%F))"
    echo
    scripts/release-notes.sh "$tag" crates web Dockerfile Cargo.toml Cargo.lock .cargo docker-compose.yml |
      sed '1,2d; s/^\*\*Full changelog:\*\* \(.*\)$/[All changes](\1)/'
  } > "$entry"
  awk -v f="$entry" '{ print } /^<!-- scripts\/release.sh/ { print ""; while ((getline l < f) > 0) print l }' CHANGELOG.md > CHANGELOG.md.tmp
  mv CHANGELOG.md.tmp CHANGELOG.md
  rm -f "$entry"
  git add CHANGELOG.md
  git commit -q --amend --no-edit
  git tag -f "$tag" >/dev/null
fi
echo "Committed and tagged $tag ($part $current -> $version)."
echo "Next: git push origin main, wait for CI, then: git push origin $tag"
