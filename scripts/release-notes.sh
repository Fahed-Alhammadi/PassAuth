#!/usr/bin/env bash
# Print Markdown release notes for one part's tag: the commits since that part's previous tag
# that touched the given paths (release bump commits left out), plus a compare link.
#
#   scripts/release-notes.sh server-v0.4.6 crates web Dockerfile ...
#
# The previous tag is the highest older <part>-vX.Y.Z tag, or else the highest old combined
# vX.Y.Z tag (≤ 0.4.3, when all parts were released together). Needs the full git history.
set -euo pipefail
cd "$(dirname "$0")/.."

tag=${1:?usage: $0 <part>-vX.Y.Z <path>...}
shift
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "no tag $tag" >&2; exit 1; }
part=${tag%-v*}
repo=${GITHUB_REPOSITORY:-Fahed-Alhammadi/PassAuth}

prev=$(git tag --list "$part-v*" --sort=-v:refname | grep -vx -- "$tag" | head -1 || true)
[ -n "$prev" ] || prev=$(git tag --list 'v[0-9]*' --sort=-v:refname | head -1 || true)

if [ -n "$prev" ]; then
  range="$prev..$tag"
else
  range="$tag"
fi

changes=$(git log --no-merges --format='- %s (%h)' "$range" -- "$@" | grep -v -E '^- Release ' || true)

echo "## Changes"
echo
if [ -n "$changes" ]; then
  echo "$changes"
else
  echo "- Maintenance release."
fi
if [ -n "$prev" ]; then
  echo
  echo "**Full changelog:** https://github.com/$repo/compare/$prev...$tag"
fi
