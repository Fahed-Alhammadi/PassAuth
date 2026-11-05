#!/usr/bin/env bash
# Print Markdown release notes for one part's tag: the commits since that part's previous tag
# that touched the given paths (release bump commits left out), plus a compare link.
#
#   scripts/release-notes.sh server-0.4.6 crates web Dockerfile ...
#   scripts/release-notes.sh --tags server     # that part's tags, oldest first
#
# Tags are <part>-X.Y.Z (until 2026-11-05: <part>-vX.Y.Z). The previous tag is the highest
# other tag of the same part in either form, or else the highest old combined
# vX.Y.Z tag (≤ 0.4.3, when all parts were released together). Needs the full git history.
set -euo pipefail
cd "$(dirname "$0")/.."

# All tags of one part, both forms, sorted by version.
part_tags() {
  git tag --list "$1-[0-9]*" "$1-v[0-9]*" |
    awk -v n=$((${#1} + 2)) '{ v = substr($0, n); sub(/^v/, "", v); print v "\t" $0 }' |
    sort -t $'\t' -k1,1V | cut -f2
}
if [ "${1:-}" = --tags ]; then part_tags "${2:?usage: $0 --tags <part>}"; exit; fi

tag=${1:?usage: $0 <part>-X.Y.Z <path>...}
shift
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "no tag $tag" >&2; exit 1; }
part=${tag%%-[0-9v]*}
repo=${GITHUB_REPOSITORY:-Fahed-Alhammadi/PassAuth}

prev=$(part_tags "$part" | grep -vx -- "$tag" | tail -1 || true)
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
