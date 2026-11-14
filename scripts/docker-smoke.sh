#!/usr/bin/env bash
# Smoke test of the server image with only the settings .env.example asks for and the
# hardened flags from docker-compose.yml:
#   - starts as root, gives a fresh data volume to PUID:PGID and runs as that user
#   - admin sign-in with PASSAUTH_ADMIN_USERNAME/PASSWORD works over plain HTTP
#   - an old compose file (`user:` and no cap_add) still runs
#   - without the capabilities it stops with a clear error
# Usage: scripts/docker-smoke.sh [image]   (default passauth:dev)
set -euo pipefail

image="${1:-passauth:dev}"
run="passauth-smoke-$$"
port="${SMOKE_PORT:-18080}"
base="http://127.0.0.1:${port}"
env_file="$(mktemp)"
hardened=(--read-only --tmpfs /tmp --security-opt no-new-privileges:true --cap-drop ALL)

cleanup() {
  docker rm -f "$run" "$run-old" >/dev/null 2>&1 || true
  docker volume rm "$run" "$run-old" >/dev/null 2>&1 || true
  rm -f "$env_file"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  docker logs "$run" 2>&1 | tail -n 30 >&2 || true
  exit 1
}

wait_healthy() {
  for _ in $(seq 1 60); do
    curl -fsS "$base/api/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

sed -e 's/^PUID=.*/PUID=1234/' -e 's/^PGID=.*/PGID=2345/' \
  -e 's/^PASSAUTH_ADMIN_PASSWORD=.*/PASSAUTH_ADMIN_PASSWORD=smoke-test-admin-password/' \
  .env.example >"$env_file"

echo "== new compose: starts as root, runs as PUID:PGID"
docker run -d --name "$run" --env-file "$env_file" -p "127.0.0.1:${port}:8080" \
  -v "$run:/data" "${hardened[@]}" --cap-add CHOWN --cap-add SETUID --cap-add SETGID \
  "$image" >/dev/null
wait_healthy || fail "server did not become healthy"
ids="$(docker top "$run" -o pid,uid,gid | awk 'NR == 2 { print $2 ":" $3 }')"
[ "$ids" = "1234:2345" ] || fail "server runs as $ids, expected 1234:2345"
owner="$(docker run --rm -v "$run:/data" busybox:1.37 stat -c '%u:%g' /data /data/passauth.db | sort -u)"
[ "$owner" = "1234:2345" ] || fail "data folder owned by $owner, expected 1234:2345"

echo "== admin sign-in over plain HTTP"
mode="$(curl -fsS "$base/api/admin/login")"
case "$mode" in *'"mode":"password"'*) ;; *) fail "admin login mode: $mode" ;; esac
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d '{"username":"admin","password":"wrong-password-here"}' "$base/api/admin/login")"
[ "$code" = 401 ] || fail "wrong admin password answered $code"
token="$(curl -fsS -H 'content-type: application/json' \
  -d '{"username":"admin","password":"smoke-test-admin-password"}' "$base/api/admin/login" |
  sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || fail "admin sign-in returned no token"
curl -fsS -H "authorization: Bearer $token" "$base/api/admin/overview" | grep -q '"admin_login":"password"' ||
  fail "admin overview with the session token failed"
docker rm -f "$run" >/dev/null

echo "== old compose: user: 1000:1000 and no cap_add"
docker run -d --name "$run-old" --user 1000:1000 -p "127.0.0.1:${port}:8080" \
  -v "$run-old:/data" "${hardened[@]}" "$image" >/dev/null
wait_healthy || { docker logs "$run-old" 2>&1 | tail -n 30 >&2; fail "old-style container did not become healthy"; }
docker rm -f "$run-old" >/dev/null

echo "== root without the capabilities: clear error"
if out="$(docker run --rm --env-file "$env_file" -v "$run:/data" "${hardened[@]}" "$image" 2>&1)"; then
  fail "started without CHOWN/SETUID/SETGID"
fi
case "$out" in *cap_add*) ;; *) fail "unclear error without capabilities: $out" ;; esac

echo "OK: image $image passed the smoke test"
