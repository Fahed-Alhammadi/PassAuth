#!/usr/bin/env python3
"""Set TestFlight "What to Test" (en-US) for an uploaded build from ios/whatsnew/en-US.txt.

    scripts/testflight-notes.py <marketing version> <build number> <notes file>

Env: ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_PATH (App Store Connect API key, .p8).
Waits up to 40 minutes for App Store Connect to list the build after the upload.
Needs PyJWT with the crypto extra (pip install "pyjwt[crypto]").
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt

API = "https://api.appstoreconnect.apple.com/v1"
BUNDLE_ID = "io.passauth.app"
LOCALE = "en-US"


def token() -> str:
    now = int(time.time())
    with open(os.environ["ASC_KEY_PATH"]) as f:
        key = f.read()
    return jwt.encode(
        {"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 15 * 60, "aud": "appstoreconnect-v1"},
        key,
        algorithm="ES256",
        headers={"kid": os.environ["ASC_KEY_ID"], "typ": "JWT"},
    )


def call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {path} failed: HTTP {e.code} {e.read().decode(errors='replace')[:500]}")


def main() -> None:
    version, build, notes_file = sys.argv[1:4]
    with open(notes_file, encoding="utf-8") as f:
        notes = f.read().strip()
    if not notes or len(notes) > 4000:
        sys.exit(f"{notes_file}: notes must be 1-4000 characters (got {len(notes)})")

    q = urllib.parse.urlencode({"filter[bundleId]": BUNDLE_ID})
    apps = call("GET", f"/apps?{q}")["data"]
    if not apps:
        sys.exit(f"no app with bundle id {BUNDLE_ID}")
    app_id = apps[0]["id"]

    q = urllib.parse.urlencode({"filter[app]": app_id, "filter[version]": build, "filter[preReleaseVersion.version]": version})
    build_id = None
    for _ in range(80):  # 80 × 30 s = 40 min
        found = call("GET", f"/builds?{q}")["data"]
        if found:
            build_id = found[0]["id"]
            break
        time.sleep(30)
    if not build_id:
        sys.exit(f"build {version} ({build}) did not appear in App Store Connect")

    existing = [
        loc for loc in call("GET", f"/builds/{build_id}/betaBuildLocalizations")["data"] if loc["attributes"]["locale"] == LOCALE
    ]
    if existing:
        call("PATCH", f"/betaBuildLocalizations/{existing[0]['id']}",
             {"data": {"type": "betaBuildLocalizations", "id": existing[0]["id"], "attributes": {"whatsNew": notes}}})
    else:
        call("POST", "/betaBuildLocalizations", {"data": {
            "type": "betaBuildLocalizations",
            "attributes": {"locale": LOCALE, "whatsNew": notes},
            "relationships": {"build": {"data": {"type": "builds", "id": build_id}}},
        }})
    print(f"What to Test set for {version} ({build})")


if __name__ == "__main__":
    main()
