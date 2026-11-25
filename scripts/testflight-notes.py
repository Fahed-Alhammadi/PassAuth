#!/usr/bin/env python3
"""Set TestFlight "What to Test" (en-US) for an uploaded build from ios/whatsnew/en-US.txt,
answer the build's export compliance question (see USES_NON_EXEMPT_ENCRYPTION), then add it to
the external tester group (EXTERNAL_GROUP, the public TestFlight link) and send it to Beta App
Review. Each step is skipped when it is already done, so the script can be run again.

    scripts/testflight-notes.py <marketing version> <build number> <notes file>

Env: ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_PATH (App Store Connect API key, .p8).
Waits up to 40 minutes for App Store Connect to list the build after the upload, and up to
30 more for it to finish processing before answering export compliance.
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
# App Store Connect's export compliance answer. PassAuth encrypts vaults in its own Rust core with
# standard, published algorithms (ChaCha20-Poly1305, AES, X25519, Argon2, OPAQUE) and is not sold
# in France. For App Store Connect that is "exempt" (no documents): Apple only accepts an
# encryption declaration for proprietary cryptography, or standard cryptography sold in France
# (409 otherwise), and a "true" without a declaration is silently dropped. So the answer is False,
# as on every build so far. Separate US obligation: yearly BIS self-classification report (ECCN
# 5D992.c) by February 1. Apple refuses to change the answer once a build has one, so it is set
# here right after processing, before anyone answers by hand.
USES_NON_EXEMPT_ENCRYPTION = False
# External TestFlight group with the public link (https://testflight.apple.com/join/MGBhGbhp).
EXTERNAL_GROUP = os.environ.get("TESTFLIGHT_EXTERNAL_GROUP", "Testing")


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

    for _ in range(60):  # 60 × 30 s = 30 min
        attrs = call("GET", f"/builds/{build_id}")["data"]["attributes"]
        if attrs["processingState"] != "PROCESSING":
            break
        time.sleep(30)
    if attrs["processingState"] != "VALID":
        sys.exit(f"build {version} ({build}) is {attrs['processingState']}: answer export compliance in App Store Connect")
    if attrs["usesNonExemptEncryption"] is None:
        call("PATCH", f"/builds/{build_id}",
             {"data": {"type": "builds", "id": build_id, "attributes": {"usesNonExemptEncryption": USES_NON_EXEMPT_ENCRYPTION}}})
        attrs = call("GET", f"/builds/{build_id}")["data"]["attributes"]
    if attrs["usesNonExemptEncryption"] is not USES_NON_EXEMPT_ENCRYPTION:
        sys.exit(f"build {version} ({build}): export compliance is {attrs['usesNonExemptEncryption']}, "
                 f"expected {USES_NON_EXEMPT_ENCRYPTION} (Apple can't change it: upload a new build)")
    print(f"Export compliance set for {version} ({build}): non-exempt encryption = {USES_NON_EXEMPT_ENCRYPTION}")

    groups = [g for g in call("GET", f"/apps/{app_id}/betaGroups?limit=200")["data"]
              if g["attributes"]["name"] == EXTERNAL_GROUP and not g["attributes"]["isInternalGroup"]]
    if not groups:
        sys.exit(f"no external TestFlight group named {EXTERNAL_GROUP!r}")
    group_id = groups[0]["id"]
    in_group = {b["id"] for b in call("GET", f"/betaGroups/{group_id}/builds?limit=200")["data"]}
    if build_id not in in_group:
        call("POST", f"/betaGroups/{group_id}/relationships/builds", {"data": [{"type": "builds", "id": build_id}]})
    print(f"Added {version} ({build}) to the TestFlight group {EXTERNAL_GROUP!r}")

    state = call("GET", f"/builds/{build_id}/buildBetaDetail")["data"]["attributes"]["externalBuildState"]
    if state == "READY_FOR_BETA_SUBMISSION":
        call("POST", "/betaAppReviewSubmissions",
             {"data": {"type": "betaAppReviewSubmissions", "relationships": {"build": {"data": {"type": "builds", "id": build_id}}}}})
        state = call("GET", f"/builds/{build_id}/buildBetaDetail")["data"]["attributes"]["externalBuildState"]
    print(f"External testing for {version} ({build}): {state}")


if __name__ == "__main__":
    main()
