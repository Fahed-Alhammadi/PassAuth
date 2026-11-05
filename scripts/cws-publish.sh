#!/usr/bin/env bash
# Upload an extension zip to the Chrome Web Store and submit it for review (API v2).
# Approved versions go live automatically. Used by .github/workflows/extension.yml.
#
#   CWS_SERVICE_ACCOUNT_JSON  service account JSON key (added under Account in the Developer Dashboard)
#   CWS_PUBLISHER_ID          Developer Dashboard → Publisher → Settings
#   CWS_ITEM_ID               the extension ID (end of the store listing URL)
#
# Usage: scripts/cws-publish.sh passauth-extension-X.Y.Z.zip
#        scripts/cws-publish.sh --check   (sign in and print the store status only)
set -euo pipefail

zip="${1:?usage: $0 <zip> | --check}"
: "${CWS_SERVICE_ACCOUNT_JSON:?}" "${CWS_PUBLISHER_ID:?}" "${CWS_ITEM_ID:?}"
api="https://chromewebstore.googleapis.com"
item="publishers/$CWS_PUBLISHER_ID/items/$CWS_ITEM_ID"

# Access token: sign a JWT with the service account key and exchange it (no gcloud needed).
key="$(mktemp)"
trap 'rm -f "$key"' EXIT
jq -r .private_key <<<"$CWS_SERVICE_ACCOUNT_JSON" >"$key"
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now="$(date +%s)"
header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
claims="$(jq -nc --arg iss "$(jq -r .client_email <<<"$CWS_SERVICE_ACCOUNT_JSON")" --argjson iat "$now" \
  '{iss:$iss, scope:"https://www.googleapis.com/auth/chromewebstore",
    aud:"https://oauth2.googleapis.com/token", iat:$iat, exp:($iat + 3600)}' | b64url)"
sig="$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$key" | b64url)"
token="$(curl -sS --fail-with-body https://oauth2.googleapis.com/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer -d "assertion=$header.$claims.$sig" |
  jq -r .access_token)"
echo "::add-mask::$token"
auth=(-H "Authorization: Bearer $token")

status() { curl -sS --fail-with-body "${auth[@]}" "$api/v2/$item:fetchStatus"; }

if [ "$zip" = --check ]; then
  echo "Signed in as $(jq -r .client_email <<<"$CWS_SERVICE_ACCOUNT_JSON")"
  status | jq '{published: .publishedItemRevisionStatus, submitted: .submittedItemRevisionStatus}'
  exit 0
fi

# A newer release replaces a version still waiting for review.
if [ "$(status | jq -r '.submittedItemRevisionStatus.state // empty')" = PENDING_REVIEW ]; then
  echo "Cancelling the submission still pending review"
  curl -sS --fail-with-body "${auth[@]}" -X POST "$api/v2/$item:cancelSubmission" >/dev/null
fi

echo "Uploading $zip"
res="$(curl -sS --fail-with-body "${auth[@]}" -X POST -H "Content-Type: application/zip" \
  -T "$zip" "$api/upload/v2/$item:upload")"
echo "$res"
state="$(jq -r .uploadState <<<"$res")"
for _ in $(seq 30); do
  case "$state" in
    IN_PROGRESS | UPLOAD_IN_PROGRESS) sleep 10; state="$(status | jq -r .lastAsyncUploadState)" ;;
    *) break ;;
  esac
done
[ "$state" = SUCCEEDED ] || { echo "::error::Web Store upload ended in state $state"; exit 1; }

echo "Submitting for review"
res="$(curl -sS --fail-with-body "${auth[@]}" -X POST -H "Content-Type: application/json" \
  -d '{"publishType":"DEFAULT_PUBLISH"}' "$api/v2/$item:publish")"
echo "$res"
echo "Web Store state: $(jq -r .state <<<"$res")"
