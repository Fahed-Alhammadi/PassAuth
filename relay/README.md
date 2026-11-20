# PassAuth push relay

A Cloudflare Worker that sends **sign-in request notifications** to the PassAuth apps. A self-hosted PassAuth server
can't hold the app publisher's Apple push key, so when someone asks to sign in with another device, the server asks
this relay to wake the account's phones up. Approving still happens in the app (matching words and a 6-digit code).

- Address: `https://passauth-push.uaealhammadi.com` (the default in every PassAuth server; never change it).
- Stores nothing. It sees a device's push token and when to send, never an account, an email or vault data.
- The notification text is fixed: "Sign-in request. Someone wants to sign in to your PassAuth account on a new
  device. Open PassAuth to review."
- Server admins can turn push off or point to another relay on the admin page.

## API

`POST /v1/notify` with `{"platform":"apns","token":"<hex>","environment":"production"|"sandbox","kind":"auth_request"}`

| Status | Body | Meaning |
| --- | --- | --- |
| 202 | `{"ok":true}` | Sent to Apple |
| 410 | `{"error":"unregistered"}` | The token is dead: the server forgets it |
| 400 | `{"error":"bad_request"}` | Not the shape above |
| 413 | `{"error":"too_large"}` | Body over 1 KB |
| 429 | `{"error":"rate_limited"}` | 3 a minute per device, 300 a minute per server address (`Retry-After`) |
| 502 | `{"error":"upstream"}` | Apple or the network failed |

`GET /v1/health` → `{"ok":true}`

## Develop

```sh
cd relay
npm ci
npm test            # Apple faked
npm run typecheck
```

## Deploy

Needs `Keys/` (the Apple key `APNS_KEY_P8` and the Cloudflare token/account):

```sh
cd relay
export CLOUDFLARE_API_TOKEN="$(cat ../Keys/CLOUDFLARE_API_TOKEN)" CLOUDFLARE_ACCOUNT_ID="$(cat ../Keys/CLOUDFLARE_ACCOUNT_ID)"
umask 077; python3 -c 'import json,sys;print(json.dumps({"APNS_KEY_P8":open(sys.argv[1]).read()}))' ../Keys/APNS_KEY_P8 > /tmp/relay-secrets.json
npx cf deploy --secrets-file /tmp/relay-secrets.json; rm /tmp/relay-secrets.json
```

The key ID, team ID and app id are plain values in `cloudflare.config.ts`; the key itself is only ever a Worker
secret.
