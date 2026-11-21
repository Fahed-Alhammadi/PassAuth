// Checks the addons.mozilla.org API key (secrets AMO_JWT_ISSUER / AMO_JWT_SECRET): signs in and prints the account
// and, if it exists yet, the PassAuth add-on's listing status. Uploads nothing. Run by extension.yml's manual run.
// Usage: AMO_JWT_ISSUER=… AMO_JWT_SECRET=… node scripts/amo-check.mjs
import { createHmac, randomUUID } from "node:crypto";
import { GECKO_ID } from "../extension/firefox-manifest.mjs";

const { AMO_JWT_ISSUER: iss, AMO_JWT_SECRET: secret } = process.env;
if (!iss || !secret) throw new Error("AMO_JWT_ISSUER and AMO_JWT_SECRET must be set");
const API = "https://addons.mozilla.org/api/v5";

// AMO's JWT: HS256, issuer = API key, a unique jti, at most 5 minutes long.
const b64 = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");
function token() {
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss, jti: randomUUID(), iat: now, exp: now + 60 })}`;
  return `${body}.${createHmac("sha256", secret).update(body).digest("base64url")}`;
}
const get = (path) => fetch(`${API}${path}`, { headers: { authorization: `JWT ${token()}` } });

const me = await get("/accounts/profile/");
if (!me.ok) throw new Error(`AMO sign-in failed: HTTP ${me.status} ${await me.text()}`);
const profile = await me.json();
console.log(`AMO sign-in OK: account ${profile.id} (${profile.name || profile.username})`);

const addon = await get(`/addons/addon/${encodeURIComponent(GECKO_ID)}/`);
if (addon.status === 404) console.log(`Add-on ${GECKO_ID}: not on AMO yet (the first release tag creates it).`);
else if (!addon.ok) throw new Error(`Reading the add-on failed: HTTP ${addon.status}`);
else {
  const a = await addon.json();
  console.log(`Add-on ${GECKO_ID}: status ${a.status}, current version ${a.current_version?.version ?? "none"}, ${a.url}`);
}
