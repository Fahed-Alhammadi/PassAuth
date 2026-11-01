# Import formats

Every importer runs on the client, in `crates/core`, which is compiled to WASM. Plaintext exports never reach the server. Formats are learned from public docs and from reading open-source importers; no code is copied.

## Bitwarden / Vaultwarden
Vaultwarden has no export format of its own; it uses the Bitwarden clients' format.

### Plain JSON
`{"encrypted":false,"folders":[{id,name}],"items":[…]}`. An organization export has `collections:[{id,organizationId,name}]` instead of `folders`. Nested folders are written in the name with `/`, as in `Work/Infra`.

Item fields:
- `id, folderId, collectionIds[], type, name, notes, favorite, reprompt (0|1)`
- `fields[{name,value,type,linkedId}]`
- `passwordHistory[{password,lastUsedDate}]`
- `revisionDate, creationDate, deletedDate, archivedDate`

`type` decides which sub-object the item has:

| `type` | Sub-object |
|---|---|
| 1 | `login` |
| 2 | `secureNote` |
| 3 | `card{cardholderName,brand,number,expMonth,expYear,code}` |
| 4 | `identity{…}` |
| 5 | `sshKey{privateKey,publicKey,keyFingerprint}` |
| 6 | `bankAccount` |
| 7 | `driversLicense` |
| 8 | `passport` |

The `login` object:
- `{username,password,totp,uris[{uri,match}],fido2Credentials[]}`
- `match`: null default, 0 Domain, 1 Host, 2 StartsWith, 3 Exact, 4 RegEx, 5 Never.
- `fido2Credentials[]`:
  - Fields: `{credentialId ("<uuid>" or "b64.<b64url>"), keyType, keyAlgorithm:"ECDSA", keyCurve:"P-256", keyValue (b64url PKCS#8), rpId, rpName, userHandle (b64url), userName, userDisplayName, counter, discoverable, creationDate}`.
  - `counter` and `discoverable` are **strings**.

Custom field `type` values:
- 0 Text, 1 Hidden, 2 Boolean (`"true"` or `"false"`).
- 3 Linked: `linkedId` 100 means username, 101 means password, and there is no value.

The zip export contains `data.json` plus `attachments/<item>/<file>`.

### CSV
- Header: `folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp`. An organization export has `collections` instead of `folder,favorite`.
- Columns: look them up by header name, because older exports lack `archivedDate`.
- `type`: `login` or `note`.
- `login_uri`: comma-joined, so parse that cell as its own CSV row.
- `fields`: newline-separated `name: value`; split each line on the **last** `": "`.

### Encrypted JSON
- **Account-restricted** has `encrypted:true` and no `passwordProtected`. It can't be decrypted outside Bitwarden; tell the user to export password-protected or plain instead.
- **Password-protected** looks like `{"encrypted":true,"passwordProtected":true,"salt","kdfType","kdfIterations","kdfMemory","kdfParallelism","encKeyValidation_DO_NOT_EDIT","data"}`. To decrypt it:
  1. Treat `salt` as UTF-8 bytes. It is **not** base64.
  2. Derive the key:
     - `kdfType` 0: PBKDF2-HMAC-SHA256(pw, salt, iterations, 32).
     - `kdfType` 1: Argon2id v0x13(pw, salt=SHA256(salt), t=iterations, m=kdfMemory MiB, p=parallelism, 32).
  3. Clamp the parameters before deriving: PBKDF2 5k–2M; Argon2 t 2–10, m 16–1024 MiB, p 1–16.
  4. Stretch the key: encKey = HKDF-Expand-SHA256(k, "enc", 32) and macKey = HKDF-Expand(k, "mac", 32).
  5. Read each EncString `2.` as base64 `iv|ct|mac`. Verify HMAC-SHA256(macKey, iv‖ct) in constant time, then decrypt AES-256-CBC with PKCS7.
  6. Decrypt `encKeyValidation_DO_NOT_EDIT` first; if that fails, the password is wrong. Then `data` decrypts to the plain JSON above.

## 1Password

### .1pux
A zip containing `export.attributes`, `export.data` (JSON) and `files/<documentId>__<fileName>`. Inside `export.data`:
- `accounts[].vaults[{attrs{uuid,name,type}, items[]}]`
- Each item: `{uuid,favIndex,createdAt,updatedAt,state:"active|archived",categoryUuid,overview{title,url,urls[{label,url}],tags[]},details{loginFields[],notesPlain,password,passwordHistory[{value,time}],sections[{title,fields[{title,id,value{…}}]}],documentAttributes}}`

`categoryUuid` codes:

| Code | Category | Code | Category |
|---|---|---|---|
| 001 | Login | 104 | OutdoorLicense |
| 002 | CreditCard | 105 | Membership |
| 003 | SecureNote | 106 | Passport |
| 004 | Identity | 107 | Rewards |
| 005 | Password (secret in `details.password`) | 108 | SSN |
| 006 | Document | 109 | WirelessRouter |
| 100 | SoftwareLicense | 110 | Server |
| 101 | BankAccount | 111 | EmailAccount |
| 102 | Database | 112 | API Credential |
| 103 | DriversLicense | 113 | MedicalRecord |
| | | 114 | SSH Key |

`loginFields[]`:
- `designation` `username` or `password` marks the main credentials.
- `fieldType` codes: T text, E email, U url, N number, P password, A textarea, TEL phone, C checkbox (checked when `value` is non-empty).

Section field `value` objects have exactly one key:
- Text: `string`, `concealed`, `email{email_address}`, `phone`, `url`.
- Dates: `date` (unix seconds), `monthYear` (YYYYMM).
- `totp`: an `otpauth://` URL or a bare seed. Wrap a bare seed as `otpauth://totp/<title>?secret=`.
- Structured: `address{street,city,state,zip,country}`, `sshKey{privateKey,metadata{publicKey,fingerprint}}`.
- Other: `menu`, `creditCardType`, `creditCardNumber`, `reference`, `file{fileName,documentId}`.

Folders: none. Use the vault name, falling back to `tags[0]`. Passkeys are **not** included in 1PUX exports.

### CSV (1Password 8)
- Header: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`.
- Tags are `;`-separated; Favorite and Archived are `true`/`false`.
- 1Password 7 CSVs (`UUID,TITLE,USERNAME,…`) are legacy; support them best-effort.

## Passbolt

### CSV
- Every cell is quoted, lines end in CRLF, and there is a single URL.
- Folder paths use `/`; a literal `/` inside a folder name appears as ` / `.
- Variant headers:
  - KeePass-style: `"Title","Username","URL","Password","Notes","Group","TOTP"` (TOTP is an `otpauth://` URL).
  - Bitwarden-style: `name,login_username,login_uri,login_password,notes,folder,login_totp`.
  - LastPass-style: `url,username,password,totp,extra,name,grouping,fav`.
  - 1Password-style: `Title,Username,Url,Password,Notes,Type`.
  - Chromium-style: `name,url,username,password`.

### KDBX
- KDBX4 written by kdbxweb. Root group `passbolt export`, with nested groups for folders.
- Unlocked with a password and/or a key file. Read it with the Rust `keepass` crate (pin the version).
- Entry fields: `Title, UserName, Password, URL, Notes`.
- Extra URLs: `KP2A_URL`, `KP2A_URL_2`, …
- Custom fields are other strings; Passbolt renames duplicates to `Name (1)`.
- TOTP is one of:
  - `otp` = an `otpauth://` URL, or
  - `TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`, `TimeOtp-Length`, `TimeOtp-Period`.
- Expiry is stored in `Times.Expires`.

## Mapping to the PassAuth item model

| PassAuth | BW JSON | BW CSV | 1PUX | 1P CSV | KDBX | Passbolt CSV |
|---|---|---|---|---|---|---|
| name | name | name | overview.title | Title | Title | Title |
| username | login.username | login_username | loginField designation=username | Username | UserName | Username |
| password | login.password | login_password | designation=password or details.password | Password | Password | Password |
| urls | login.uris[].uri | login_uri | overview.urls[].url, else url | Url | URL, KP2A_URL* | URL |
| totp | login.totp | login_totp | section value.totp | OTPAuth | otp or TimeOtp-* | TOTP |
| notes | notes | notes | details.notesPlain | Notes | Notes | Notes |
| fields | fields[] | fields | other loginFields + sections | — | other strings | — |
| folder | folders[].name | folder | vault name / tags[0] | Tags | group path | Group |
| passkeys | login.fido2Credentials | — | — | — | — | — |

## PassAuth export (`crates/core/src/export.rs`)

Every client exports through the core, and `import::import` reads the results back (format `pass_auth_json`).

- **JSON:** `{"format":"passauth","version":1,"exported_at":<unix>,"items":[<Item>…]}`. Contains every item kind, as the same item JSON the clients encrypt.
- **Password-protected JSON:** `{"format":"passauth-encrypted","version":1,"kdf":{memory_kib,iterations,parallelism,salt},"data":"<base64url>"}`.
  - `data` is the JSON above, encrypted with XChaCha20-Poly1305 (AAD `passauth/export/v1`) under a key derived from the export password by Argon2id with the account defaults.
  - Export passwords need at least 10 characters.
- **CSV:** columns `folder,favorite,type,name,notes,login_uri,login_username,login_password,login_totp`, containing logins and secure notes only. Several website addresses are joined with commas.
