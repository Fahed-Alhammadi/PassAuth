import Foundation
import PassAuthCore

/// Passkeys for the AutoFill credential provider. Keys, authenticator data and signatures come
/// from the Rust core (`passkeyCreate` / `passkeyAssert`: ES256, the PassAuth AAGUID, flags
/// UP|UV|BE|BS, counter 0), the same as the browser extension and the Android app. iOS checks
/// the website or app against the RP ID and hands over the `clientDataHash`, which is signed
/// as given.
public enum PasskeyLogic {
    public static let es256 = -7

    public static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// Unpadded or padded base64url (also accepts standard base64), nil if malformed.
    public static func b64urlDecode(_ s: String) -> Data? {
        var t = s.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.hasSuffix("=") { t.removeLast() }
        guard t.count % 4 != 1 else { return nil }
        t += String(repeating: "=", count: (4 - t.count % 4) % 4)
        return Data(base64Encoded: t)
    }

    /// The record stored in `login.passkeys[]`, like the extension's `createPasskey`.
    /// iOS doesn't pass the RP name or the user's display name: the RP ID and user name stand in.
    public static func record(rpId: String, userName: String, userHandle: Data, created: NewPasskey, now: Int64) -> Passkey {
        var p = Passkey()
        p.credentialId = b64url(created.credentialId)
        p.rpId = rpId.lowercased()
        p.rpName = rpId.lowercased()
        p.userHandle = b64url(userHandle)
        p.userName = userName
        p.userDisplayName = userName
        p.algorithm = es256
        p.privateKey = b64url(created.privateKeyPkcs8)
        p.counter = 0
        p.discoverable = true
        p.createdAt = now
        return p
    }

    /// A saved passkey for the RP is in the request's excluded credentials (refused after consent).
    public static func excludedExists(_ excluded: [Data], rpId: String, all: [Passkey]) -> Bool {
        guard !excluded.isEmpty else { return false }
        return all.contains { p in p.rpId.lowercased() == rpId.lowercased() && b64urlDecode(p.credentialId).map(excluded.contains) == true }
    }

    /// Passkeys usable for an assertion: same RP ID, ES256, listed in `allowed` or (none listed) discoverable.
    public static func matching(rpId: String, allowed: [Data], _ all: [(Entry, Passkey)]) -> [(Entry, Passkey)] {
        all.filter { _, p in
            guard p.rpId.lowercased() == rpId.lowercased(), p.algorithm == es256 else { return false }
            if allowed.isEmpty { return p.discoverable }
            return b64urlDecode(p.credentialId).map(allowed.contains) ?? false
        }
    }

    public enum StorePlan: Sendable {
        /// Add the passkey to this login (same site and user name).
        case attach(Entry, Item)
        /// A new login for `https://<rpId>`.
        case create(Item)
    }

    /// Where a new passkey goes (the extension's `storePasskey`): the writable login for the same
    /// site (base domain of the RP ID) and user name, else a new login for `https://<rpId>`.
    public static func storePlan(_ vault: VaultData, _ p: Passkey) -> StorePlan {
        let site = UrlMatcher.baseDomain(p.rpId)
        let existing = vault.entries.first { e in
            guard let l = e.item.login, vault.canWrite(e), l.username.lowercased() == p.userName.lowercased() else { return false }
            return l.urls.contains { u in
                guard let parsed = UrlMatcher.parse(u.url), parsed.scheme == "http" || parsed.scheme == "https" else { return false }
                return UrlMatcher.baseDomain(parsed.hostname) == site
            }
        }
        if let e = existing, var l = e.item.login {
            var item = e.item
            l.passkeys.append(p)
            item.login = l
            return .attach(e, item)
        }
        var login = Login(username: p.userName, password: "", urls: [LoginUrl(url: "https://\(p.rpId)", match: .default)])
        login.passkeys = [p]
        return .create(Item(name: p.rpName.isEmpty ? p.rpId : p.rpName, login: login))
    }
}
