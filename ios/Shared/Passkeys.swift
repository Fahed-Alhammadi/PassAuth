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
        /// Add the passkey to this login (the one the user chose).
        case attach(Entry, Item)
        /// A new login for `https://<rpId>`.
        case create(Item)
    }

    /// Save target meaning "create a new login" (never an item id: those are UUIDs).
    public static let newLogin = "new"

    /// Hostnames of a login's http(s) URLs, lowercase, without a trailing dot.
    static func loginHosts(_ e: Entry) -> [String] {
        (e.item.login?.urls ?? []).compactMap { u in
            guard let p = UrlMatcher.parse(u.url), p.scheme == "http" || p.scheme == "https" else { return nil }
            return p.hostname.hasSuffix(".") ? String(p.hostname.dropLast()) : p.hostname
        }
    }

    /// Whether a login is for exactly this RP ID's host (preselected in "Save in").
    public static func isExactSite(_ e: Entry, rpId: String) -> Bool {
        loginHosts(e).contains(rpId.lowercased())
    }

    /// Logins a new passkey can be saved in (the extension's `saveTargets`): ones you can edit
    /// whose website is the RP ID or a subdomain of it (where the passkey also works). Never just
    /// "the same base domain": cloudy.example.com and bazarr.example.com are different sites.
    /// Best first: the RP ID's exact host, then a matching user name, then by name.
    public static func saveTargets(_ vault: VaultData, rpId: String, userName: String) -> [Entry] {
        let rp = rpId.lowercased()
        let name = userName.trimmingCharacters(in: .whitespaces).lowercased()
        func score(_ e: Entry) -> Int {
            let user = (e.item.login?.username ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            let userMatch = !user.isEmpty && !name.isEmpty && (name == user || name == user.split(separator: "@").first.map(String.init))
            return (isExactSite(e, rpId: rp) ? 2 : 0) + (userMatch ? 1 : 0)
        }
        return vault.entries
            .filter { $0.item.login != nil && vault.canWrite($0) }
            .filter { loginHosts($0).contains { $0 == rp || $0.hasSuffix(".\(rp)") } }
            .sorted { a, b in
                let (sa, sb) = (score(a), score(b))
                return sa != sb ? sa > sb : a.item.name.localizedCaseInsensitiveCompare(b.item.name) == .orderedAscending
            }
    }

    /// The preselected save target: the best login for the RP ID's exact host, else a new login.
    public static func defaultTarget(_ targets: [Entry], rpId: String) -> String {
        targets.first { isExactSite($0, rpId: rpId) }?.id ?? newLogin
    }

    /// Where a new passkey goes: the login the user chose (still one they can edit for this
    /// site), else a new login for `https://<rpId>`.
    public static func storePlan(_ vault: VaultData, _ p: Passkey, target: String) -> StorePlan {
        if target != newLogin, let e = saveTargets(vault, rpId: p.rpId, userName: "").first(where: { $0.id == target }), var l = e.item.login {
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
