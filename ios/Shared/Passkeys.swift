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

    /// A login a new passkey can be saved in, and whether it is preselected.
    public struct SaveChoice: Identifiable, Sendable {
        public let entry: Entry
        /// The core's `preferred`: the user's own login for this exact host (never one in a
        /// shared vault).
        public let preferred: Bool
        public var id: String { entry.id }
    }

    /// Logins a new passkey can be saved in (the core's `passkeySaveTargets`, as in every client):
    /// ones you can edit whose website is this exact host, the RP ID or a subdomain of it (where
    /// the passkey also works). Never just "the same base domain": cloudy.example.com and
    /// bazarr.example.com are different sites; an `androidapp://` address is no website. Logins in
    /// your own vault come first, then ones in vaults somebody shared (listed with their vault's
    /// name, never preselected: see `defaultTarget`); within each: this exact host, then a
    /// matching user name (or display name), then by name. `host`: the page's host when known
    /// (nil = the RP ID: iOS and macOS don't say which page asked).
    public static func saveChoices(_ vault: VaultData, rpId: String, userName: String, host: String? = nil, displayName: String = "") -> [SaveChoice] {
        let logins = vault.entries.filter { $0.item.login != nil }
        let byId = Dictionary(logins.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let records = logins.map { e in
            PasskeyLogin(id: e.id, name: e.item.name, username: e.item.login?.username ?? "", urls: e.item.login?.urls.map(\.url) ?? [],
                         writable: vault.canWrite(e), personal: vault.isPersonal(e), vault: vault.sharedVaultName(e))
        }
        let targets = passkeySaveTargets(logins: records, host: host ?? rpId, rpId: rpId, userName: userName, displayName: displayName)
        return targets.compactMap { t in byId[t.id].map { SaveChoice(entry: $0, preferred: t.preferred) } }
    }

    /// `saveChoices` without the preselection: the logins in their order.
    public static func saveTargets(_ vault: VaultData, rpId: String, userName: String, host: String? = nil, displayName: String = "") -> [Entry] {
        saveChoices(vault, rpId: rpId, userName: userName, host: host, displayName: displayName).map(\.entry)
    }

    /// The preselected save target (the core's `passkeyDefaultTarget`): the best login for this
    /// exact host in the user's OWN vault, else a new login. Never a login in a shared vault:
    /// anyone on the server can share a vault with this account and put a login for the site in
    /// it, and the passkey's private key would then go to that vault's members by default. Such a
    /// login can still be chosen.
    public static func defaultTarget(_ choices: [SaveChoice]) -> String {
        passkeyDefaultTarget(targets: choices.map { c in
            PasskeyTarget(id: c.id, name: c.entry.item.name, username: c.entry.item.login?.username ?? "", preferred: c.preferred)
        })
    }

    /// The sheet's warning for a "Save in" choice in a shared vault (nil for the user's own vault
    /// or a new login): the passkey's private key goes to everyone in that vault.
    public static func sharedWarning(_ e: Entry?, in vault: VaultData) -> String? {
        guard let e, let name = vault.sharedVaultName(e) else { return nil }
        return "Saving here shares this passkey with everyone in \(name)."
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
