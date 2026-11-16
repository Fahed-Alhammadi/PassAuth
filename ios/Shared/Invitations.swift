import Foundation

// Vault invitations (servers with the `vault_invitations` feature; server side
// `crates/server/src/vault/sharing.rs`). Sharing a vault with someone who isn't a member yet
// makes an invitation: nothing of the vault reaches their apps until they accept it, so nobody
// can put a vault, or logins planted in it, into someone's apps without consent. Every `/sync`
// answer, full or delta, lists the pending invitations in full, each with the vault key sealed to
// the account (opened only to read the vault's name) and the public key the server lists for the
// sharer. The sealed key is anonymous, so a server could make an invitation up: the app shows that
// key's fingerprint as what the server lists, never as proof, and asks the user to accept only
// invitations they expected (client review F2). The pure parts are
// here (unit-tested in `InvitationTests`), as the web vault's `invitations.ts`; `VaultRepository`
// opens the sealed keys. The AutoFill extensions ignore invitations.

/// The `/api/config` feature of servers with vault invitations.
public let vaultInvitationsFeature = "vault_invitations"

/// An invitation as `/sync` lists it (the vault key sealed to this account, the vault's name
/// encrypted with that key).
public struct SyncInvitation: Codable, Equatable, Sendable {
    /// Who shared the vault, with their public key for the fingerprint.
    public struct Sharer: Codable, Equatable, Sendable {
        public var id: String
        public var email: String
        public var name: String
        public var publicKey: String

        public init(id: String, email: String = "", name: String = "", publicKey: String = "") {
            self.id = id
            self.email = email
            self.name = name
            self.publicKey = publicKey
        }

        enum CodingKeys: String, CodingKey {
            case id, email, name
            case publicKey = "public_key"
        }
    }

    public var vaultId: String
    /// As the server names it: owner, admin, write, read (or a role this app doesn't know yet).
    public var role: String
    public var wrappedKey: String
    public var meta: String
    /// nil once the sharer's account is deleted.
    public var invitedBy: Sharer?
    /// Unix seconds; nil when the server didn't say.
    public var invitedAt: Int64?

    public init(vaultId: String, role: String, wrappedKey: String, meta: String, invitedBy: Sharer? = nil, invitedAt: Int64? = nil) {
        self.vaultId = vaultId
        self.role = role
        self.wrappedKey = wrappedKey
        self.meta = meta
        self.invitedBy = invitedBy
        self.invitedAt = invitedAt
    }

    enum CodingKeys: String, CodingKey {
        case role, meta
        case vaultId = "vault_id", wrappedKey = "wrapped_key", invitedBy = "invited_by", invitedAt = "invited_at"
    }

    /// The `invitations` of a `/sync` answer (or of a stored copy). Servers without the feature
    /// send none (an empty list); an entry without a vault id, sealed key, encrypted name or role
    /// is left out, and a vault listed twice counts once: one malformed entry never makes the
    /// whole answer unreadable. A role this app doesn't know is kept (shown as the server names it).
    public static func read(_ value: JSON?) -> [SyncInvitation] {
        var seen = Set<String>()
        var out: [SyncInvitation] = []
        for raw in value?.array ?? [] {
            guard case .object = raw else { continue }
            let vaultId = raw.str("vault_id")
            let wrapped = raw.str("wrapped_key")
            let meta = raw.str("meta")
            let role = raw.str("role")
            guard !vaultId.isEmpty, !seen.contains(vaultId), !wrapped.isEmpty, !meta.isEmpty, !role.isEmpty else { continue }
            var sharer: Sharer?
            if let by = raw["invited_by"], case .object = by, let id = by["id"]?.string {
                sharer = Sharer(id: id, email: by.str("email"), name: by.str("name"), publicKey: by.str("public_key"))
            }
            var at: Int64?
            switch raw["invited_at"] {
            case .int(let n)?: at = n
            case .double(let d)? where d.isFinite: at = Int64(d)
            default: at = nil
            }
            seen.insert(vaultId)
            out.append(SyncInvitation(vaultId: vaultId, role: role, wrappedKey: wrapped, meta: meta, invitedBy: sharer, invitedAt: at))
        }
        return out
    }

    /// Identifies what the vault's name was read from (a new sealed key or name reads it again).
    var nameKey: String { "\(vaultId)\n\(wrappedKey)\n\(meta)" }
}

/// An invitation as the app shows it.
public struct Invitation: Identifiable, Equatable, Sendable {
    public var id: String { vaultId }
    public let vaultId: String
    public let role: String
    /// The vault's name; nil when this account's keys can't open the invitation (then it can
    /// only be declined).
    public let name: String?
    public let invitedBy: SyncInvitation.Sharer?
    public let invitedAt: Int64?

    public init(vaultId: String, role: String, name: String?, invitedBy: SyncInvitation.Sharer? = nil, invitedAt: Int64? = nil) {
        self.vaultId = vaultId
        self.role = role
        self.name = name
        self.invitedBy = invitedBy
        self.invitedAt = invitedAt
    }

    /// The invitations as the app shows them, in the server's order (oldest first). `open`
    /// reads a vault's name with the sealed key (see `name(fromMeta:)`) and returns nil or throws
    /// when that isn't possible; names already read from the same sealed key and encrypted name
    /// (`previous`) are reused. Returns the names to keep for the next call.
    public static func open(_ list: [SyncInvitation], previous: [String: String?],
                            _ open: (SyncInvitation) throws -> String?) -> (invitations: [Invitation], names: [String: String?]) {
        var names: [String: String?] = [:]
        let shown = list.map { inv -> Invitation in
            let name: String?
            if let known = previous[inv.nameKey] {
                name = known
            } else {
                name = (try? open(inv)) ?? nil
            }
            names[inv.nameKey] = name
            return Invitation(vaultId: inv.vaultId, role: inv.role, name: name, invitedBy: inv.invitedBy, invitedAt: inv.invitedAt)
        }
        return (shown, names)
    }

    /// The vault's name from its decrypted `meta` (JSON text): a name that isn't blank, else
    /// "Shared vault"; nil when the text isn't readable.
    public static func name(fromMeta text: String) -> String? {
        guard let j = try? JSON.parse(text), case .object = j else { return nil }
        let name = j.str("name")
        return name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Shared vault" : name
    }
}

/// Invitation wording, as the web vault's Settings → Vaults & sharing (pure, unit-tested).
public enum InvitationText {
    public static let pageTitle = "Vault invitations"
    public static let intro = "A vault shared with you appears in your apps only after you accept it."
    /// Under the fingerprint, in the list and in the accept sheet.
    public static let expectedOnly = "Accept only invitations you expected."
    public static let cantOpenTitle = "Invitation that can't be opened"
    public static let noLongerOpen = "This invitation is no longer open. The person who shared the vault may have cancelled it."
    public static let declineTitle = "Decline this invitation?"
    public static let declineBody = "The vault won't appear in your apps. The invitation already gave your account the vault's key, so the people who manage the vault will be asked to replace it."
    public static let declined = "Invitation declined."

    /// "Owner", "Admin", "Can edit", "Can view"; a role this app doesn't know as the server names it.
    public static func role(_ role: String) -> String {
        switch role {
        case "owner": "Owner"
        case "admin": "Admin"
        case "write": "Can edit"
        case "read": "Can view"
        default: role
        }
    }

    /// What accepting lets the user do; nil for roles without a sentence.
    public static func roleSentence(_ role: String) -> String? {
        switch role {
        case "read": "You'll be able to view its items."
        case "write": "You'll be able to view and edit its items."
        case "admin": "You'll be able to edit its items and share the vault."
        default: nil
        }
    }

    /// The name and email the server lists for the sharer, as shown (`ShownText`: no control or
    /// format characters such as bidi overrides; a name at most 64 characters).
    static func listedName(_ by: SyncInvitation.Sharer?) -> String { ShownText.clean(by?.name ?? "", limit: 64) }
    static func listedEmail(_ by: SyncInvitation.Sharer?) -> String { ShownText.clean(by?.email ?? "", limit: 254) }

    /// Who shared the vault: "Alex Morgan (alex@example.com)", the email or name alone, or a note
    /// when their account is gone.
    public static func sharer(_ inv: Invitation) -> String {
        guard let by = inv.invitedBy else { return "Someone whose account was deleted" }
        let name = listedName(by)
        let email = listedEmail(by)
        if !name.isEmpty && !email.isEmpty { return "\(name) (\(email))" }
        if !name.isEmpty { return name }
        if !email.isEmpty { return email }
        return "Someone on this server"
    }

    public static let unknownSharer = "the person who shared it"

    /// The sharer's name alone, for running text ("ask Alex Morgan to…").
    public static func sharerShort(_ inv: Invitation) -> String {
        let name = listedName(inv.invitedBy)
        if !name.isEmpty { return name }
        let email = listedEmail(inv.invitedBy)
        return email.isEmpty ? unknownSharer : email
    }

    /// "From Alex Morgan (alex@example.com), 12 Nov 2026".
    public static func from(_ inv: Invitation) -> String {
        var t = "From \(sharer(inv))"
        if let at = inv.invitedAt { t += ", " + Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .omitted) }
        return t
    }

    /// One quiet line for the vault list while invitations wait; nil when there are none.
    public static func notice(_ list: [Invitation]) -> String? {
        guard let first = list.first else { return nil }
        let head: String
        if list.count > 1 {
            head = "You have \(list.count) invitations to shared vaults."
        } else {
            let who = first.invitedBy == nil ? "Someone" : sharerShort(first)
            head = "\(who) invited you to " + (first.name.map { "the shared vault \"\($0)\"." } ?? "a shared vault.")
        }
        return head + " Nothing from \(list.count == 1 ? "it" : "them") reaches your apps until you accept."
    }

    public static func noticeAction(_ count: Int) -> String {
        count == 1 ? "See the invitation" : "See the invitations"
    }

    /// Identifies a set of invitations, so a dismissed notice comes back when a new one arrives.
    public static func key(_ list: [Invitation]) -> String {
        list.map(\.vaultId).sorted().joined(separator: ",")
    }

    /// Whom the server says sent it, for the fingerprint's label: their email, else their name.
    public static func listedFor(_ inv: Invitation) -> String {
        let email = listedEmail(inv.invitedBy)
        return email.isEmpty ? sharerShort(inv) : email
    }

    /// "Fingerprint your server lists for alex@example.com": the key the server gives for the
    /// sharer, which can't prove the invitation is genuine (the server made the listing).
    public static func fingerprintLabel(_ inv: Invitation) -> String {
        "Fingerprint your server lists for \(listedFor(inv))"
    }

    /// Under the fingerprint.
    public static func checkHint(_ inv: Invitation) -> String { expectedOnly }

    /// The account's keys can't open the sealed key: only Decline is offered.
    public static func cantOpen(_ inv: Invitation) -> String {
        "Your account's keys can't open this invitation, so PassAuth can't show the vault's name. Decline it, then ask \(sharerShort(inv)) to share the vault again."
    }

    /// No fingerprint to show: the sharer's account is gone, or the key listed for it can't be read.
    public static func noFingerprint(_ inv: Invitation) -> String {
        inv.invitedBy == nil
            ? "The account that shared this vault no longer exists. \(expectedOnly)"
            : "PassAuth can't show the fingerprint your server lists for \(listedFor(inv)). \(expectedOnly)"
    }

    public static func acceptTitle(_ name: String) -> String { "Accept \"\(name)\"?" }

    public static func acceptBody(_ inv: Invitation) -> String {
        var t = "The vault and its items appear in all your apps."
        if let s = roleSentence(inv.role) { t += " " + s }
        return t + " The people who manage it can add and change items in it."
    }

    public static func acceptCheck(_ inv: Invitation) -> String { expectedOnly }

    public static func joined(_ name: String) -> String { "You joined \"\(name)\"." }
}

extension VaultRepository {
    /// Accept a vault shared with the account: it becomes a membership and the vault arrives
    /// whole with the sync that follows. Gone (404: cancelled by the sharer, or the vault was
    /// deleted) → the list is refreshed and the user told.
    public func acceptInvitation(_ vaultId: String) async throws {
        do {
            _ = try await api.call(activeId, "/vaults/\(Self.pathSegment(vaultId))/invitation/accept", method: "POST")
        } catch let e as ApiError where e.status == 404 {
            try? await sync()
            throw UserError(InvitationText.noLongerOpen)
        }
        await syncAfterAnswer()
    }

    /// Decline a vault shared with the account. The server then asks the vault's owners and
    /// admins to replace its key (the invitation already gave this account the key). Already gone
    /// (404) is fine: the list is refreshed.
    public func declineInvitation(_ vaultId: String) async throws {
        do {
            _ = try await api.call(activeId, "/vaults/\(Self.pathSegment(vaultId))/invitation", method: "DELETE")
        } catch let e as ApiError where e.status == 404 {}
        await syncAfterAnswer()
    }

    /// The sync after an answer the server took: failing doesn't make the answer fail (the copy
    /// shows as offline until the next sync brings the change).
    private func syncAfterAnswer() async {
        await lock.run { await syncAfterWrite() }
    }

    /// One path segment (ids from the server are UUIDs; anything else is escaped).
    nonisolated static func pathSegment(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? s
    }
}
