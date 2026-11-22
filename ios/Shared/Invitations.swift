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
    /// Signed sharing: the vault's key epoch (signed into the share), the share
    /// (`{signature, signer, signer_deleted}` or `null`), and the vault's latest member roster
    /// with its version. nil from older servers.
    public var keyEpoch: Int64?
    public var share: JSON?
    public var memberRoster: String?
    public var memberRosterSeq: Int64?

    public init(vaultId: String, role: String, wrappedKey: String, meta: String, invitedBy: Sharer? = nil, invitedAt: Int64? = nil,
                keyEpoch: Int64? = nil, share: JSON? = nil, memberRoster: String? = nil, memberRosterSeq: Int64? = nil) {
        self.vaultId = vaultId
        self.role = role
        self.wrappedKey = wrappedKey
        self.meta = meta
        self.invitedBy = invitedBy
        self.invitedAt = invitedAt
        self.keyEpoch = keyEpoch
        self.share = share
        self.memberRoster = memberRoster
        self.memberRosterSeq = memberRosterSeq
    }

    enum CodingKeys: String, CodingKey {
        case role, meta, share
        case vaultId = "vault_id", wrappedKey = "wrapped_key", invitedBy = "invited_by", invitedAt = "invited_at"
        case keyEpoch = "key_epoch", memberRoster = "member_roster", memberRosterSeq = "member_roster_seq"
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
            let at = raw["invited_at"]?.number
            seen.insert(vaultId)
            let share: JSON? = if let sh = raw["share"], case .object = sh { sh } else { nil }
            out.append(SyncInvitation(vaultId: vaultId, role: role, wrappedKey: wrapped, meta: meta, invitedBy: sharer, invitedAt: at,
                                      keyEpoch: raw["key_epoch"]?.number, share: share, memberRoster: raw["member_roster"]?.string,
                                      memberRosterSeq: raw["member_roster_seq"]?.number))
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
    /// Signed sharing (servers with it): what the checks found; nil on servers without it (the
    /// fingerprint the server lists is shown, as before).
    public var trust: InvitationTrust?
    /// Signed sharing: what accepting writes (the vault's key epoch pin, the signer's pin, the
    /// verified roster to remember); nil when it can't be accepted.
    var acceptance: Acceptance?
    /// Not an invitation but a vault the server lists as a membership that this account never
    /// accepted (signed sharing's consent): accepting writes only this device's checks, declining
    /// leaves the vault.
    public var consent: Consent?
    /// The key id an unsigned vault the server added would be accepted by (shown with it).
    public var shownKeyId: String? { acceptance?.shownKeyId }
    /// A vault waiting for consent that isn't signed, or that waits while the account's trust
    /// memory is missing (or this device had no earlier copy of it): Decline isn't offered, only
    /// Accept or later (a server can't push the user into leaving vaults they really are in).
    public var declineHidden = false
    /// Signed sharing's consent: the account held this vault with its own key wrap before (a
    /// personal vault must never silently turn into one whose key someone else sealed).
    public var own = false

    public enum Consent: Equatable, Sendable {
        /// Added without an invitation this account accepted.
        case added
        /// Left before, shared again with a newer member list.
        case rejoin
        /// Accepted before and never seen signed; its key was replaced by an app that doesn't
        /// sign. Declining keeps it locked (it can be accepted later).
        case replaced
    }

    public init(vaultId: String, role: String, name: String?, invitedBy: SyncInvitation.Sharer? = nil, invitedAt: Int64? = nil,
                trust: InvitationTrust? = nil) {
        self.vaultId = vaultId
        self.role = role
        self.name = name
        self.invitedBy = invitedBy
        self.invitedAt = invitedAt
        self.trust = trust
    }

    /// Accept is offered: the vault's name could be read and, with signed sharing, the invitation verified.
    public var canAccept: Bool {
        // A vault the server added: whatever the checks allow accepting (an unsigned one only
        // after an unsigned key replacement, or while the account's trust memory is missing).
        if consent != nil { return name != nil && acceptance != nil }
        guard name != nil, trust?.canAccept ?? true else { return false }
        return trust == nil || acceptance != nil
    }

    /// Decline is offered only where the verdict says `declinable` (round 5 M2: never for a
    /// re-join, a replaced key, the account's own vault, a first signature or a vault it holds —
    /// "Not now" keeps those locked): an invitation whose verdict says so, or that can only be
    /// declined (not signed, didn't verify); a vault the server added only when it is signed (a
    /// signer is named), declinable, and not waiting while trust memory is missing (cross-client
    /// rule 1).
    public var canDecline: Bool {
        if let flags = acceptance?.flags, !flags.declinable { return false }
        guard let consent else { return true }
        guard consent != .replaced, !declineHidden, case .signed? = trust, acceptance?.flags.declinable == true else { return false }
        return true
    }

    /// The verdict's consent flags (nil: none known, e.g. an invitation that isn't signed).
    public var flags: ConsentFlags? { acceptance?.flags }

    /// Whether `current` (the entry as it is now) is still the decision `shown` showed: the same
    /// vault, kind (invitation or consent), role and listed sharer key, and with signed sharing
    /// the same key epoch pin, signer identity (hash) and the email it was shown and is pinned
    /// with, and trusted roster (hash). Accepting needs it.
    public static func sameDecision(_ shown: Invitation, _ current: Invitation) -> Bool {
        guard shown.vaultId == current.vaultId, shown.consent == current.consent, shown.own == current.own, shown.role == current.role,
              shown.invitedBy?.publicKey == current.invitedBy?.publicKey, (shown.trust == nil) == (current.trust == nil) else { return false }
        guard shown.acceptance?.epochPin == current.acceptance?.epochPin, shown.acceptance?.rosterHash == current.acceptance?.rosterHash,
              shown.acceptance?.rosterVersion == current.acceptance?.rosterVersion,
              // The verdict's flags (re-join, held, first signature, …) and kind (round 5, Android M).
              shown.acceptance?.flags == current.acceptance?.flags, shown.acceptance?.invitation == current.acceptance?.invitation,
              shown.acceptance?.kind == current.acceptance?.kind,
              shown.acceptance?.signer?.identityHash == current.acceptance?.signer?.identityHash,
              shown.acceptance?.signer?.pinEmailToWrite == current.acceptance?.signer?.pinEmailToWrite,
              shown.acceptance?.signer?.pinVerifiedToWrite == current.acceptance?.signer?.pinVerifiedToWrite else { return false }
        return signerHash(shown.trust) == signerHash(current.trust) && signerEmails(shown.trust) == signerEmails(current.trust)
    }

    /// The identity hash of whoever signed it (nil: not signed).
    static func signerHash(_ t: InvitationTrust?) -> String? {
        switch t {
        case .signed(let s)?, .keyChanged(let s)?: s.identityHash
        default: nil
        }
    }

    /// The emails shown for whoever signed it (pinned, listed), in the form pins keep.
    static func signerEmails(_ t: InvitationTrust?) -> [String] {
        switch t {
        case .signed(let s)?, .keyChanged(let s)?: [s.pinnedEmail ?? "", s.listedEmail]
        default: []
        }
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
    public static let cantAcceptUnverified = "PassAuth couldn't verify this invitation, so it can't be accepted."
    /// The entry changed after it was shown (another signer, key, member list…): nothing accepted.
    public static let changed = "This invitation changed. Check it again."

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

    /// Who shared it, as headings say it. Signed sharing: the signer's pinned email (the one this
    /// account knows them by), "you"; someone not pinned yet (or an invitation that isn't signed or
    /// didn't verify) only as "someone listed by your server as …". Without signed sharing, as the
    /// server lists them.
    public static func sharerHeading(_ inv: Invitation) -> String {
        if inv.consent != nil {
            // A vault the server lists for the account: its signer, else only the server.
            if case .signed(let s)? = inv.trust { return s.heading }
            return "your server"
        }
        switch inv.trust {
        case nil:
            return sharer(inv)
        case .signed(let s)? where s.pin == .me:
            return "you"
        case .signed(let s)? where s.isPinned && !s.email.isEmpty:
            return s.email
        default:
            return inv.invitedBy == nil ? sharer(inv) : "someone listed by your server as \(sharer(inv))"
        }
    }

    /// "From alex@example.com, 12 Nov 2026" (`sharerHeading`).
    public static func from(_ inv: Invitation) -> String {
        if inv.consent != nil, inv.trust.map({ if case .signed = $0 { return false } else { return true } }) ?? true {
            return "Listed by your server"
        }
        var t = "From \(sharerHeading(inv))"
        if let at = inv.invitedAt { t += ", " + Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .omitted) }
        return t
    }

    /// One quiet line for the vault list while invitations wait; nil when there are none.
    public static func notice(_ list: [Invitation]) -> String? {
        guard let first = list.first else { return nil }
        let head: String
        if list.count > 1 {
            head = "You have \(list.count) invitations to shared vaults."
        } else if first.consent != nil {
            head = "Your server lists " + (first.name.map { "the shared vault \"\($0)\"" } ?? "a shared vault") + " for your account. It waits for your OK."
        } else {
            let lead = sharerHeading(first)
            let who = first.trust == nil ? (first.invitedBy == nil ? "Someone" : sharerShort(first))
                : (lead.prefix(1).uppercased() + lead.dropFirst())
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
    ///
    /// Signed sharing: only an invitation the checks verified is accepted (one that isn't signed
    /// or didn't verify can only be declined); accepting pins its signer and the vault's key
    /// epoch (clearing a tombstone) and remembers its verified member roster, all in the
    /// account's key pins and this device's memory, so the vault's first sync continues from
    /// there. A vault the server added without an invitation (`consent`) is accepted on this
    /// device only (the server already lists it). Runs under the repository's lock.
    public func acceptInvitation(_ shown: Invitation) async throws {
        try await lock.run {
            let account = activeId
            let vaultId = shown.vaultId
            // Bound to what the user saw (review M-A): the entry as it is now must still be the
            // shown one (same key epoch pin, signer, roster), else nothing is accepted.
            guard let inv = vault?.invitations.first(where: { $0.vaultId == vaultId }) else {
                try? await syncLocked()
                throw UserError(InvitationText.noLongerOpen)
            }
            guard Invitation.sameDecision(shown, inv) else { throw UserError(InvitationText.changed) }
            if !inv.canAccept {
                throw UserError(inv.consent != nil && inv.trust == .unsigned ? SharingText.consentUnsigned : InvitationText.cantAcceptUnverified)
            }
            if inv.trust != nil, let session = sessions[account], !(sharingMemory.load(account).proven || session.sharingProven) {
                // Nothing is accepted before the server has shown it signs (cross-client rule 2).
                throw UserError(SharingText.checking)
            }
            if inv.consent == nil {
                do {
                    _ = try await api.call(account, "/vaults/\(Self.pathSegment(vaultId))/invitation/accept", method: "POST")
                } catch let e as ApiError where e.status == 404 {
                    try? await syncLocked()
                    throw UserError(InvitationText.noLongerOpen)
                }
            } else if inv.acceptance == nil {
                throw UserError(InvitationText.cantAcceptUnverified)
            }
            if let acceptance = inv.acceptance, let session = sessions[account] {
                try await accept(account, session, vaultId: vaultId, acceptance)
            }
            await syncAfterWrite()
        }
    }

    /// Decline a vault shared with the account. The server then asks the vault's owners and
    /// admins to replace its key (the invitation already gave this account the key). Already gone
    /// (404) is fine: the list is refreshed. A vault the server added without an invitation is
    /// left (`DELETE /vaults/{id}/members/{me}`).
    ///
    /// Offered only where the verdict says `declinable` (`Invitation.canDecline`; round 5 M2):
    /// never for a re-join, a replaced key, the account's own vault, a first signature, a vault it
    /// holds, an unsigned vault the server added or one waiting while trust memory is missing
    /// (they stay locked; throws). With signed sharing the key pins are written first with
    /// `pins_decline` (a tombstone at roster version 0, only for a vault the account doesn't hold
    /// and that isn't one of this sync's vault rows, whatever its verdict: a vault the server
    /// added never is; a server-chosen roster version never goes into it); one not written now
    /// is written at the next sync. The server's decline follows either way (cross-client rules
    /// 1–3: nothing written before the server has shown it signs).
    public func declineInvitation(_ vaultId: String) async throws {
        try await lock.run {
            let account = activeId
            let inv = vault?.invitations.first { $0.vaultId == vaultId }
            let session = sessions[account]
            if let inv, !inv.canDecline { throw UserError(SharingText.cantDecline) }
            // Unknown copy: counted as a current row (nothing tombstoned).
            let currentRow = inv?.consent != nil || (copySnapshot?.vaults.contains { $0.id == vaultId } ?? true)
            let proven = session.map { sharingMemory.load(account).proven || $0.sharingProven } ?? false
            if let session, signedSharingOn(account, copySnapshot), proven, !currentRow {
                do {
                    try await decline(account, session, vaultId: vaultId, currentRow: currentRow)
                } catch {
                    // Written at the next sync (kept in this process, and in the device memory as
                    // soon as it can be written, so a restart doesn't lose it).
                    pendingTombstones[account, default: [:]][vaultId] = 0
                    let stored = loadMemory(account, session)
                    var update = SharingMemoryRecord().owned(by: session.meId, server: store.get().file.accounts[account]?.server ?? "")
                    update.tombstones = (stored.unreadable ? [:] : stored.tombstones ?? [:])
                        .merging(pendingTombstones[account] ?? [:]) { max($0, $1) }
                    saveMemory(account, session, update)
                }
            }
            if inv?.consent != nil, let session {
                do {
                    _ = try await api.call(account, "/vaults/\(Self.pathSegment(vaultId))/members/\(Self.pathSegment(session.meId))", method: "DELETE")
                } catch let e as ApiError where e.status == 404 {
                    // Gone already (the server answers non-members 404). A 403 is a refusal
                    // (policy, two-step login, reauth) and is shown, never taken as done.
                }
            } else {
                do {
                    _ = try await api.call(account, "/vaults/\(Self.pathSegment(vaultId))/invitation", method: "DELETE")
                } catch let e as ApiError where e.status == 404 {}
            }
            await syncAfterWrite()
        }
    }

    /// One path segment (ids from the server are UUIDs; anything else is escaped).
    nonisolated static func pathSegment(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/"))) ?? s
    }
}
