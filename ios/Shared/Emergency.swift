import CryptoKit
import Foundation

/// Emergency access (servers with the `emergency_access` feature): someone (the grantor) names a
/// trusted contact with an account on the same server and a waiting period of 1–90 days.
/// invited → (the contact accepts) accepted → (the grantor checks the contact's fingerprint with
/// them and confirms) confirmed → (the contact asks) requested → (the grantor approves, or the
/// waiting period ends) approved. The grantor may reject a request or end an approved access
/// (rejected; the contact may ask again); either side may remove it.
///
/// Keys (servers with `emergency_vault_keys`): confirming makes an emergency key for the access,
/// seals it to the contact's public key, keeps it wrapped by the grantor's account key
/// (`grantor_key`) and wraps each personal vault's key with it. The roster (sealed with the account
/// key, versioned inside) lists the accesses the grantor's apps may add wraps for.
///
/// The rules are the web vault's `web/src/lib/emergency.ts`, ported one to one (pure,
/// `EmergencyTests` with the web's test cases); the requests are `EmergencyClient`.
public let emergencyAccessFeature = "emergency_access"
public let emergencyVaultKeysFeature = "emergency_vault_keys"

public enum GrantStatus: String, CaseIterable, Sendable {
    case invited, accepted, confirmed, requested, approved, rejected
}

public struct GrantPerson: Equatable, Sendable {
    public var id: String
    public var email: String
    public var name: String
    /// For the fingerprint shown before confirming.
    public var publicKey: String

    public init(id: String, email: String, name: String, publicKey: String) {
        self.id = id
        self.email = email
        self.name = name
        self.publicKey = publicKey
    }
}

public struct Grant: Identifiable, Equatable, Sendable {
    public var id: String
    public var status: GrantStatus
    public var waitDays: Int
    public var createdAt: Int64
    public var updatedAt: Int64
    public var requestedAt: Int64?
    public var approvedAt: Int64?
    /// While a request waits: when the server approves it unless the grantor answers.
    public var autoApproveAt: Int64?
    public var grantor: GrantPerson
    public var grantee: GrantPerson
    /// The key scheme (2: an emergency key over the personal vaults); nil when not given.
    public var keyVersion: Int?
    /// The access's emergency key wrapped by this account's key, once confirmed.
    public var grantorKey: String?
    /// Confirmed before emergency keys: the grantor confirms the contact again.
    public var reconfirm: Bool
    /// Personal vaults without a wrap for this access (when accepted: the vaults to wrap).
    public var missingVaults: [String]
    /// Confirmed before emergency keys, when the contact got the account key itself.
    public var v1Exposed: Bool
}

/// `GET /emergency-access`: the accesses both ways, and the account's sealed roster.
public struct GrantLists: Equatable, Sendable {
    public var asGrantor: [Grant]
    public var asGrantee: [Grant]
    /// The roster as the server keeps it (sealed); nil until one is stored.
    public var roster: String?
    /// The roster's sequence number; nil from servers without it.
    public var rosterSeq: Int64?

    public init(asGrantor: [Grant], asGrantee: [Grant], roster: String?, rosterSeq: Int64?) {
        self.asGrantor = asGrantor
        self.asGrantee = asGrantee
        self.roster = roster
        self.rosterSeq = rosterSeq
    }
}

public enum Tone: Sendable { case ok, warn, info }

public enum GrantorAction: String, Sendable { case confirm, approve, reject, end, wait, remove }
public enum GranteeAction: String, Sendable { case accept, decline, request, view, remove }

public enum Emergency {
    /// The key scheme this app makes and opens.
    public static let keyVersion = 2
    public static let minWaitDays = 1
    public static let maxWaitDays = 90
    public static let defaultWaitDays = 7

    static func str(_ v: JSON?) -> String { v?.string ?? "" }

    static func num(_ v: JSON?) -> Int64? { v?.number }

    /// A JSON number that is whole (as JavaScript's `Number.isInteger` would see it).
    static func wholeNum(_ v: JSON?) -> Int64? {
        switch v {
        case .int(let n)?: n
        case .double(let d)? where d == d.rounded(): JSON.wholeInt64(d)
        default: nil
        }
    }

    /// Strings of a list, non-empty, each once (first seen first).
    static func strings(_ v: JSON?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        var seen = Set<String>()
        var out: [String] = []
        for x in a {
            if case .string(let s) = x, !s.isEmpty, !seen.contains(s) {
                seen.insert(s)
                out.append(s)
            }
        }
        return out
    }

    static func readPerson(_ v: JSON?) -> GrantPerson? {
        guard let v, case .object = v, !str(v["id"]).isEmpty else { return nil }
        return GrantPerson(id: str(v["id"]), email: str(v["email"]), name: str(v["name"]), publicKey: str(v["public_key"]))
    }

    /// One emergency access from the API, or nil when malformed (an unknown status included).
    public static func readGrant(_ g: JSON?) -> Grant? {
        guard let g, case .object = g, let grantor = readPerson(g["grantor"]), let grantee = readPerson(g["grantee"]),
              let status = g["status"]?.string.flatMap(GrantStatus.init(rawValue:)), let wait = num(g["wait_days"]), !str(g["id"]).isEmpty else { return nil }
        return Grant(
            id: str(g["id"]), status: status, waitDays: Int(min(max(wait, 0), 36_500)),
            createdAt: num(g["created_at"]) ?? 0, updatedAt: num(g["updated_at"]) ?? 0,
            requestedAt: num(g["requested_at"]), approvedAt: num(g["approved_at"]), autoApproveAt: num(g["auto_approve_at"]),
            grantor: grantor, grantee: grantee,
            keyVersion: num(g["key_version"]).map { Int(clamping: $0) },
            grantorKey: str(g["grantor_key"]).isEmpty ? nil : str(g["grantor_key"]),
            reconfirm: g["reconfirm"] == .bool(true),
            missingVaults: strings(g["missing_vaults"]),
            v1Exposed: g["v1_exposed"] == .bool(true)
        )
    }

    /// `GET /emergency-access`: the contacts the account named, the people who named it, the roster.
    public static func readGrants(_ v: JSON?) -> GrantLists {
        func list(_ x: JSON?) -> [Grant] { (x?.array ?? []).compactMap(readGrant) }
        let seq = wholeNum(v?["roster_seq"])
        let roster = str(v?["roster"])
        return GrantLists(asGrantor: list(v?["as_grantor"]), asGrantee: list(v?["as_grantee"]),
                          roster: roster.isEmpty ? nil : roster, rosterSeq: seq.flatMap { $0 >= 0 && $0 < 1 << 53 ? $0 : nil })
    }

    /// A person's name, else their email address.
    public static func personName(_ p: GrantPerson) -> String {
        let n = p.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !n.isEmpty { return n }
        return p.email.isEmpty ? "Someone" : p.email
    }

    /// "1 day", "7 days".
    public static func daysText(_ days: Int) -> String { "\(days) \(days == 1 ? "day" : "days")" }

    /// A waiting period the server accepts: a whole number of days from 1 to 90.
    public static func validWait(_ days: Double) -> Bool { days == days.rounded() && days >= Double(minWaitDays) && days <= Double(maxWaitDays) }

    /// What a contact confirmed before emergency keys may still hold.
    public static func v1Warning(_ who: String) -> String {
        "\(who) was confirmed with an earlier version of PassAuth, which gave them your account key. Removing them can't take that back. If you no longer trust them, change the passwords that matter or move to a new account."
    }

    /// What confirming a contact means, said before it is done.
    public static func confirmMeaning(_ who: String, v1Exposed: Bool = false) -> String {
        let gives = "Confirming gives \(who) a key to your personal vaults. Once they get access (or at once, if your server is ever compromised), they can read everything in those vaults. Shared vaults and Sends stay out of reach."
        return v1Exposed
            ? "\(gives) \(v1Warning(who))"
            : "\(gives) If you remove them, PassAuth changes the keys of those vaults, so they can't read anything you add afterwards, unless your server is later compromised."
    }

    /// Why a contact confirmed before emergency keys has to be confirmed again.
    public static func reconfirmText(_ who: String) -> String {
        "PassAuth now gives emergency contacts a key to your personal vaults only. Confirm \(who) again to give them access."
    }

    /// Statuses in which an access holds its keys.
    public static func hasKeys(_ g: Grant) -> Bool { [.confirmed, .requested, .approved, .rejected].contains(g.status) }

    /// What removing the contact of `g` does, for the grantor's confirmation.
    public static func removalText(_ g: Grant) -> String {
        let who = personName(g.grantee)
        let v1 = g.v1Exposed ? " \(v1Warning(who))" : ""
        if !hasKeys(g) { return "\(who) can't ask for access any more.\(v1)" }
        let changes = "Changing a vault's key also deletes the earlier versions kept of its items."
        if g.v1Exposed { return "\(who) can't ask for access any more, and PassAuth changes the keys of your personal vaults. \(changes)\(v1)" }
        let kept = g.status == .confirmed ? "" : " If they had access, they keep what they saw: change the passwords that matter if you no longer trust them."
        return "\(who) can't ask for access any more, and PassAuth changes the keys of your personal vaults, so they can't read anything you add afterwards, unless your server is later compromised. \(changes)\(kept)"
    }

    /// What a status means to the grantor. `when` formats Unix seconds.
    public static func grantorStatus(_ g: Grant, when: (Int64) -> String) -> (label: String, text: String, tone: Tone) {
        let who = personName(g.grantee)
        switch g.status {
        case .invited:
            return ("Invited", "Waiting for \(who) to accept.", .info)
        case .accepted:
            return g.reconfirm
                ? ("Confirm again", reconfirmText(who), .warn)
                : ("Confirm", "\(who) accepted. Check their fingerprint with them, then confirm them.", .warn)
        case .confirmed:
            return ("Ready", "\(who) can ask for access. You'd have \(daysText(g.waitDays)) to say no.", .ok)
        case .requested:
            let text = g.autoApproveAt.map { at in
                "\(who) asked for access\(g.requestedAt.map { " on \(when($0))" } ?? ""). Unless you reject it, they can view your personal vaults from \(when(at))."
            } ?? "\(who) asked for access. Unless you reject it, they can view your personal vaults after \(daysText(g.waitDays))."
            return ("Access requested", text, .warn)
        case .approved:
            return ("Has access", "\(who) can view your personal vaults\(g.approvedAt.map { " since \(when($0))" } ?? "").", .warn)
        case .rejected:
            return ("Rejected", "You rejected \(who)'s last request. They can ask again.", .info)
        }
    }

    /// What a status means to the contact.
    public static func granteeStatus(_ g: Grant, when: (Int64) -> String) -> (label: String, text: String, tone: Tone) {
        let who = personName(g.grantor)
        switch g.status {
        case .invited:
            return ("Invitation", "\(who) named you as their emergency contact. Accept to be able to ask for access to their vaults if you ever need to.", .info)
        case .accepted:
            return ("Waiting", "Waiting for \(who) to confirm you.", .info)
        case .confirmed:
            return ("Ready", "You can ask for access. \(who) is told at once and has \(daysText(g.waitDays)) to say no.", .ok)
        case .requested:
            let text = g.autoApproveAt.map { "You asked for access. Unless \(who) rejects it, you can view their vaults from \(when($0))." }
                ?? "You asked for access. Unless \(who) rejects it, you can view their vaults after \(daysText(g.waitDays))."
            return ("Requested", text, .warn)
        case .approved:
            return ("Access granted", "You can view \(who)'s vaults.", .ok)
        case .rejected:
            return ("Rejected", "\(who) rejected your request. You can ask again.", .info)
        }
    }

    /// What the grantor can do now, most important first.
    public static func grantorActions(_ g: Grant) -> [GrantorAction] {
        switch g.status {
        case .accepted: [.confirm, .wait, .remove]
        case .requested: [.approve, .reject, .wait, .remove]
        case .approved: [.end, .wait, .remove]
        default: [.wait, .remove]
        }
    }

    /// What the contact can do now, most important first.
    public static func granteeActions(_ g: Grant) -> [GranteeAction] {
        switch g.status {
        case .invited: [.accept, .decline]
        case .confirmed, .rejected: [.request, .remove]
        case .approved: [.view, .remove]
        default: [.remove]
        }
    }

    /// Grants that want the account's answer.
    public static func needsAnswer(asGrantor: [Grant], asGrantee: [Grant]) -> Int {
        asGrantor.filter { $0.status == .accepted || $0.status == .requested }.count + asGrantee.filter { $0.status == .invited }.count
    }

    // MARK: The keys

    /// A vault as this app's own sync shows it.
    public struct OwnVault: Equatable, Sendable {
        public var id: String
        public var role: Role
        public var keyKind: String

        public init(id: String, role: Role, keyKind: String) {
            self.id = id
            self.role = role
            self.keyKind = keyKind
        }
    }

    /// Whether this app's own data says a vault is personal: owned with the account's own key, its
    /// members (invitees included) are this account alone, and (signed sharing) it has no signed
    /// history on this device or account (`signedHistory`: a trusted roster listing anyone else,
    /// a share seen signed, an epoch pin with `signed_since`). Unknown vaults and lists aren't.
    public static func isPersonal(_ vault: OwnVault?, members: [String]?, me: String, signedHistory: Bool = false) -> Bool {
        guard let vault, vault.role == .owner, vault.keyKind == VaultInfo.accountKeyKind, !me.isEmpty, let members, !signedHistory else { return false }
        return members == [me]
    }

    /// Which of the vaults the server asks to wrap this app wraps (`wrap`), and the others.
    public static func vaultsToWrap(_ wanted: [String], personal: (String) -> Bool) -> (wrap: [String], refused: [String]) {
        var wrap: [String] = []
        var refused: [String] = []
        var seen = Set<String>()
        for id in wanted where !seen.contains(id) {
            seen.insert(id)
            if personal(id) { wrap.append(id) } else { refused.append(id) }
        }
        return (wrap, refused)
    }

    /// The accesses whose wraps this account should add now.
    public static func accessesToFill(_ grants: [Grant]) -> [Grant] {
        grants.filter { hasKeys($0) && $0.grantorKey != nil && !$0.missingVaults.isEmpty && ($0.keyVersion ?? keyVersion) == keyVersion }
    }

    /// The vault ids of an answer that asks for new keys (`rotation_pending`).
    public static func vaultsToRotate(_ answer: JSON?) -> [String] { strings(answer?["rotation_pending"]) }

    /// The vaults whose keys the grantor's app replaces after removing a contact.
    public static func vaultsToReKey(_ answer: JSON?, personal: (String) -> Bool) -> [String] {
        vaultsToWrap(vaultsToRotate(answer), personal: personal).wrap
    }

    // MARK: The roster

    /// SHA-256 of `text` (UTF-8), base64url without padding: how the roster names a `grantor_key`.
    public static func sha256b64(_ text: String) -> String {
        Data(SHA256.hash(data: Data(text.utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    public static let emptyRoster = Roster(version: 0, accesses: [], removed: [])
    /// Most removed accesses a roster keeps; the oldest go first.
    public static let maxRemoved = 300
    /// The largest sealed roster the server takes (base64url characters).
    public static let maxSealedRoster = 48 * 1024
    public static let maxEmail = 254
    public static let maxName = 100

    /// A roster from its JSON (as the core opened it); nil when malformed.
    public static func readRoster(_ json: String) -> Roster? {
        guard let v = try? JSON.parse(json), case .object = v, let version = wholeNum(v["version"]), version >= 0,
              case .array(let accessList)? = v["accesses"] else { return nil }
        var removedList: [JSON] = []
        switch v["removed"] {
        case nil: break
        case .array(let a)?: removedList = a
        default: return nil
        }
        var accesses: [RosterEntry] = []
        for e in accessList {
            guard case .object = e, !str(e["id"]).isEmpty, !str(e["contact_key"]).isEmpty, !str(e["grantor_key_hash"]).isEmpty else { return nil }
            var email: String?
            var name: String?
            switch e["email"] {
            case nil: break
            case .string(let s)?: email = s
            default: return nil
            }
            switch e["name"] {
            case nil: break
            case .string(let s)?: name = s
            default: return nil
            }
            accesses.append(RosterEntry(id: str(e["id"]), contactKey: str(e["contact_key"]), grantorKeyHash: str(e["grantor_key_hash"]), email: email, name: name))
        }
        var removed: [RemovedEntry] = []
        for e in removedList {
            guard case .object = e, !str(e["id"]).isEmpty, case .string(let h)? = e["grantor_key_hash"] else { return nil }
            removed.append(RemovedEntry(id: str(e["id"]), grantorKeyHash: h))
        }
        return Roster(version: version, accesses: accesses, removed: removed)
    }

    /// The roster's JSON, for `Account.sealEmergencyRoster` (keys in the web vault's order).
    public static func rosterJson(_ r: Roster) -> String {
        func q(_ s: String) -> String { JSON.string(s).text }
        let accesses = r.accesses.map { e in
            var parts = ["\"id\":\(q(e.id))", "\"contact_key\":\(q(e.contactKey))", "\"grantor_key_hash\":\(q(e.grantorKeyHash))"]
            if let m = e.email { parts.append("\"email\":\(q(m))") }
            if let n = e.name { parts.append("\"name\":\(q(n))") }
            return "{" + parts.joined(separator: ",") + "}"
        }
        let removed = r.removed.map { "{\"id\":\(q($0.id)),\"grantor_key_hash\":\(q($0.grantorKeyHash))}" }
        return "{\"version\":\(r.version),\"accesses\":[\(accesses.joined(separator: ","))],\"removed\":[\(removed.joined(separator: ","))]}"
    }

    /// How long `r` is once sealed (base64url of version, nonce, the JSON and the tag).
    public static func sealedLength(_ r: Roster) -> Int {
        let n = 1 + 24 + rosterJson(r).utf8.count + 16
        return (n / 3) * 4 + [0, 2, 3][n % 3]
    }

    /// `removed` and then `add`, each access once (a later copy counts as newer), the oldest trimmed
    /// beyond `maxRemoved`. Throws `RosterFullError` when it would pass the server's size limit.
    static func withRemoved(version: Int64, accesses: [RosterEntry], _ removed: [RemovedEntry], add: [RemovedEntry] = []) throws -> Roster {
        var all: [RemovedEntry] = []
        for x in removed + add {
            all.removeAll { $0.id == x.id }
            all.append(x)
        }
        let out = Roster(version: version, accesses: accesses, removed: Array(all.suffix(maxRemoved)))
        if sealedLength(out) > maxSealedRoster { throw RosterFullError() }
        return out
    }

    /// Whether `r` took access `id` (or its key, by hash) off for good.
    public static func isRemoved(_ r: Roster?, _ id: String, grantorKeyHash: String? = nil) -> Bool {
        guard let r else { return false }
        let hash = grantorKeyHash ?? ""
        return r.removed.contains { x in x.id == id || (!hash.isEmpty && x.grantorKeyHash == hash) }
    }

    /// A roster entry for access `g` as the grantor confirms it.
    public static func rosterEntry(_ g: Grant, checkedContactKey: String, grantorKeyHash: String) -> RosterEntry {
        RosterEntry(id: g.id, contactKey: checkedContactKey, grantorKeyHash: grantorKeyHash,
                    email: PlainText.oneLine(g.grantee.email, max: maxEmail), name: PlainText.oneLine(g.grantee.name, max: maxName))
    }

    /// The entries whose access the server still lists.
    public static func pruneRoster(_ r: Roster, listed: Set<String>) -> [RosterEntry] { r.accesses.filter { listed.contains($0.id) } }

    /// A change of the roster: one access added (replacing one of the same id), or one taken out.
    public enum RosterChange: Equatable, Sendable {
        case add(RosterEntry)
        case remove(String, hash: String? = nil)
    }

    /// The next roster after `r` (see the web vault's `nextRoster`); nil when nothing changes.
    public static func nextRoster(_ r: Roster, seen: Int64, _ change: RosterChange?, listed: Set<String>? = nil) throws -> Roster? {
        var accesses = listed.map { pruneRoster(r, listed: $0) } ?? r.accesses
        var gone = r.accesses.filter { e in !accesses.contains(e) }.map { RemovedEntry(id: $0.id, grantorKeyHash: $0.grantorKeyHash) }
        switch change {
        case .add(let e)?:
            accesses.removeAll { $0.id == e.id }
            accesses.append(e)
        case .remove(let id, let hash)?:
            let entry = accesses.first { $0.id == id } ?? r.accesses.first { $0.id == id }
            accesses.removeAll { $0.id == id }
            if entry != nil || hash != nil { gone.append(RemovedEntry(id: id, grantorKeyHash: entry?.grantorKeyHash ?? hash ?? "")) }
        case nil: break
        }
        let next = try withRemoved(version: max(r.version, seen) + 1, accesses: accesses, r.removed, add: gone)
        var same = next
        same.version = r.version
        return rosterJson(same) == rosterJson(r) ? nil : next
    }

    /// Accesses that hold keys but that the (trusted) roster doesn't list and didn't remove.
    public static func needsConfirmAgain(_ g: Grant, _ roster: Roster?, grantorKeyHash: String? = nil) -> Bool {
        guard let roster else { return false }
        return hasKeys(g) && !roster.accesses.contains { $0.id == g.id } && !isRemoved(roster, g.id, grantorKeyHash: grantorKeyHash)
    }

    /// What the app says about an access the roster removed.
    public static func removedText(_ who: String) -> String {
        "\(who) was removed from your emergency contacts. To give them access again, add them as a new contact."
    }

    /// A roster entry as the grantor reviews it: its own name and email, or "Unknown contact".
    public static func entryLabel(_ e: RosterEntry) -> String {
        let name = e.name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let email = e.email ?? ""
        if !name.isEmpty && !email.isEmpty { return "\(name) (\(email))" }
        if !name.isEmpty { return name }
        return email.isEmpty ? "Unknown contact" : email
    }

    /// The server's roster as the grantor reviews it before "Use the server's list".
    public static func reviewRoster(_ server: Roster, trusted: Roster?, listed: Set<String>) -> [ReviewedEntry] {
        pruneRoster(server, listed: listed).map { entry in
            ReviewedEntry(entry: entry,
                          wouldReturn: !(trusted?.accesses.contains { $0.id == entry.id && $0.contactKey == entry.contactKey } ?? false),
                          removed: isRemoved(server, entry.id, grantorKeyHash: entry.grantorKeyHash) || isRemoved(trusted, entry.id, grantorKeyHash: entry.grantorKeyHash))
        }
    }

    /// Whether `r` is older than the highest roster version this device has opened.
    public static func rosterIsOlder(_ r: Roster, seen: Int64) -> Bool { r.version < seen }

    /// "Use the server's list": exactly the entries the grantor was shown, less those removed and
    /// those the server no longer lists, one version above the newest seen.
    public static func restoredRosterForward(_ shown: [ReviewedEntry], server: Roster, trusted: Roster?, seen: Int64, listedNow: Set<String>) throws -> Roster {
        let accesses = shown.filter { !$0.removed && listedNow.contains($0.entry.id) }.map(\.entry)
        var gone = server.accesses.filter { e in !accesses.contains { $0.id == e.id } }.map { RemovedEntry(id: $0.id, grantorKeyHash: $0.grantorKeyHash) }
        for r in shown where !accesses.contains(r.entry) && !gone.contains(where: { $0.id == r.entry.id }) {
            gone.append(RemovedEntry(id: r.entry.id, grantorKeyHash: r.entry.grantorKeyHash))
        }
        return try withRemoved(version: max(seen, server.version) + 1, accesses: accesses, server.removed + (trusted?.removed ?? []), add: gone)
    }

    /// "Start a new list": an empty one above the newest seen, keeping what `trusted` removed.
    public static func freshRoster(seen: Int64, trusted: Roster? = nil) throws -> Roster {
        try withRemoved(version: seen + 1, accesses: [], trusted?.removed ?? [])
    }

    /// The accesses the fill may add wraps for: those `accessesToFill` lists whose id, contact key
    /// and `grantor_key` (by hash in `hashes`) are in the roster and that it didn't remove.
    public static func fillableAccesses(_ grants: [Grant], _ roster: Roster, hashes: [String: String]) -> [Grant] {
        accessesToFill(grants).filter { g in
            let hash = g.grantorKey.flatMap { hashes[$0] }
            return !isRemoved(roster, g.id, grantorKeyHash: hash)
                && roster.accesses.contains { $0.id == g.id && $0.contactKey == g.grantee.publicKey && hash != nil && $0.grantorKeyHash == hash }
        }
    }

    // MARK: The grantor's vault

    /// `GET /emergency-access/{id}/vault`.
    public struct GrantorVaultData: Equatable, Sendable {
        public struct Vault: Equatable, Sendable {
            public var id: String
            public var meta: String
            public var wrappedKey: String

            public init(id: String, meta: String, wrappedKey: String) {
                self.id = id
                self.meta = meta
                self.wrappedKey = wrappedKey
            }
        }

        public struct Row: Equatable, Sendable {
            public var id: String
            public var vaultId: String
            public var key: String
            public var data: String
            public var deletedAt: Int64?
            public var updatedAt: Int64

            public init(id: String, vaultId: String, key: String, data: String, deletedAt: Int64?, updatedAt: Int64) {
                self.id = id
                self.vaultId = vaultId
                self.key = key
                self.data = data
                self.deletedAt = deletedAt
                self.updatedAt = updatedAt
            }
        }

        public var keyVersion: Int?
        public var sealedKey: String
        public var vaults: [Vault]
        public var items: [Row]
    }

    /// The answer as the core takes it; nil when malformed.
    public static func readGrantorVault(_ v: JSON?) -> GrantorVaultData? {
        guard let v, case .object = v, !str(v["sealed_key"]).isEmpty, case .array(let vs)? = v["vaults"], case .array(let items)? = v["items"] else { return nil }
        let vaults = vs.compactMap { r -> GrantorVaultData.Vault? in
            guard !str(r["id"]).isEmpty, !str(r["meta"]).isEmpty, !str(r["wrapped_key"]).isEmpty else { return nil }
            return GrantorVaultData.Vault(id: str(r["id"]), meta: str(r["meta"]), wrappedKey: str(r["wrapped_key"]))
        }
        let rows = items.compactMap { r -> GrantorVaultData.Row? in
            guard !str(r["id"]).isEmpty, !str(r["vault_id"]).isEmpty, !str(r["item_key"]).isEmpty, !str(r["data"]).isEmpty else { return nil }
            return GrantorVaultData.Row(id: str(r["id"]), vaultId: str(r["vault_id"]), key: str(r["item_key"]), data: str(r["data"]),
                                        deletedAt: num(r["deleted_at"]), updatedAt: num(r["updated_at"]) ?? 0)
        }
        return GrantorVaultData(keyVersion: num(v["key_version"]).map { Int(clamping: $0) }, sealedKey: str(v["sealed_key"]), vaults: vaults, items: rows)
    }
}

/// One access the grantor's apps may add wraps for.
public struct RosterEntry: Equatable, Sendable {
    public var id: String
    /// The contact's public key the grantor checked by its fingerprint.
    public var contactKey: String
    /// SHA-256 of the access's `grantor_key`, base64url.
    public var grantorKeyHash: String
    /// The contact's email address and name as the grantor saw them (missing in older entries).
    public var email: String?
    public var name: String?

    public init(id: String, contactKey: String, grantorKeyHash: String, email: String? = nil, name: String? = nil) {
        self.id = id
        self.contactKey = contactKey
        self.grantorKeyHash = grantorKeyHash
        self.email = email
        self.name = name
    }
}

/// An access taken off the roster for good.
public struct RemovedEntry: Equatable, Sendable {
    public var id: String
    /// SHA-256 of its `grantor_key`, base64url ("" when it never had one).
    public var grantorKeyHash: String

    public init(id: String, grantorKeyHash: String) {
        self.id = id
        self.grantorKeyHash = grantorKeyHash
    }
}

/// The roster's content (inside the sealed box).
public struct Roster: Equatable, Sendable {
    public var version: Int64
    public var accesses: [RosterEntry]
    public var removed: [RemovedEntry]

    public init(version: Int64, accesses: [RosterEntry], removed: [RemovedEntry]) {
        self.version = version
        self.accesses = accesses
        self.removed = removed
    }
}

/// One entry of the server's roster under review.
public struct ReviewedEntry: Equatable, Sendable {
    public var entry: RosterEntry
    /// Not in this device's last trusted roster: taking the list lets them in again.
    public var wouldReturn: Bool
    /// Removed for good (by the server's list or this device's own): shown, never written back.
    public var removed: Bool
}

/// The roster would pass the server's size limit: nothing is written.
public struct RosterFullError: Error, LocalizedError, Equatable {
    public init() {}
    public var errorDescription: String? {
        "Your list of emergency contacts is full. Remove a contact you no longer need, then try again."
    }
}
