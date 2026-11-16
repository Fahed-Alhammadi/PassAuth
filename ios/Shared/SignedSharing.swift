import Foundation
import PassAuthCore

// Signed sharing (servers whose `/api/config` `features` has "signed_sharing"; docs/ARCHITECTURE.md
// "Signed sharing"; core `crates/core/src/sharing.rs`, UniFFI `crates/core-ffi/src/sharing.rs`).
// Whoever seals a vault key to a member signs the share, and the vault's member roster is signed
// too, so a server can't plant a vault key of its own, serve an older key again, or make a key
// replacement seal the new key to members it chose. The server checks shapes and signatures but
// can't vouch for anything: every check here runs on this device, against identities it pinned
// (the account's sealed key pins) and the rosters it trusted before (device-local).
//
// The pure parts are here (unit-tested in `SignedSharingTests`; golden vectors in
// `SignedSharingVectorTests`): identity JSON for the core, the per-vault and per-invitation checks
// (steps 1 and 3 of "What the apps do"), the device-local memory and the wording.
// `VaultRepository` (SignedSharingRepository.swift) does the requests: the signing identity, the
// key pins, roster fetches, accepting and key replacement.

/// The `/api/config` feature of servers with signed sharing.
public let signedSharingFeature = "signed_sharing"

// MARK: Identities

public enum SharingIdentity {
    /// `{user_id, public_key, signing_key, identity_signature, x25519_signature}` (the core's
    /// `PublicIdentity`) from a server row: a member, a lookup answer, a share's signer, an
    /// invitation's sharer (`user_id`, else `id`). Built field by field, never passed on as the
    /// server sent it. nil without an id or a public key.
    public static func json(_ row: JSON?) -> String? {
        object(row).map { JSON.object($0).text }
    }

    static func object(_ row: JSON?) -> [String: JSON]? {
        guard let row, case .object = row else { return nil }
        let id = row["user_id"]?.string ?? row["id"]?.string ?? ""
        let pk = row.str("public_key")
        guard !id.isEmpty, !pk.isEmpty else { return nil }
        func opt(_ k: String) -> JSON { row[k]?.string.map(JSON.string) ?? .null }
        return ["user_id": .string(id), "public_key": .string(pk), "signing_key": opt("signing_key"),
                "identity_signature": opt("identity_signature"), "x25519_signature": opt("x25519_signature")]
    }

    /// A member row for the core (`RosterMemberInput`: the identity, the role and the email the
    /// server lists, cleaned as pins keep it).
    static func memberJson(_ identity: String, role: String, email: String? = nil) -> JSON? {
        guard case .object(var o)? = try? JSON.parse(identity) else { return nil }
        o["role"] = .string(role)
        if let email, !email.isEmpty { o["email"] = .string(email) }
        return .object(o)
    }

    /// The email as pins keep it and the core compares it: one line without control characters,
    /// in the core's `normalize_email` form (invisible characters removed, NFKC, lower case, the
    /// domain in IDNA ASCII, non-ASCII escaped where IDNA refuses it). Every email that is pinned,
    /// compared or sent to the core goes through here, so pins hold one form only.
    static func pinEmail(_ raw: String) -> String {
        let clean = ShownText.clean(raw, limit: 320)
        return clean.isEmpty ? "" : normalizeEmail(email: clean)
    }

    /// The identity fingerprint of an identity hash (base64url): the first 15 bytes in base32
    /// (RFC 4648), groups of four: what `verify_identity` reports, for pins (which keep only the
    /// hash). nil for a hash that isn't 32 bytes.
    public static func fingerprint(hash: String) -> String? {
        guard let bytes = base64url(hash), bytes.count == 32 else { return nil }
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var buffer = 0
        var bits = 0
        for b in bytes.prefix(15) {
            buffer = (buffer << 8) | Int(b)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[(buffer >> bits) & 31])
            }
        }
        var groups: [String] = []
        var i = out.startIndex
        while i < out.endIndex {
            let j = out.index(i, offsetBy: 4, limitedBy: out.endIndex) ?? out.endIndex
            groups.append(String(out[i..<j]))
            i = j
        }
        return groups.joined(separator: "-")
    }

    static func base64url(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }
}

/// A share's signature and its signer as the server sends it (`share`): the signer is the snapshot
/// taken when the share was signed (it still verifies after they changed their name or email, or
/// deleted their account).
public struct ShareRecord: Equatable, Sendable {
    public var signature: String
    /// The signer as the core reads it.
    public var signer: String
    public var signerId: String
    /// The email and name the server lists with the snapshot (cleaned; never trusted).
    public var email: String
    public var name: String
    public var signerDeleted: Bool

    /// nil for `null` (not signed) and for anything that isn't a share.
    public static func read(_ j: JSON?) -> ShareRecord? {
        guard let j, case .object = j, let signature = j["signature"]?.string, !signature.isEmpty,
              let signer = SharingIdentity.json(j["signer"]) else { return nil }
        let s = j["signer"] ?? .null
        return ShareRecord(signature: signature, signer: signer, signerId: s["user_id"]?.string ?? s.str("id"),
                           email: SharingIdentity.pinEmail(s.str("email")), name: ShownText.clean(s.str("name"), limit: 64),
                           signerDeleted: j["signer_deleted"]?.bool ?? false)
    }

    /// Whether a row carries a share at all (an object, readable or not).
    static func present(_ j: JSON?) -> Bool {
        if let j, case .object = j { return true }
        return false
    }
}

/// How an identity stands against the account's key pins, as shown.
public enum PinState: String, Equatable, Sendable {
    /// This account's own identity.
    case me
    /// Seen for the first time (pinned once its check passed, not compared).
    case new
    /// Pinned and compared out of band.
    case verified
    /// Pinned, not compared yet.
    case unverified
    /// Pinned without a signing key, now the same key with one (re-pinned, not compared).
    case upgraded
    /// Another identity than the pinned one: whatever needed it stops.
    case changed
    /// No pin for this user id, but their email is pinned for another account: whatever needed
    /// it stops (a server-made account posing as someone known).
    case emailConflict
}

/// Who signed a share (or an invitation), as the app shows it.
public struct SignerInfo: Equatable, Sendable {
    public let userId: String
    /// The email pinned for them (shown first); nil when not pinned yet.
    public let pinnedEmail: String?
    /// The email the server lists now (shown as "listed by your server as …" when it differs).
    public let listedEmail: String
    /// The name the server lists (never next to "Verified").
    public let name: String
    /// The identity fingerprint (computed by the core from the keys, never the server's).
    public let fingerprint: String
    /// The signer's account was deleted since (the share still verifies).
    public let deleted: Bool
    public let pin: PinState
    /// The identity as the core reads it ("Trust the new key" pins it).
    let identity: String
    /// The identity hash (computed by the core): accepting checks the signer is still this one.
    let identityHash: String
    /// Whether their pin is marked verified (an upgraded pin keeps it).
    let pinnedVerified: Bool

    public init(userId: String, email: String, name: String, fingerprint: String, deleted: Bool, pin: PinState, identity: String,
                pinnedEmail: String? = nil, identityHash: String = "", pinnedVerified: Bool = false) {
        self.userId = userId
        self.listedEmail = SharingIdentity.pinEmail(email)
        self.pinnedEmail = pinnedEmail.map(SharingIdentity.pinEmail)
        self.name = name
        self.fingerprint = fingerprint
        self.deleted = deleted
        self.pin = pin
        self.identity = identity
        self.identityHash = identityHash
        self.pinnedVerified = pinnedVerified
    }

    /// Whether they are in the account's key pins (their email there is the one shown first).
    public var isPinned: Bool { pin == .me || !(pinnedEmail ?? "").isEmpty }

    /// The email "Trust the new key" pins: exactly the one the sheet shows (`email`), raw as pins
    /// keep it: the pinned one, else the one the server lists.
    var trustEmail: String {
        if let p = pinnedEmail, !p.isEmpty { return p }
        return listedEmail
    }

    /// The email to show: the pinned one, else the one the server lists.
    public var email: String {
        if let p = pinnedEmail, !p.isEmpty { return SharingText.shownEmail(p) }
        return SharingText.shownEmail(listedEmail)
    }

    /// The server lists another email than the pinned one: shown as "listed by your server as …".
    public var otherListedEmail: String? {
        guard let p = pinnedEmail, !p.isEmpty, !listedEmail.isEmpty, normalizeEmail(email: p) != normalizeEmail(email: listedEmail) else { return nil }
        return SharingText.shownEmail(listedEmail)
    }

    /// Their email, else (not pinned yet) their name, else "the person who shared it".
    public var shownName: String {
        if !email.isEmpty { return email }
        if pinnedEmail == nil, !name.isEmpty { return name }
        return InvitationText.unknownSharer
    }

    /// Whether this signer still needs pinning once everything else passed.
    var needsPin: Bool { pin == .new || pin == .upgraded }

    /// The email their pin is written with once everything passed: exactly the one shown (an
    /// upgraded pin keeps the email it was pinned with, someone new the one the server lists),
    /// in the one form pins keep (`SharingIdentity.pinEmail`).
    var pinEmailToWrite: String {
        if pin == .upgraded, let p = pinnedEmail, !p.isEmpty { return p }
        return listedEmail
    }

    /// Whether that pin is marked verified: an upgraded pin keeps its mark (the same person, now
    /// with a cross-signed signing key); someone new isn't.
    var pinVerifiedToWrite: Bool { pin == .upgraded && pinnedVerified }

    /// Who signed, as headings and consent texts say it: the pinned email, "you", else only as
    /// the server lists them ("someone listed by your server as …").
    public var heading: String {
        if pin == .me { return "you" }
        if isPinned, !email.isEmpty { return email }
        let listed = SharingText.shownEmail(listedEmail)
        let shown = listed.isEmpty ? ShownText.clean(name, limit: 64) : listed
        return shown.isEmpty ? "someone your server lists" : "someone listed by your server as \(shown)"
    }
}

/// What the checks found out about a vault the app uses.
public enum VaultTrust: Equatable, Sendable {
    /// Not checked: a server without signed sharing (as before).
    case notChecked
    /// The account's own key (wrapped with its own key): its epoch and, with one, its roster checked.
    case own
    /// A shared key whose share signature verified.
    case signed(SignerInfo)
    /// A share from before signed sharing: usable as before, labelled "Not yet signed".
    case notYetSigned
}

/// Why a shared vault isn't used.
public enum Refusal: Error, Equatable, Sendable {
    /// Something didn't verify (signature, roster, key epoch, commitment, role).
    case unverified
    /// The signer's keys changed since they were pinned (or their email is pinned for another
    /// account).
    case keyChanged(SignerInfo)
    /// Its newer member list couldn't be fetched (offline): checked again at the next sync.
    case offline
    /// Its member list changed more often than a device checks at once.
    case tooLarge
    /// Sharing is paused on this device (the server lists a signing key that isn't the account's).
    case paused
    /// The account's key pins refuse it (`pins_admit`): `missing_epoch`, `left`, `older`,
    /// `conflict`, `downgraded`.
    case admission(String)
    /// An unsigned shared vault seen before this device finished the account's first signed
    /// sync (the server hasn't shown it signs yet, the signing identity's state is unknown, or
    /// the grandfathered list isn't written yet): held, neither accepted nor declinable, and
    /// checked again at the next sync (cross-client rule 2).
    case checking
}

/// A shared vault the checks refused: never used for fill, save or display.
public struct RefusedVault: Identifiable, Equatable, Sendable {
    public let id: String
    /// The vault's name as its key opens it (nil when unreadable), cleaned; shown in quotes, it is
    /// the server's claim.
    public let name: String?
    public let reason: Refusal

    public init(id: String, name: String?, reason: Refusal) {
        self.id = id
        self.name = name.map { ShownText.clean($0, limit: 64) }.flatMap { $0.isEmpty ? nil : $0 }
        self.reason = reason
    }
}

/// What the checks found out about an invitation (servers with signed sharing).
public enum InvitationTrust: Equatable, Sendable {
    /// Signed by an owner or admin of the vault's verified member roster, for this account and role.
    case signed(SignerInfo)
    /// Not signed: Decline only.
    case unsigned
    /// The signer's keys changed since they were pinned (or their email is pinned for another
    /// account): Decline, or (keys changed) compare and trust the new key.
    case keyChanged(SignerInfo)
    /// Something didn't verify: Decline only.
    case refused

    public var canAccept: Bool {
        if case .signed = self { return true }
        return false
    }
}

/// What accepting an invitation, or consenting to a vault the server added, writes once the user
/// says yes (`pins_accept` with the same observation the checks admitted): the vault's key epoch
/// pin with the trusted roster's version and hash (and the hashes of the chain fetched for it),
/// the signer's pin and the roster to remember.
public struct Acceptance: Equatable, Sendable {
    /// `VaultKey.epochPinJson` of the key the checks opened.
    let epochPin: String
    let rosterVersion: UInt64?
    let roster: String?
    /// `rosterHash` of `roster` (nil without one): accepting checks it is still the one shown.
    var rosterHash: String?
    /// The signer to pin when not pinned yet (nil: none, or this account).
    let signer: SignerInfo?
    /// The row's key kind (`sealed` for invitations and consent).
    var kind = "sealed"
    /// Its share verified.
    var signedShare = false
    /// `{"<version>": rosterHash}` of the chain the checks fetched (nil: none fetched).
    var chainHashes: [String: String]?

    init(epochPin: String, rosterVersion: UInt64?, roster: String?, rosterHash: String? = nil, signer: SignerInfo?, kind: String = "sealed",
         signedShare: Bool = false, chainHashes: [String: String]? = nil) {
        self.epochPin = epochPin
        self.rosterVersion = rosterVersion
        self.roster = roster
        self.rosterHash = rosterHash
        self.signer = signer
        self.kind = kind
        self.signedShare = signedShare
        self.chainHashes = chainHashes
    }

    /// The observation `pins_accept` gets for `vaultId` (the one the checks admitted).
    func observation(vaultId: String, paused: Bool) -> String {
        SignedSharing.observation(vaultId: vaultId, kind: kind, epochPin: epochPin, rosterVersion: rosterVersion, rosterHash: rosterHash,
                                  chainHashes: chainHashes, signedShare: signedShare, paused: paused)
    }

    /// The key id of the key accepting pins (from the epoch pin), as an unsigned vault's consent
    /// shows it: its first 16 characters in groups of four.
    public var shownKeyId: String {
        let id = (try? JSON.parse(epochPin))?.str("key_id") ?? ""
        let head = Array(id.prefix(16))
        return stride(from: 0, to: head.count, by: 4).map { String(head[$0..<min($0 + 4, head.count)]) }.joined(separator: "-")
    }
}

// MARK: Device memory

/// What this device keeps per account (device-local, never sent): whose memory it is (the
/// account id the core authenticated, and the server), the highest version of the key pins it
/// opened or wrote and those pins (sealed with the account key, at that version), whether that
/// version still has to reach the server, the last roster it trusted per vault, and the vaults
/// whose share it saw signed (a share that comes back unsigned is a rollback).
public struct SharingMemoryRecord: Codable, Equatable, Sendable {
    public var userId: String = ""
    public var server: String = ""
    public var pinsSeq: Int64 = 0
    public var sealedPins: String?
    /// false: `sealedPins` (version `pinsSeq`) is this device's change, not stored on the server yet.
    public var uploaded: Bool = true
    public var rosters: [String: String] = [:]
    public var signed: [String] = []
    /// The signing identity this device made (its hash, and its record, sealed with the account
    /// key), kept before uploading it: a later sync listing a record that opens to this hash counts
    /// it as made here (the upload's answer was lost), and an upload tried again sends the same one.
    public var pendingIdentity: String?
    public var pendingRecord: String?
    /// Shared vaults waiting for consent that may be accepted unsigned (by the key shown): the
    /// account's trust memory was missing (`missingDevice` false), or this device had no earlier
    /// copy of them at the account's first signed sync (true). nil: not changed by this writer
    /// (another process's list stays); empty: none any more.
    public var missing: [String]?
    public var missingDevice: Bool = false
    /// The server showed it signs (its config lists the feature, an identity or key pins request
    /// answered, or it sent anything signed): from then on the checks are sticky and decisions
    /// (pins, tombstones, leaving) may be written. Never written before (cross-client rule 2).
    public var proven = false
    /// Vaults this device showed as usable (an `ok` verdict, or any vault while the checks were
    /// off), in the foreground only: what "this device's earlier copy" means for grandfathering
    /// (cross-client rule 6). Not counted by `isEmpty` (it doesn't turn the checks on). nil: never
    /// recorded (an app from before).
    public var seen: [String]?
    /// The vault ids grandfathering may pass, recorded once when this device generated the
    /// signing identity (from `seen` as it was before that unlock), so rows that arrived later
    /// can't be grandfathered by a later unlock.
    public var candidates: [String]?
    /// The account's key pins remember the own identity and the grandfathered list: the pending
    /// identity and the candidates are dropped for good (a later unlock never counts as the one
    /// that created the identity).
    public var settled = false
    /// Tombstones of vaults declined on the server whose key pins write failed (vault id → trusted
    /// roster version), written at the next sync. nil: not changed by this writer.
    public var tombstones: [String: UInt64]?
    /// The Keychain couldn't be read just now (not stored): nothing is known about this device's
    /// memory, so the checks treat it as having some (shared vaults refused, nothing grandfathered)
    /// and nothing is written over it.
    public var unreadable = false

    public init() {}

    enum CodingKeys: String, CodingKey {
        case userId = "user_id", server, pinsSeq = "pins_seq", sealedPins = "sealed_pins", uploaded, rosters, signed
        case pendingIdentity = "pending_identity", pendingRecord = "pending_record", missing, missingDevice = "missing_device"
        case proven, seen, candidates, settled, tombstones
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userId = (try? c.decodeIfPresent(String.self, forKey: .userId)) ?? ""
        server = (try? c.decodeIfPresent(String.self, forKey: .server)) ?? ""
        pinsSeq = max(0, (try? c.decodeIfPresent(Int64.self, forKey: .pinsSeq)) ?? 0)
        sealedPins = try? c.decodeIfPresent(String.self, forKey: .sealedPins)
        uploaded = (try? c.decodeIfPresent(Bool.self, forKey: .uploaded)) ?? true
        rosters = (try? c.decodeIfPresent([String: String].self, forKey: .rosters)) ?? [:]
        signed = (try? c.decodeIfPresent([String].self, forKey: .signed)) ?? []
        pendingIdentity = try? c.decodeIfPresent(String.self, forKey: .pendingIdentity)
        pendingRecord = try? c.decodeIfPresent(String.self, forKey: .pendingRecord)
        missing = try? c.decodeIfPresent([String].self, forKey: .missing)
        missingDevice = (try? c.decodeIfPresent(Bool.self, forKey: .missingDevice)) ?? false
        proven = (try? c.decodeIfPresent(Bool.self, forKey: .proven)) ?? false
        seen = try? c.decodeIfPresent([String].self, forKey: .seen)
        candidates = try? c.decodeIfPresent([String].self, forKey: .candidates)
        settled = (try? c.decodeIfPresent(Bool.self, forKey: .settled)) ?? false
        tombstones = try? c.decodeIfPresent([String: UInt64].self, forKey: .tombstones)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(userId, forKey: .userId)
        try c.encode(server, forKey: .server)
        try c.encode(pinsSeq, forKey: .pinsSeq)
        try c.encodeIfPresent(sealedPins, forKey: .sealedPins)
        try c.encode(uploaded, forKey: .uploaded)
        try c.encode(rosters, forKey: .rosters)
        try c.encode(signed, forKey: .signed)
        try c.encodeIfPresent(pendingIdentity, forKey: .pendingIdentity)
        try c.encodeIfPresent(pendingRecord, forKey: .pendingRecord)
        try c.encodeIfPresent(missing, forKey: .missing)
        if missingDevice { try c.encode(missingDevice, forKey: .missingDevice) }
        if proven { try c.encode(proven, forKey: .proven) }
        try c.encodeIfPresent(seen, forKey: .seen)
        try c.encodeIfPresent(candidates, forKey: .candidates)
        if settled { try c.encode(settled, forKey: .settled) }
        if let t = tombstones, !t.isEmpty { try c.encode(t, forKey: .tombstones) }
    }

    /// An unreadable record (the Keychain refused the read).
    static var unreadableRecord: SharingMemoryRecord {
        var r = SharingMemoryRecord()
        r.unreadable = true
        return r
    }

    /// Whether this device has seen signed sharing on the account: then the checks run even when
    /// the server stops listing the feature (a downgrade can't switch them off).
    public var isEmpty: Bool {
        !unreadable && !proven && pinsSeq == 0 && sealedPins == nil && rosters.isEmpty && signed.isEmpty && pendingIdentity == nil
    }

    /// At most this many vault ids in `seen` (the oldest drop first).
    static let maxSeen = 2000

    /// The server's version this device's pins build on.
    var serverBase: Int64 { uploaded ? pinsSeq : max(0, pinsSeq - 1) }

    /// The record for `userId` on `server`: this one when it is theirs (or nobody's yet), else an
    /// empty one (another account's memory under the same local account, after "Change server").
    func owned(by userId: String, server: String) -> SharingMemoryRecord {
        if (self.userId.isEmpty || self.userId == userId) && (self.server.isEmpty || self.server == server) {
            var r = self
            r.userId = userId
            r.server = server
            return r
        }
        var fresh = SharingMemoryRecord()
        fresh.userId = userId
        fresh.server = server
        return fresh
    }

    /// `ours` written over this (the stored) record without losing what another process (the app
    /// or its AutoFill extension) stored meanwhile: the higher key pins version with its sealed
    /// copy (at the same version a copy the server has wins), the higher trusted roster per
    /// vault, the union of the vaults seen signed. Another account's record is replaced.
    func merging(_ ours: SharingMemoryRecord) -> SharingMemoryRecord {
        if !userId.isEmpty, !ours.userId.isEmpty, userId != ours.userId { return ours }
        if !server.isEmpty, !ours.server.isEmpty, server != ours.server { return ours }
        var out = self
        if out.userId.isEmpty { out.userId = ours.userId }
        if out.server.isEmpty { out.server = ours.server }
        if ours.sealedPins != nil {
            let take = out.sealedPins == nil || ours.pinsSeq > out.pinsSeq
                || (ours.pinsSeq == out.pinsSeq && (ours.uploaded || !out.uploaded))
            if take {
                out.pinsSeq = ours.pinsSeq
                out.sealedPins = ours.sealedPins
                out.uploaded = ours.uploaded
            }
        }
        for (vault, roster) in ours.rosters {
            if let have = out.rosters[vault], (SignedSharing.rosterVersion(have) ?? 0) >= (SignedSharing.rosterVersion(roster) ?? 0) { continue }
            out.rosters[vault] = roster
        }
        for v in ours.signed where !out.signed.contains(v) { out.signed.append(v) }
        if ours.pendingIdentity != nil {
            out.pendingIdentity = ours.pendingIdentity
            out.pendingRecord = ours.pendingRecord
        }
        if let m = ours.missing {
            out.missing = m
            out.missingDevice = ours.missingDevice
        }
        out.proven = out.proven || ours.proven
        if let s = ours.seen {
            var all = out.seen ?? []
            for v in s where !all.contains(v) { all.append(v) }
            out.seen = Array(all.suffix(Self.maxSeen))
        }
        if out.candidates == nil { out.candidates = ours.candidates }
        if let t = ours.tombstones { out.tombstones = t }
        out.settled = out.settled || ours.settled
        if out.settled {
            out.pendingIdentity = nil
            out.pendingRecord = nil
            out.candidates = nil
        }
        out.unreadable = false
        return out
    }
}

/// Merges this process's key pins into what another process stored (`VaultRepository` opens both
/// with the account key): called under the memory's lock with the stored record and ours, returns
/// ours with the pins to keep.
public typealias SharingMemoryResolver = (_ stored: SharingMemoryRecord, _ ours: SharingMemoryRecord) -> SharingMemoryRecord

public protocol SharingMemory: AnyObject {
    /// The stored record; `unreadable` when the store couldn't be read just now (never "empty").
    func load(_ account: String) -> SharingMemoryRecord
    /// Stores `record` merged into what is stored (`resolve`, then `SharingMemoryRecord.merging`),
    /// never a plain overwrite: the app and its AutoFill extension both write it. false: not
    /// stored now (the store couldn't be read or written, or its lock wasn't free); kept in this
    /// process and tried again with the next save, never written over what couldn't be read.
    @discardableResult
    func save(_ account: String, _ record: SharingMemoryRecord, resolve: SharingMemoryResolver?) -> Bool
    func clear(_ account: String)
}

extension SharingMemory {
    @discardableResult
    public func save(_ account: String, _ record: SharingMemoryRecord) -> Bool { save(account, record, resolve: nil) }
}

/// In the Keychain (the app and its iOS AutoFill extension share it), one item per account; every
/// write merges under a lock file in the shared data directory (`FileLock`). A read the Keychain
/// refuses is never taken for an empty item; a write that can't take the lock, or can't read what
/// is stored first, isn't made: it waits in this process and is tried again with the next save.
public final class KeychainSharingMemory: SharingMemory, @unchecked Sendable {
    /// The Keychain calls (tests replace them).
    public struct Store: Sendable {
        public var lookup: @Sendable (String) -> Keychain.ReadResult
        public var write: @Sendable (String, Data) -> Bool
        public var delete: @Sendable (String) -> Void

        public static let keychain = Store(lookup: { Keychain.lookup($0) }, write: { Keychain.write($0, $1) }, delete: { Keychain.delete($0) })
    }

    private let lockDirectory: URL?
    private let keychain: Store
    private let lockTimeout: TimeInterval
    /// Records not stored yet, by account (tried again with the next save, shown by `load`).
    private var pending: [String: SharingMemoryRecord] = [:]
    private let guardLock = NSLock()

    public init(lockDirectory: URL? = nil, keychain: Store = .keychain, lockTimeout: TimeInterval = 2) {
        self.lockDirectory = lockDirectory
        self.keychain = keychain
        self.lockTimeout = lockTimeout
    }

    private static func key(_ account: String) -> String { "signed-sharing.\(account)" }

    /// The stored record: `.unreadable` when the Keychain refuses the read.
    private func stored(_ account: String) -> SharingMemoryRecord {
        switch keychain.lookup(Self.key(account)) {
        case .found(let d):
            // Data that isn't a record can't be recovered: read as none.
            return (try? JSONDecoder().decode(SharingMemoryRecord.self, from: d)) ?? SharingMemoryRecord()
        case .notFound:
            return SharingMemoryRecord()
        case .failed:
            return .unreadableRecord
        }
    }

    public func load(_ account: String) -> SharingMemoryRecord {
        guard !account.isEmpty else { return SharingMemoryRecord() }
        let r = stored(account)
        guard !r.unreadable else { return r }
        guardLock.lock()
        let waiting = pending[account]
        guardLock.unlock()
        return waiting.map { r.merging($0) } ?? r
    }

    @discardableResult
    public func save(_ account: String, _ record: SharingMemoryRecord, resolve: SharingMemoryResolver?) -> Bool {
        guard !account.isEmpty else { return false }
        guardLock.lock()
        let ours = pending[account].map { $0.merging(record) } ?? record
        pending[account] = ours
        guardLock.unlock()
        // Held briefly (a Keychain read and write). Not free in time (the other process holds it):
        // nothing is written now (merging without it could lose what the other one writes).
        guard let lock = FileLock.acquireSync(FileLock.url("signed-sharing", directory: lockDirectory), timeout: lockTimeout) else { return false }
        defer { lock.release() }
        let have = stored(account)
        guard !have.unreadable else { return false }
        let resolved = resolve?(have, ours) ?? ours
        guard let d = try? JSONEncoder().encode(have.merging(resolved)), keychain.write(Self.key(account), d) else { return false }
        guardLock.lock()
        if pending[account] == ours { pending[account] = nil }
        guardLock.unlock()
        return true
    }

    /// Removes the account's record, under the same lock as writes (an AutoFill extension's
    /// write can't land after it); without the lock in time it is deleted anyway (an account
    /// being removed must not keep its memory).
    public func clear(_ account: String) {
        guard !account.isEmpty else { return }
        guardLock.lock()
        pending[account] = nil
        guardLock.unlock()
        let lock = FileLock.acquireSync(FileLock.url("signed-sharing", directory: lockDirectory), timeout: lockTimeout)
        defer { lock?.release() }
        keychain.delete(Self.key(account))
    }
}

/// In memory only (tests); merges like the Keychain one. `failReads`/`failWrites` act like a
/// Keychain that refuses reads or writes.
public final class InMemorySharingMemory: SharingMemory, @unchecked Sendable {
    private var records: [String: SharingMemoryRecord] = [:]
    private let lock = NSLock()
    public var failReads = false
    public var failWrites = false

    public init() {}

    public func load(_ account: String) -> SharingMemoryRecord {
        lock.lock()
        defer { lock.unlock() }
        if failReads { return .unreadableRecord }
        return records[account] ?? SharingMemoryRecord()
    }

    @discardableResult
    public func save(_ account: String, _ record: SharingMemoryRecord, resolve: SharingMemoryResolver?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if failReads || failWrites { return false }
        let have = records[account] ?? SharingMemoryRecord()
        records[account] = have.merging(resolve?(have, record) ?? record)
        return true
    }

    /// Replaces the record as it is (tests set up a device's memory with it).
    public func put(_ account: String, _ record: SharingMemoryRecord) {
        lock.lock()
        records[account] = record
        lock.unlock()
    }

    public func clear(_ account: String) {
        lock.lock()
        records[account] = nil
        lock.unlock()
    }
}

// MARK: Key pins

/// A pinned identity as the app lists it (Settings → People you share with).
public struct PinnedPerson: Identifiable, Equatable, Sendable {
    public var id: String { userId }
    public let userId: String
    /// The pinned email (cleaned for display).
    public let email: String
    public let fingerprint: String
    public let verified: Bool
    /// The pin's identity hash: "Mark as verified" marks only this identity (the one shown).
    let identityHash: String
}

public enum KeyPinsReader {
    /// The people in the key pins (JSON), sorted by email; entries that can't be read are left out.
    public static func people(_ pins: String?) -> [PinnedPerson] {
        guard let pins, let j = try? JSON.parse(pins) else { return [] }
        return j["pins"]?.array.compactMap { p -> PinnedPerson? in
            let id = p.str("user_id"), pk = p.str("public_key"), hash = p.str("identity")
            guard !id.isEmpty, !pk.isEmpty, let fp = SharingIdentity.fingerprint(hash: hash) else { return nil }
            return PinnedPerson(userId: id, email: SharingText.shownEmail(p.str("email")), fingerprint: fp,
                                verified: p["verified"]?.bool ?? false, identityHash: hash)
        }.sorted { $0.email.localizedCaseInsensitiveCompare($1.email) == .orderedAscending } ?? []
    }

    /// The pin for `userId` (raw: email as pinned, verified), else nil.
    static func pin(_ pins: String?, _ userId: String) -> (email: String, verified: Bool, identity: String)? {
        guard let pins, let j = try? JSON.parse(pins),
              let p = j["pins"]?.array.first(where: { $0.str("user_id") == userId }) else { return nil }
        return (p.str("email"), p["verified"]?.bool ?? false, p.str("identity"))
    }

    /// Whether the pin for `userId` is marked verified.
    static func verified(_ pins: String?, _ userId: String) -> Bool { pin(pins, userId)?.verified ?? false }

    /// The email pinned for `userId` (names a former member), else nil.
    static func email(_ pins: String?, _ userId: String) -> String? {
        pin(pins, userId).flatMap { $0.email.isEmpty ? nil : SharingText.shownEmail($0.email) }
    }

    /// Whether the account's key pins remember an own identity, grandfathered vaults, and a vault's
    /// signed history (an epoch pin with `signed_since`).
    static func field(_ pins: String?, _ name: String) -> JSON? {
        guard let pins, let j = try? JSON.parse(pins) else { return nil }
        let v = j[name]
        if case .null? = v { return nil }
        return v
    }

    static func signedSince(_ pins: String?, _ vaultId: String) -> Bool {
        guard let e = field(pins, "epochs")?[vaultId], let s = e["signed_since"] else { return false }
        if case .null = s { return false }
        return true
    }

    /// The key pins with `userId`'s pin marked verified (the pin itself unchanged) when it still is
    /// the identity `identityHash` the user compared; nil when there is no such pin; throws when
    /// the pinned identity is another one now ("keys changed; compare again").
    static func markingVerified(_ pins: String?, userId: String, identityHash: String) throws -> String? {
        guard let pins, case .object(var root)? = try? JSON.parse(pins), case .array(var list)? = root["pins"] else { return nil }
        guard let i = list.firstIndex(where: { $0.str("user_id") == userId }), case .object(var pin) = list[i] else { return nil }
        guard pin["identity"]?.string == identityHash else { throw UserError(SharingText.keysChangedCompareAgain) }
        pin["verified"] = .bool(true)
        list[i] = .object(pin)
        root["pins"] = .array(list)
        return JSON.object(root).text
    }
}

// MARK: The checks

/// Who this account is to the checks.
struct SharingSelf: Sendable {
    /// This account's identity as the core reads it: its signing identity, or its legacy identity
    /// before it has one (or while sharing is paused).
    let identity: String
    /// The account id the core authenticated (never `/sync` `user.id`).
    let userId: String
    /// The signing identity's hash (nil before it has one, or while paused): a share this account
    /// signed must carry exactly it.
    let signingHash: String?
    let paused: Bool
}

/// What signed sharing needs to check one copy of the vault (made by the repository before
/// decrypting, see `SignedSharingRepository.swift`).
struct SharingInputs: @unchecked Sendable {
    let me: SharingSelf
    /// The account's key pins (JSON; nil: none yet).
    let pins: String?
    /// The pins already differ from the stored ones (own identity remembered, grandfathered).
    let pinsChanged: Bool
    let memory: SharingMemoryRecord
    /// Rosters fetched for vaults (and invitations) whose head was `fetch` (newer than the
    /// remembered one, oldest first); a vault missing here couldn't be fetched (offline).
    let fetched: [String: [String]]
    /// Vaults whose newer rosters were beyond what a device checks at once.
    let tooLarge: Set<String>
    /// Every shared (sealed) vault is refused for this reason (`Refusal.admission`): the key pins
    /// the server lists couldn't be had on a device without its own copy (`pins_unavailable`), or
    /// this device's memory couldn't be read (`memory_unreadable`).
    var unavailable: String?
    /// What the checks change may be kept (device memory, key pins): the server has shown it signs.
    /// Not yet (its config unknown): the checks run, nothing that keeps them on is stored.
    var keep = true
    /// The server withholds a newer list of known keys: this device's changes stay on it.
    var holdPins = false
    /// This device finished the account's first signed sync (the server showed it signs, the
    /// signing identity's state is known, the grandfathered list is written): only then is an
    /// unsigned shared vault the account never accepted shown for consent; before, it is held
    /// neutrally (`Refusal.checking`; cross-client rule 2).
    var firstSyncDone = false
    /// What the vault list says about the account's keys (paused, rollback, …), before the
    /// consent states (`missing`) are added.
    var notice: String?
    let now: Int64

    var meId: String { me.userId }
}

/// What the checks changed: the key pins (new signers, epoch pins) and the device memory.
struct SharingOutputs: Sendable {
    var pins: String?
    var pinsChanged = false
    var memory: SharingMemoryRecord
    var keep = true
    var holdPins = false
    var notice: String?
}

enum SignedSharing {
    /// The outcome of checking one vault row.
    enum VaultCheck: Equatable {
        /// Usable: its trust, the roster to remember (nil: none) and the key pins with what this
        /// row adds (its epoch pin, a new signer).
        case ok(VaultTrust, roster: String?, pins: String?)
        /// A sealed vault this account never accepted (or left, re-shared since: `rejoin`): not
        /// opened beyond its name; shown like an invitation. `signer`: its share verified (as
        /// checked); `own`: the account held it with its own key wrap before.
        case consent(Acceptance, rejoin: Bool, replaced: Bool, own: Bool, signer: SignerInfo?)
        case refused(Refusal)
    }

    /// A trusted roster and, when newer rosters were fetched and verified for it, the chain's
    /// roster hashes (`chain_hashes`: the remembered roster and every newer one).
    struct Trusted {
        var roster: String?
        var chainHashes: [String: String]?
    }

    /// The status `roster_head` reports (`unsigned`, `same`, `fetch` with `after`), or nil when
    /// it refuses (rollback, fork, another vault's, unreadable).
    static func head(_ vaultId: String, remembered: String?, latest: String?) -> (status: String, after: Int64)? {
        guard let text = try? rosterHead(vaultId: vaultId, remembered: remembered, latest: latest), let j = try? JSON.parse(text) else { return nil }
        return (j.str("status"), j["after"]?.number ?? 0)
    }

    /// The trusted roster of a vault after the server's `latest`: the remembered one when the
    /// same, else the verified chain from it. `.failure(.offline)` when newer rosters are needed
    /// but weren't fetched.
    static func trustedRoster(_ vaultId: String, remembered: String?, latest: String?, newer: [String]?, tooLarge: Bool) -> Result<Trusted, Refusal> {
        guard let h = head(vaultId, remembered: remembered, latest: latest) else { return .failure(.unverified) }
        switch h.status {
        case "unsigned": return .success(Trusted())
        case "same": return .success(Trusted(roster: remembered))
        case "fetch":
            if tooLarge { return .failure(.tooLarge) }
            guard let newer, let latest else { return .failure(.offline) }
            guard let chain = try? verifyRosterChain(vaultId: vaultId, trusted: remembered, newer: newer, latest: latest),
                  let hashes = chainHashes(remembered: remembered, newer: newer) else { return .failure(.unverified) }
            return .success(Trusted(roster: chain, chainHashes: hashes))
        default: return .failure(.unverified)
        }
    }

    /// `chain_hashes` of a verified chain: `rosterHash` of the roster it started from (if any)
    /// and of every newer one, by version (plain decimal). nil when a hash can't be had.
    static func chainHashes(remembered: String?, newer: [String]) -> [String: String]? {
        var out: [String: String] = [:]
        for roster in (remembered.map { [$0] } ?? []) + newer {
            guard let version = rosterVersion(roster), let hash = try? rosterHash(rosterJson: roster) else { return nil }
            out[String(version)] = hash
        }
        return out
    }

    /// One vault row (`docs/ARCHITECTURE.md` "What the apps do", step 1), its key opened with the
    /// row's epoch: (b) the roster chain from the remembered roster ending exactly at the row's,
    /// the key's epoch and commitment against it and this account's role in it; (c) a sealed
    /// key's share signature by an owner or admin of that roster, its signer checked against the
    /// pins; (d) the account's key pins' verdict (`pins_admit`). The new pins (epoch pin, a new
    /// signer) come back only for a usable row.
    static func checkVault(_ v: SyncVault, key: VaultKey, me: SharingSelf, pins: String?, remembered: String?, newer: [String]?,
                           tooLarge: Bool, seenSigned: Bool, now: Int64) -> VaultCheck {
        guard let rowEpoch = v.keyEpoch, rowEpoch >= 0 else { return .refused(.admission("missing_epoch")) }
        let epoch = UInt64(rowEpoch)
        let kind = v.keyKind.isEmpty ? VaultInfo.accountKeyKind : v.keyKind
        // Paused (the server lists a signing key that isn't this account's): no shared vault is used.
        if me.paused && kind != VaultInfo.accountKeyKind { return .refused(.paused) }
        // (b) The member roster.
        let trusted: String?
        let chain: [String: String]?
        switch trustedRoster(v.id, remembered: remembered, latest: v.memberRoster, newer: newer, tooLarge: tooLarge) {
        case .success(let r):
            trusted = r.roster
            chain = r.chainHashes
        case .failure(let r): return .refused(r)
        }
        if let roster = trusted {
            // Paused, this account checks with its legacy identity, which a roster listing its full
            // one doesn't match: its own (account-wrapped) vaults are found by its user id then.
            let mine = ((try? rosterMemberRole(rosterJson: roster, identityJson: me.identity)) ?? nil)
                ?? (me.paused && kind == VaultInfo.accountKeyKind ? roleOf(roster, userId: me.userId) : nil)
            guard rosterEpoch(roster) == rowEpoch, (try? key.matchesRoster(vaultId: v.id, rosterJson: roster)) == true,
                  mine == v.role else { return .refused(.unverified) }
        }
        // (c) A key someone sealed to this account.
        var signer: SignerInfo?
        var signedShare = false
        if kind != VaultInfo.accountKeyKind {
            if let share = ShareRecord.read(v.share) {
                switch checkSigner(share, me: me, pins: pins) {
                case .success(let s): signer = s
                case .failure(let r): return .refused(r)
                }
                guard (try? verifyShare(vaultId: v.id, recipientJson: me.identity, role: v.role, keyEpoch: epoch, sealedKey: v.wrappedKey,
                                        signerJson: share.signer, signature: share.signature)) != nil else { return .refused(.unverified) }
                if let roster = trusted {
                    let role = (try? rosterSignerRole(rosterJson: roster, signerJson: share.signer)) ?? nil
                    guard role == "owner" || role == "admin" else { return .refused(.unverified) }
                }
                signedShare = true
            } else if ShareRecord.present(v.share) {
                return .refused(.unverified)
            } else if seenSigned {
                // Seen signed on this device before, now not: a rollback.
                return .refused(.admission("downgraded"))
            }
        }
        // (d) The account's verdict (`pins_observe`: `pins_admit`, and what its `pin` says pinned).
        guard let epochPin = try? key.epochPinJson(vaultId: v.id, keyEpoch: epoch) else { return .refused(.unverified) }
        let version = trusted.flatMap(rosterVersion)
        let hash = trusted.flatMap { try? rosterHash(rosterJson: $0) }
        guard trusted == nil || hash != nil,
              let observed = observe(pins, vaultId: v.id, kind: kind, epochPin: epochPin, rosterVersion: version, rosterHash: hash,
                                     chainHashes: chain, signedShare: signedShare, paused: me.paused),
              let verdict = observed.admission else { return .refused(.unverified) }
        switch verdict.str("status") {
        case "ok":
            var p = observed.pins
            if let s = signer, s.needsPin {
                guard let next = try? pinSet(pinsJson: p, identityJson: s.identity, email: s.pinEmailToWrite, verified: s.pinVerifiedToWrite,
                                             now: now) else {
                    return .refused(.unverified)
                }
                p = next
            }
            let trust: VaultTrust = switch verdict.str("trust") {
            case "own": .own
            case "signed": signer.map { .signed($0) } ?? .own
            default: .notYetSigned
            }
            return .ok(trust, roster: trusted, pins: p)
        case "consent":
            // Accepting runs `pins_accept` on this same observation.
            return .consent(Acceptance(epochPin: epochPin, rosterVersion: version, roster: trusted, rosterHash: hash,
                                       signer: signer?.needsPin == true ? signer : nil, kind: kind, signedShare: signedShare, chainHashes: chain),
                            rejoin: verdict["rejoin"]?.bool ?? false, replaced: verdict["replaced"]?.bool ?? false,
                            own: verdict["own"]?.bool ?? false, signer: signer)
        default:
            let reason = verdict.str("reason")
            return .refused(reason == "paused" ? .paused : .admission(reason.isEmpty ? "unverified" : reason))
        }
    }

    /// The observation of a row for `pins_admit` / `pins_observe` / `pins_accept`: `signed_share`
    /// and `paused` always (required since round 4), `chain_hashes` whenever a chain was fetched.
    static func observation(vaultId: String, kind: String, epochPin: String?, rosterVersion: UInt64?, rosterHash: String? = nil,
                            chainHashes: [String: String]? = nil, signedShare: Bool, paused: Bool) -> String {
        var o: [String: JSON] = ["vault_id": .string(vaultId), "key_kind": .string(kind), "signed_share": .bool(signedShare),
                                 "paused": .bool(paused)]
        o["key"] = epochPin.flatMap { try? JSON.parse($0) } ?? .null
        o["roster_version"] = rosterVersion.map { .int(Int64($0)) } ?? .null
        if let rosterHash { o["roster_hash"] = .string(rosterHash) }
        if let chainHashes { o["chain_hashes"] = .object(chainHashes.mapValues { .string($0) }) }
        return JSON.object(o).text
    }

    /// `pins_observe` for a row: the verdict and the key pins with what it says to pin.
    static func observe(_ pins: String?, vaultId: String, kind: String, epochPin: String?, rosterVersion: UInt64?, rosterHash: String?,
                        chainHashes: [String: String]? = nil, signedShare: Bool, paused: Bool) -> (admission: JSON?, pins: String?)? {
        let o = observation(vaultId: vaultId, kind: kind, epochPin: epochPin, rosterVersion: rosterVersion, rosterHash: rosterHash,
                            chainHashes: chainHashes, signedShare: signedShare, paused: paused)
        guard let text = try? pinsObserve(pinsJson: pins, observationJson: o), let j = try? JSON.parse(text) else { return nil }
        let changed = j["changed"]?.bool ?? false
        return (j["admission"], changed ? j["pins"].map(\.text) : pins)
    }

    /// `pins_admit` for a row.
    static func admit(_ pins: String?, vaultId: String, kind: String, epochPin: String?, rosterVersion: UInt64?, rosterHash: String? = nil,
                      chainHashes: [String: String]? = nil, signedShare: Bool, paused: Bool) -> JSON? {
        let o = observation(vaultId: vaultId, kind: kind, epochPin: epochPin, rosterVersion: rosterVersion, rosterHash: rosterHash,
                            chainHashes: chainHashes, signedShare: signedShare, paused: paused)
        guard let text = try? pinsAdmit(pinsJson: pins, observationJson: o) else { return nil }
        return try? JSON.parse(text)
    }

    /// The signer of a share against the key pins (read only: pinning happens once every check
    /// of the row passed): refused when their identity doesn't verify, stopped when it changed or
    /// their email is pinned for another account. This account itself is never pinned: a share it
    /// signed must carry exactly its signing identity.
    static func checkSigner(_ share: ShareRecord, me: SharingSelf, pins: String?) -> Result<SignerInfo, Refusal> {
        guard let infoText = try? verifyIdentity(identityJson: share.signer), let info = try? JSON.parse(infoText) else {
            return .failure(.unverified)
        }
        let fingerprint = info.str("fingerprint")
        let userId = info.str("user_id")
        let pinned = KeyPinsReader.pin(pins, userId)
        func signer(_ pin: PinState) -> SignerInfo {
            SignerInfo(userId: userId, email: share.email, name: share.name, fingerprint: fingerprint, deleted: share.signerDeleted, pin: pin,
                       identity: share.signer, pinnedEmail: pinned?.email, identityHash: info.str("hash"), pinnedVerified: pinned?.verified ?? false)
        }
        if userId == me.userId {
            guard let mine = me.signingHash, mine == info.str("hash") else { return .failure(.unverified) }
            return .success(signer(.me))
        }
        guard let status = try? pinCheck(pinsJson: pins, identityJson: share.signer, email: share.email) else { return .failure(.unverified) }
        switch status {
        case "match": return .success(signer(pinned?.verified == true ? .verified : .unverified))
        case "new": return .success(signer(.new))
        case "upgraded": return .success(signer(.upgraded))
        case "changed": return .failure(.keyChanged(signer(.changed)))
        case "email_conflict": return .failure(.keyChanged(signer(.emailConflict)))
        default: return .failure(.unverified)
        }
    }

    /// An invitation (step 3): signed by an owner or admin of the vault's verified roster chain
    /// (from the remembered roster, ending exactly at the invitation's), for this account with the
    /// invitation's role and epoch, the sealed key the one the roster commits to, the signer
    /// checked against the pins (read only: nothing is pinned before the user accepts), and the
    /// account's key pins not refusing the vault (a vault it left needs a newer roster). Returns
    /// the trust and what accepting writes.
    static func checkInvitation(_ inv: SyncInvitation, key: VaultKey?, me: SharingSelf, pins: String?, remembered: String?, newer: [String]?,
                                tooLarge: Bool) -> (InvitationTrust, Acceptance?) {
        guard let share = ShareRecord.read(inv.share) else { return (ShareRecord.present(inv.share) ? .refused : .unsigned, nil) }
        guard let key, let rowEpoch = inv.keyEpoch, rowEpoch >= 0, !me.paused else { return (.refused, nil) }
        let epoch = UInt64(rowEpoch)
        let signer: SignerInfo
        switch checkSigner(share, me: me, pins: pins) {
        case .success(let s): signer = s
        case .failure(.keyChanged(let s)): return (.keyChanged(s), nil)
        case .failure: return (.refused, nil)
        }
        guard (try? verifyShare(vaultId: inv.vaultId, recipientJson: me.identity, role: inv.role, keyEpoch: epoch, sealedKey: inv.wrappedKey,
                                signerJson: share.signer, signature: share.signature)) != nil,
              inv.memberRoster != nil,
              case .success(let trusted) = trustedRoster(inv.vaultId, remembered: remembered, latest: inv.memberRoster, newer: newer, tooLarge: tooLarge),
              let roster = trusted.roster,
              rosterEpoch(roster) == rowEpoch,
              (try? key.matchesRoster(vaultId: inv.vaultId, rosterJson: roster)) == true else { return (.refused, nil) }
        let signerRole = (try? rosterSignerRole(rosterJson: roster, signerJson: share.signer)) ?? nil
        let myRole = (try? rosterMemberRole(rosterJson: roster, identityJson: me.identity)) ?? nil
        guard signerRole == "owner" || signerRole == "admin", myRole == inv.role,
              let epochPin = try? key.epochPinJson(vaultId: inv.vaultId, keyEpoch: epoch) else { return (.refused, nil) }
        let version = rosterVersion(roster)
        guard let hash = try? rosterHash(rosterJson: roster) else { return (.refused, nil) }
        let o = observation(vaultId: inv.vaultId, kind: "sealed", epochPin: epochPin, rosterVersion: version,
                            rosterHash: hash, chainHashes: trusted.chainHashes, signedShare: true, paused: me.paused)
        guard let text = try? pinsAdmit(pinsJson: pins, observationJson: o), let verdict = try? JSON.parse(text),
              verdict.str("status") != "refused" else { return (.refused, nil) }
        return (.signed(signer), Acceptance(epochPin: epochPin, rosterVersion: version, roster: roster, rosterHash: hash,
                                            signer: signer.needsPin ? signer : nil, kind: "sealed", signedShare: true,
                                            chainHashes: trusted.chainHashes))
    }

    /// A roster's key epoch (read only after the core verified the roster).
    static func rosterEpoch(_ roster: String) -> Int64? {
        (try? JSON.parse(roster))?["key_epoch"]?.number
    }

    /// A roster's version (read only after the core verified it).
    static func rosterVersion(_ roster: String) -> UInt64? {
        (try? JSON.parse(roster))?["version"]?.number.map { UInt64(max(0, $0)) }
    }

    /// The role a (verified) roster gives a user id.
    static func roleOf(_ roster: String, userId: String) -> String? {
        (try? JSON.parse(roster))?["members"]?.array.first { $0.str("user_id") == userId }?["role"]?.string
    }

    /// The members a roster lists (user ids), for naming people.
    static func rosterMembers(_ roster: String) -> [String] {
        (try? JSON.parse(roster))?["members"]?.array.map { $0.str("user_id") } ?? []
    }
}

// MARK: Member reviews

/// One member of a review (`roster_review`), as the review sheet shows them.
public struct ReviewPerson: Identifiable, Equatable, Sendable {
    public var id: String { userId }
    public let userId: String
    public let role: String
    public let fingerprint: String
    public let isSelf: Bool
    /// `new`, `match`, `changed`, `upgraded`, `email_conflict`.
    public let pin: String
    public let verified: Bool
    /// Pinned email (shown first), the email the server lists now (cleaned).
    public let pinnedEmail: String?
    public let listedEmail: String?
    /// `same`, `added`, `identity_changed`, `role_changed`.
    public let change: String

    /// The pinned email, else the listed one, else "a member".
    public var shownEmail: String {
        if let p = pinnedEmail, !p.isEmpty { return p }
        if let l = listedEmail, !l.isEmpty { return l }
        return "a member"
    }

    /// The server lists another email than the pinned one.
    public var otherListedEmail: String? {
        guard let p = pinnedEmail, !p.isEmpty, let l = listedEmail, !l.isEmpty, normalizeEmail(email: p) != normalizeEmail(email: l) else { return nil }
        return l
    }

    /// "Verified", "Not verified", "New", "Keys changed"…
    public var pinLabel: String {
        if isSelf { return "You" }
        switch pin {
        case "match": return verified ? SharingText.verified : SharingText.notVerified
        case "new": return "New: not verified"
        case "upgraded": return "New signing key: not verified"
        case "email_conflict": return "Another account with this email"
        default: return "Keys changed"
        }
    }
}

/// `roster_review`'s answer, read.
public struct MemberReview: Equatable, Sendable {
    public let vaultId: String
    public let version: UInt64
    public let first: Bool
    public let blocked: Bool
    public let members: [ReviewPerson]
    /// Members of the trusted roster the server doesn't list.
    public let missing: [MissingPerson]
    public let digest: String

    public struct MissingPerson: Equatable, Sendable {
        public let userId: String
        /// Their pinned email (cleaned), else nil.
        public let email: String?
    }

    static func read(_ text: String) -> MemberReview? {
        guard let j = try? JSON.parse(text), let digest = j["digest"]?.string, let version = j["version"]?.number else { return nil }
        let clean: (JSON?) -> String? = { v in v?.string.map(SharingText.shownEmail).flatMap { $0.isEmpty ? nil : $0 } }
        let members = (j["members"]?.array ?? []).map { m in
            ReviewPerson(userId: m.str("user_id"), role: m.str("role"), fingerprint: m.str("fingerprint"), isSelf: m["is_self"]?.bool ?? false,
                         pin: m.str("pin"), verified: m["verified"]?.bool ?? false, pinnedEmail: clean(m["pinned_email"]),
                         listedEmail: clean(m["listed_email"]), change: m.str("change"))
        }
        let missing = (j["missing"]?.array ?? []).map { MissingPerson(userId: $0.str("user_id"), email: clean($0["pinned_email"])) }
        return MemberReview(vaultId: j.str("vault_id"), version: UInt64(max(0, version)), first: j["first"]?.bool ?? false,
                            blocked: j["blocked"]?.bool ?? false, members: members, missing: missing, digest: digest)
    }

    /// Members whose key changed (pin `changed`/`email_conflict`, or another identity than the
    /// trusted roster's): why a blocked review stops.
    var blockers: [ReviewPerson] {
        members.filter { $0.pin == "changed" || $0.pin == "email_conflict" || $0.change == "identity_changed" }
    }

    /// Members the trusted roster doesn't list as they are now (added, another identity or role).
    var changed: [ReviewPerson] { members.filter { $0.change != "same" } }
}

// MARK: Wording

public enum SharingText {
    public static let refused = "PassAuth couldn't verify this shared vault's key, so it isn't used. Ask its owner, or your server's admin."
    public static let offline = "PassAuth couldn't check this shared vault's newer member list while offline, so it isn't used until PassAuth reaches your server."
    public static let tooLarge = "This shared vault's member list changed more often than PassAuth checks at once, so it isn't used. Ask its owner, or your server's admin."
    public static let notYetSigned = "Not yet signed"
    public static let notYetSignedHelp = "This vault was shared before PassAuth signed shared vaults. Its owner or an admin can sign it in the web vault or the desktop app."
    public static let paused = "Your server lists a signing key that isn't yours. Sharing is paused on this device."
    public static let pausedRefusal = "Sharing is paused on this device (your server lists a signing key that isn't yours), so shared vaults aren't used."
    public static let pinsRolledBack = "Your server sent an older list of known keys. PassAuth keeps using the newer list on this device."
    public static let trustMemoryMissing = "PassAuth couldn't find your list of known keys on your server, so each shared vault needs your OK again. If you didn't expect this, tell your server's admin."
    /// The account's first signed sync ran on a device with no earlier copy of its vaults.
    public static let newDevice = "This device had no earlier copy of your shared vaults, so each one shared before signing needs your OK once. Accept only the ones you expected."
    /// The server lists a newer list of known keys than this device's but didn't give it.
    public static let pinsWithheld = "Your server didn't send your newer list of known keys. PassAuth keeps using the list on this device."
    /// This device has no list of known keys and couldn't get the server's.
    public static let pinsUnavailable = "PassAuth couldn't get your list of known keys from your server, so shared vaults aren't used until it can."
    /// The Keychain couldn't be read just now.
    public static let memoryUnreadable = "PassAuth couldn't read what this device knows about your shared vaults, so they aren't used until it can. Unlock your device and try again."
    public static let wrongAccount = "Your server sent another account's data, so PassAuth didn't use it."
    public static let ownFingerprint = "Your identity fingerprint"
    public static let ownFingerprintHelp = "People you share vaults with compare this with the fingerprint their app shows for you, for example on a call."
    public static let peopleTitle = "People you share with"
    public static let peopleHelp = "PassAuth remembers the keys of everyone who shared a vault with you or whom you share with. Compare a fingerprint with the person, for example on a call, then mark it as verified."
    public static let trustNewKey = "Trust the new key…"
    public static let markVerified = "Mark as verified…"
    public static let verified = "Verified"
    public static let notVerified = "Not verified"
    public static let sharedVaultsTitle = "Shared vaults"
    public static let unknownMember = "a former member"
    public static let keysChangedCompareAgain = "This person's keys changed since the list was shown. Compare the fingerprint with them again."

    /// An email as shown: the form key pins compare (lower case, an internationalized domain in
    /// punycode, so a look-alike domain can't pass for a known one), cleaned to one line of at
    /// most 128 characters.
    public static func shownEmail(_ raw: String) -> String {
        ShownText.clean(normalizeEmail(email: ShownText.clean(raw, limit: 320)), limit: 128)
    }

    /// "Signed by alex@example.com", "Signed by alex@example.com (account deleted)", "Signed by you".
    public static func signedBy(_ s: SignerInfo) -> String {
        if s.pin == .me { return "Signed by you" }
        return "Signed by \(s.shownName)" + (s.deleted ? " (account deleted)" : "")
    }

    /// "Listed by your server as bob@new.example" when the server lists another email than the
    /// pinned one.
    public static func listedAs(_ email: String) -> String { "Listed by your server as \(email)" }

    /// The pin state as a short label (nil for this account).
    public static func pinLabel(_ s: SignerInfo) -> String? {
        switch s.pin {
        case .me: nil
        case .verified: verified
        case .new, .unverified, .upgraded: notVerified
        case .changed: "Keys changed"
        case .emailConflict: "Unknown account"
        }
    }

    /// Under a signer seen for the first time (or whose key just got a signing key).
    public static func firstTime(_ s: SignerInfo) -> String? {
        switch s.pin {
        case .new: "First time you share with \(s.shownName): compare this fingerprint with them."
        case .upgraded: "\(s.shownName) has a new signing key. Compare this fingerprint with them."
        default: nil
        }
    }

    public static func keyChanged(_ s: SignerInfo) -> String {
        if s.pin == .emailConflict { return emailConflict(s.shownName) }
        return "\(s.shownName)'s keys changed. Compare their fingerprint with them before you continue."
    }

    public static func emailConflict(_ email: String) -> String {
        "Your server lists a new account for \(email), whose keys you already know under another account."
    }

    public static func trustNewKeyBody(_ s: SignerInfo) -> String {
        "Only trust the new key after you compared this fingerprint with \(s.shownName), for example on a call. If you can't, ask your server's admin."
    }

    public static func fingerprintLabel(_ s: SignerInfo) -> String { "Identity fingerprint of \(s.shownName)" }

    /// Under "Trust the new key": the email the new key is saved with (the one shown).
    public static func trustSavedAs(_ s: SignerInfo) -> String {
        let email = shownEmail(s.trustEmail)
        return "PassAuth saves the new key for \(email.isEmpty ? InvitationText.unknownSharer : email)."
    }

    public static func markVerifiedBody(_ email: String) -> String {
        "Mark this as verified only if \(email.isEmpty ? "the person" : email) read you the same fingerprint, for example on a call."
    }

    /// Why a vault isn't used.
    public static func refusal(_ r: Refusal) -> String {
        switch r {
        case .unverified: refused
        case .offline: offline
        case .tooLarge: tooLarge
        case .paused: pausedRefusal
        case .checking: checking
        case .keyChanged(let s): keyChanged(s) + " Until then this shared vault isn't used."
        case .admission(let reason):
            switch reason {
            case "left": "You left this vault, so PassAuth doesn't use it. It can come back only if someone shares it with you again."
            case "older": refused + " Your server sent an older key for it."
            case "conflict": refused + " Your server sent another key for it than before."
            case "downgraded": refused + " It was signed before, and your server now sends it without its signature or member list."
            case "missing_epoch": refused + " Your server didn't say which key it uses."
            case "roster_forked": refused + " Your server sent two different member lists with the same number."
            case "pins_unavailable": pinsUnavailable
            case "memory_unreadable": memoryUnreadable
            default: refused
            }
        }
    }

    /// One line for the vault list; nil when nothing was refused.
    public static func refusedNotice(_ list: [RefusedVault]) -> String? {
        guard !list.isEmpty else { return nil }
        if list.allSatisfy({ $0.reason == .offline }) {
            return list.count == 1 ? "A shared vault isn't shown until PassAuth reaches your server." : "\(list.count) shared vaults aren't shown until PassAuth reaches your server."
        }
        if list.allSatisfy({ $0.reason == .checking }) {
            return list.count == 1 ? "A shared vault isn't shown until PassAuth finishes checking it." : "\(list.count) shared vaults aren't shown until PassAuth finishes checking them."
        }
        return list.count == 1 ? "PassAuth couldn't verify a shared vault, so it isn't shown." : "PassAuth couldn't verify \(list.count) shared vaults, so they aren't shown."
    }

    // Invitations and vaults the server added

    public static func unsignedInvitation(_ who: String) -> String {
        "This invitation isn't signed. Ask \(who) to update PassAuth and share again."
    }

    public static func refusedInvitation(_ who: String) -> String {
        "PassAuth couldn't verify this invitation, so it can't be accepted. Decline it, then ask \(who) to share the vault again."
    }

    /// A sealed vault this account never accepted, shown like an invitation.
    public static func consent(_ name: String?) -> String {
        "Your server added " + (name.map { "\u{201C}\($0)\u{201D}" } ?? "a shared vault") + " to your account. Accept only if you expected it."
    }

    public static func rejoin(_ name: String?) -> String {
        "You left " + (name.map { "\u{201C}\($0)\u{201D}" } ?? "this vault") + " before, and it was shared with you again. Accept only if you expected it."
    }

    /// A vault already accepted, never seen signed, whose key changed: unsigned ("by an app that
    /// doesn't sign yet"), or signed for the first time by `signer` (pinned email first, else only
    /// as the server lists them; their fingerprint is shown with it).
    public static func replaced(_ name: String?, signer: SignerInfo? = nil) -> String {
        let vault = name.map { "\u{201C}\($0)\u{201D}" } ?? "this vault"
        guard let signer else {
            return "The key of \(vault) was replaced by an app that doesn't sign yet. Accept only if someone in this vault just replaced its key."
        }
        return "The key of \(vault) was replaced and signed by \(signer.heading) for the first time. Compare their fingerprint before you accept."
    }

    /// Before the consent text of a vault the account held with its own key wrap.
    public static func ownVault(_ name: String?) -> String {
        (name.map { "\u{201C}\($0)\u{201D}" } ?? "This vault") + " was your own vault. Your server now says someone else gave you a new key for it. Accept only if you shared this vault and expected a key change."
    }

    /// Under an unsigned vault the server added that may not be accepted here: no Decline either
    /// (declining writes a tombstone, and a server could make a real vault look like this).
    public static let consentUnsigned = "This vault isn't signed, so PassAuth can't accept it. Ask the vault's owner to sign this vault."
    /// Under an unsigned vault that may be accepted (trust memory missing, a new device, an
    /// unsigned key replacement): the key accepting pins.
    public static func consentKeyId(_ keyId: String) -> String { "Key ID: \(keyId)" }
    /// An unsigned shared vault seen before the account's first signed sync finished.
    public static let checking = "PassAuth is still checking this shared vault. It is used once PassAuth has checked it with your server."
    /// Decline isn't offered for this entry (unsigned, or a replaced key: keep it locked).
    public static let cantDecline = "This vault can't be declined here. It stays locked until you accept it or its owner signs it."
    /// The server allows a limited number of key replacements per vault and hour (429 `rate_limited`).
    public static func keyReplacementLimited(_ retryAfter: Int?) -> String {
        "This vault's key was replaced too often in the last hour, so your server didn't take another replacement. "
            + (retryAfter.map { "Try again in \(waitText($0))." } ?? "Try again later.")
    }

    // Key replacement

    public static func membersDiffer(_ people: [String]) -> String {
        "The server lists members your vault's signed member list doesn't: \(people.joined(separator: ", ")). PassAuth didn't change the key."
    }

    public static func memberKeyChanged(_ who: String) -> String {
        "\(who)'s keys changed. Compare their fingerprint with them before you continue. PassAuth didn't change the key."
    }

    public static let needsIdentity = "This vault's members are signed, and this device can't sign yet. Unlock PassAuth while it can reach your server, then try again."
    public static let reviewTitle = "Check the members"
    public static let reviewFirst = "First time this vault is signed: compare these fingerprints with the people. PassAuth seals the new key only to the members you confirm here."
    public static let reviewConfirm = "I compared them: replace the key"

    /// A vault whose members need the review before its key is replaced.
    public static func reviewNeeded(_ name: String) -> String {
        "\(name.isEmpty ? "A vault" : name)'s members were never signed. Check them before PassAuth replaces its key."
    }
}
