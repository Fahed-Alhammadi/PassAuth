import Foundation
import PassAuthCore

// Vault manifests (docs/ARCHITECTURE.md "Vault manifests"; servers whose `/api/config`
// `features` has "vault_manifest"). Each vault carries a small sealed record of its items (a
// version, how many are live and in the trash, and a sum over every item's id, state and
// encrypted data), written by the members' apps with every change. After every sync the app
// computes the same over the items it now holds and compares, so a server can't serve an older
// item, hide a new one or a deletion, or bring a deleted item back without it showing. The core
// does the arithmetic (`VaultKey.manifestVerify` / `manifestStart` / `manifestNext`); the pure
// rules around it are here (unit-tested in `VaultManifestTests`), the requests in
// `VaultRepository`.

/// The `/api/config` feature of servers that keep vault manifests.
public let vaultManifestFeature = "vault_manifest"

/// What the last check of a vault against its manifest found.
public enum ManifestStatus: String, Sendable, Equatable {
    /// The vault has no manifest (and this device never saw one for it).
    case none
    case ok
    /// The server sent an older manifest than this device saw (or none after one was seen).
    case rollback
    /// The items the server sent aren't the ones the manifest records.
    case mismatch
    /// The copy holds rows it can't check yet (trashed rows cached before manifests, without
    /// their data's hash): the next sync fetches everything once.
    case incomplete
    /// The core's answer for a manifest more than one step ahead of the remembered one: the
    /// vault's manifest log is fetched and the check made again with it. Never shown or stored.
    case needLog = "need_log"
    /// Not checked against an answer of the server yet: the copy on the device (or this device's
    /// memory) couldn't settle it. No warning; a write syncs first.
    case unchecked

    /// The vault warning is shown and nothing is written into the vault from this device.
    public var unresolved: Bool { self == .rollback || self == .mismatch }
    /// The vault warning is shown.
    public var warns: Bool { unresolved }
    /// The next sync with the server decides; until then writes into the vault wait.
    public var pending: Bool { self == .incomplete || self == .unchecked || self == .needLog }
}

/// What this device remembers of a vault's manifest: the version and link of the last one it
/// checked `ok` or wrote itself.
public struct ManifestMark: Codable, Equatable, Sendable {
    public var version: UInt64
    public var link: String

    public init(version: UInt64, link: String) {
        self.version = version
        self.link = link
    }

    /// A version of 1 or more and a link of 43 base64url characters; anything else (a bare
    /// number from the first format too) is "nothing remembered".
    public var valid: Bool { version >= 1 && version <= VaultManifest.maxNumber && VaultManifest.isLink(link) }

    /// The entry of a stored memory, or nil when it isn't one.
    static func read(_ j: JSON) -> ManifestMark? {
        guard case .object(let o) = j, case .int(let v)? = o["version"], v >= 1, case .string(let link)? = o["link"] else { return nil }
        let m = ManifestMark(version: UInt64(v), link: link)
        return m.valid ? m : nil
    }
}

/// The wording, the same in every PassAuth app.
public enum ManifestText {
    public static let warning = "Your server's copy of this vault doesn't match its record of changes. Items may be missing, restored or out of date."
    public static let action = "Use the server's copy"
    public static let confirmTitle = "Use the server's copy?"
    public static let confirmBody = "PassAuth will accept this vault as the server has it now, including anything that is missing, restored or out of date. Do this only if you know why it changed, for example after the server was restored from a backup."
    public static let reader = "Someone who can edit this vault can review it."
    /// A write refused on this device while the vault's warning stands.
    public static let held = "This vault can't be changed until its warning is resolved."
    /// The vault isn't checked against the server's answer yet and the sync for it didn't settle it.
    public static let unchecked = "PassAuth couldn't check this vault with your server yet. Try again in a moment."
    /// The read-only view of someone else's vault (emergency access) when it has no manifest.
    public static let viewUnchecked = "This vault has no record of changes yet, so PassAuth couldn't check that nothing is missing or out of date."
    /// Three attempts each met another device's write.
    public static let busy = "This vault changed on another device. Try again."
    public static let notReady = "This can't be done until every member's apps are up to date."
}

/// A vault's next manifest, as a write carries it.
public struct ManifestEntry: Equatable, Sendable {
    public var vaultId: String
    public var seq: UInt64
    /// The link of the manifest it replaces (the builder names it; 32 zero bytes for a first one).
    public var prev: String
    public var sealed: String
    /// Its own link: what this device remembers once the server stored it.
    public var link: String

    public init(vaultId: String, seq: UInt64, prev: String, sealed: String, link: String) {
        self.vaultId = vaultId
        self.seq = seq
        self.prev = prev
        self.sealed = sealed
        self.link = link
    }

    /// What the core's builders (`manifestNext`, `manifestStart`) made, for vault `vaultId`.
    public init(vaultId: String, _ w: ManifestWrite) {
        self.init(vaultId: vaultId, seq: w.seq, prev: w.prev, sealed: w.sealed, link: w.link)
    }

    /// What to remember once the server stored it.
    public var mark: ManifestMark { ManifestMark(version: seq, link: link) }

    /// The entry of a body's `manifests` list.
    public var json: JSON {
        ["vault_id": .string(vaultId), "seq": .int(Int64(clamping: seq)), "prev": .string(prev), "sealed": .string(sealed)]
    }

    /// For the requests without a body: `manifest_seq=<n>&manifest_prev=<prev>&manifest=<sealed>`
    /// (both texts are base64url; anything else is escaped so it can't add parameters).
    public var query: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_")
        func esc(_ t: String) -> String { t.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
        return "manifest_seq=\(seq)&manifest_prev=\(esc(prev))&manifest=\(esc(sealed))"
    }
}

public enum VaultManifest {
    /// How often a write is sent when the vault changed on another device meanwhile.
    public static let attempts = 3

    /// base64url SHA-256 of an item's `data` text, as the server sends it for rows without data.
    public static func dataHash(_ data: String) -> String { manifestDataHash(data: data) }

    /// An item row as the core takes it: the id, where it is (`deleted_at`) and its data, or the
    /// data's hash for a row held without it.
    public static func row(_ r: SyncItem) -> JSON {
        var o: [String: JSON] = ["id": .string(r.id), "deleted_at": r.deletedAt.map(JSON.int) ?? .null]
        if let served = r.servedSha256 {
            // A newer row this device kept: the manifest records what the server sent for it.
            o["data_sha256"] = .string(served)
        } else if let data = r.data {
            o["data"] = .string(data)
        } else if let hash = r.dataSha256 {
            o["data_sha256"] = .string(hash)
        }
        return .object(o)
    }

    public static func rowsJson(_ rows: [SyncItem]) -> String { JSON.array(rows.map(row)).text }

    /// Every row can be checked (it has its data or the data's hash).
    public static func complete(_ rows: [SyncItem]) -> Bool { rows.allSatisfy { $0.data != nil || $0.dataSha256 != nil || $0.servedSha256 != nil } }

    /// The largest whole number a server answer may carry where the apps count (2^53 − 1).
    public static let maxNumber: UInt64 = (1 << 53) - 1

    /// How many requests the manifest log of one vault may take (2000 entries each).
    public static let logRequests = 5

    /// A link as it travels: 43 base64url characters (32 bytes).
    public static func isLink(_ t: String) -> Bool {
        t.utf8.count == 43 && t.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f }
    }

    /// The link of the manifest a vault row carries (`manifestLink`); nil when the row has none
    /// or lacks one of its three fields. Opens nothing.
    public static func link(of v: SyncVault) -> String? {
        guard v.manifestVersion > 0, let prev = v.manifestPrev, let sealed = v.manifest else { return nil }
        return try? manifestLink(manifestSeq: UInt64(v.manifestVersion), prev: prev, sealed: sealed)
    }

    /// A vault row and its items (all of them, live and trashed, as the copy holds them after a
    /// sync answer was applied) against the row's manifest. `remembered`: the last manifest this
    /// device checked or wrote for the vault (version and link, both or nothing). `log`: the
    /// vault's manifest log (the entries as the server sent them) after a `needLog`. `mark`: what
    /// to remember from now on (only for `ok`). Anything the core can't read (malformed rows, an
    /// id twice, a `deleted_at` that is no time) is a mismatch.
    ///
    /// A vault without a manifest that this device never saw one for isn't sent to the core; it
    /// doesn't depend on the server listing the feature, so a server that stops listing it (or
    /// drops a manifest) is noticed as a rollback.
    public static func verify(_ v: SyncVault, key: VaultKey, remembered: ManifestMark?, log: String? = nil,
                              rows: [SyncItem]) -> (status: ManifestStatus, mark: ManifestMark?) {
        let seq = UInt64(v.manifestVersion)
        let remembered = remembered.flatMap { $0.valid ? $0 : nil }
        if seq == 0 && remembered == nil { return (.none, nil) }
        do {
            let c = try key.manifestVerify(vaultId: v.id, keyEpoch: UInt64(max(0, v.keyEpoch ?? 0)), manifestSeq: seq, prev: v.manifestPrev,
                                           sealed: v.manifest, rememberedVersion: remembered?.version, rememberedLink: remembered?.link,
                                           logJson: log, itemsJson: rowsJson(rows))
            guard let status = ManifestStatus(rawValue: c.status), status != .unchecked else { return (.mismatch, nil) }
            // A log was given: the core never asks for one again; if it did, the log doesn't connect.
            if status == .needLog && log != nil { return (.mismatch, nil) }
            guard status == .ok else { return (status, nil) }
            guard let link = c.link else { return (.mismatch, nil) }
            let mark = ManifestMark(version: c.version, link: link)
            return mark.valid ? (.ok, mark) : (.mismatch, nil)
        } catch {
            return (.mismatch, nil)
        }
    }

    /// The device memory after a check: raised for `ok`, never lowered, never another link at
    /// the same version, untouched otherwise.
    public static func remember(_ memory: inout [String: ManifestMark], vault: String, status: ManifestStatus, mark: ManifestMark?) {
        guard status == .ok, let mark, mark.valid, mark.version > (memory[vault]?.version ?? 0) else { return }
        memory[vault] = mark
    }

    /// Two device memories as one: per vault the entry with the higher version; at the same
    /// version the one already stored (`stored`) stays (the app and its AutoFill extension both
    /// write it; a link is never replaced at its version).
    public static func merged(_ stored: [String: ManifestMark], _ other: [String: ManifestMark]) -> [String: ManifestMark] {
        stored.merging(other.filter { $0.value.valid }) { a, b in b.version > a.version ? b : a }
    }

    /// A stored memory as read: `{vault: {version, link}}`; entries in any other shape (the first
    /// format's bare numbers, half an entry, a link that isn't one) are nothing remembered. nil
    /// when the text isn't a JSON object at all.
    public static func readMemory(_ data: Data) -> [String: ManifestMark]? {
        guard case .object(let o)? = try? JSON.parse(data) else { return nil }
        return o.compactMapValues(ManifestMark.read)
    }

    /// The entries of one answer of `GET /vaults/{id}/manifest-log` and whether more follow; nil
    /// when it isn't such an answer.
    public static func logPage(_ j: JSON) -> (entries: [JSON], more: Bool, last: Int64?)? {
        guard case .array(let entries)? = j["entries"] else { return nil }
        let more = j["more"] == .bool(true)
        return (entries, more, entries.last.flatMap { $0["seq"]?.number })
    }

    /// Whether this app starts the vault's first manifest after a sync: the server keeps
    /// manifests and says every member's apps know them, the vault has none and this device
    /// never saw one, the account may write, every row can be put in, and none of them is a
    /// newer copy this device kept after the server sent an older version (`rolledBack`: the
    /// vault has items the server sent older versions of).
    public static func mayStart(_ v: SyncVault, role: Role, status: ManifestStatus, remembered: ManifestMark?, rows: [SyncItem], features: [String],
                                rolledBack: Bool = false) -> Bool {
        features.contains(vaultManifestFeature) && v.manifestVersion == 0 && v.manifestOk == true && v.seq != nil && v.keyEpoch != nil
            && role != .read && status == .none && remembered == nil && complete(rows)
            && !rolledBack && !rows.contains { $0.servedSha256 != nil }
    }

    /// The version of a new baseline ("Use the server's copy"): above the row's and above what
    /// this device remembers, so neither still counts as newer.
    public static func baselineSeq(row: Int64, remembered: UInt64?) -> UInt64 {
        let top = max(UInt64(max(0, row)), remembered ?? 0)
        return top >= maxNumber ? maxNumber : top + 1
    }

    /// How far the server's clock and this device's may differ for old trash to be deleted.
    public static let clockTolerance: Int64 = 86400
    /// The most rows one old-trash request deletes.
    public static let purgeChunk = 250

    /// The trashed rows this device deletes for good now. All of these must hold: the server's
    /// retention has run out for the row (`deleted_at` before `serverTime - trashDays` days, by
    /// the server's clock; none when it keeps the trash forever or didn't say); this device has
    /// itself seen the row in the trash for that long by its own clock (`firstSeen`: when it
    /// first did); and the two clocks agree within a day. So a server can't have the trash
    /// emptied by naming a far-off time, a short retention or early `deleted_at`s: nothing goes
    /// before this device watched it wait.
    public static func dueTrash(_ rows: [SyncItem], serverTime: Int64?, trashDays: Int64?, firstSeen: [String: Int64], now: Int64) -> [SyncItem] {
        guard let serverTime, let trashDays, trashDays >= 1, serverTime > 0, now > 0 else { return [] }
        let (span, overflow) = trashDays.multipliedReportingOverflow(by: 86400)
        guard !overflow, span > 0 else { return [] }
        let (gap, gapOverflow) = serverTime.subtractingReportingOverflow(now)
        guard !gapOverflow, gap >= -clockTolerance, gap <= clockTolerance else { return [] }
        let cutoff = serverTime - span
        let (seenBefore, seenOverflow) = now.subtractingReportingOverflow(span)
        guard !seenOverflow else { return [] }
        return rows.filter { r in
            guard let at = r.deletedAt, at > 0, at < cutoff, let seen = firstSeen[r.id], seen > 0 else { return false }
            return seen <= seenBefore
        }
    }

    /// The first-seen-in-the-trash memory after a copy was stored: every trashed row keeps the
    /// time this device first saw it there (`now` for one it sees for the first time); rows that
    /// are live again or gone are forgotten.
    public static func trashSeen(_ memory: [String: Int64], rows: [SyncItem], now: Int64) -> [String: Int64] {
        var out: [String: Int64] = [:]
        for r in rows where r.deletedAt != nil {
            out[r.id] = memory[r.id].flatMap { $0 > 0 && $0 <= now ? $0 : nil } ?? now
        }
        return out
    }

    /// 409 `manifest_conflict` (another write got there first) or 400 `manifest_required` (the
    /// vault got its manifest since this device's copy): sync, check, compute again, resend.
    /// Decided by the code, never the status.
    public static func retry(_ e: ApiError) -> Bool {
        e.code == "manifest_conflict" || e.code == "manifest_required"
    }

    /// The manifest a key replacement carries: version `row`'s + 1, made with the new key for the
    /// next epoch over every re-encrypted item where it was, naming the row's manifest (sealed
    /// under the old key: only its link is taken, nothing old is opened). nil: the vault has no
    /// manifest. Throws when the row's manifest can't be named.
    public static func rotation(_ row: SyncVault, newKey: VaultKey, nextEpoch: UInt64?, rows: [SyncItem], items: [JSON]) throws -> ManifestEntry? {
        guard row.manifestVersion > 0 else { return nil }
        guard let nextEpoch, let prev = link(of: row), UInt64(row.manifestVersion) < maxNumber else { throw UserError(ManifestText.held) }
        let w = try newKey.manifestStart(vaultId: row.id, keyEpoch: nextEpoch, version: UInt64(row.manifestVersion) + 1, prev: prev,
                                         itemsJson: rotationRows(rows, items))
        return ManifestEntry(vaultId: row.id, w)
    }

    /// The rows of a key replacement's manifest: every re-encrypted item where it was (live or
    /// in the trash) with its new data.
    public static func rotationRows(_ rows: [SyncItem], _ items: [JSON]) -> String {
        JSON.array(zip(rows, items).map { r, item in
            ["id": .string(r.id), "deleted_at": r.deletedAt.map(JSON.int) ?? .null, "data": .string(item.str("data"))]
        }).text
    }
}

/// Part S: this app only uses servers with signed sharing (every server from 0.12.0 lists the
/// feature `signed_sharing`), so a server can't switch its checks off on a new device by not
/// listing it.
public enum ServerSupport {
    public static let updateServer = "Update your PassAuth server to keep using this app."

    /// The server's settings were never read on this device and can't be read now: nothing is
    /// asked of it (a server could otherwise dodge the check by breaking `/api/config`).
    public static let unreachable = "PassAuth couldn't reach your server. Check the connection and try again."

    /// `features`: the server's `/api/config` `features` as fetched and kept (nil: never fetched,
    /// which isn't a refusal by itself: `VaultRepository.requireSupportedServer` then asks, and
    /// without an answer nothing is used). A server with API 2 or later that doesn't list
    /// `signed_sharing`, and one from before API 2 (no `api`, no features), is refused.
    public static func refused(features: [String]?) -> Bool {
        guard let features else { return false }
        return !features.contains(signedSharingFeature)
    }
}
