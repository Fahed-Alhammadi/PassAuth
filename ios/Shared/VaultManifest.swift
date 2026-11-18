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

    /// Writes into the vault are held back.
    public var unresolved: Bool { self == .rollback || self == .mismatch || self == .incomplete }
    /// The vault warning is shown.
    public var warns: Bool { self == .rollback || self == .mismatch }
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
    /// Three attempts each met another device's write.
    public static let busy = "This vault changed on another device. Try again."
    public static let notReady = "This can't be done until every member's apps are up to date."
}

/// A vault's next manifest, as a write carries it.
public struct ManifestEntry: Equatable, Sendable {
    public var vaultId: String
    public var seq: UInt64
    public var sealed: String

    public init(vaultId: String, seq: UInt64, sealed: String) {
        self.vaultId = vaultId
        self.seq = seq
        self.sealed = sealed
    }

    /// The entry of a body's `manifests` list.
    public var json: JSON {
        ["vault_id": .string(vaultId), "seq": .int(Int64(clamping: seq)), "sealed": .string(sealed)]
    }

    /// For the requests without a body: `manifest_seq=<n>&manifest=<sealed>` (the sealed text is
    /// base64url; anything else is escaped so it can't add parameters).
    public var query: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_")
        return "manifest_seq=\(seq)&manifest=" + (sealed.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")
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

    /// A vault row and its items (all of them, live and trashed, as the copy holds them after a
    /// sync answer was applied) against the row's manifest. `remembered`: the highest manifest
    /// version this device saw for the vault. `version`: what to remember from now on (only for
    /// `ok`). Anything the core can't read (malformed rows, an id twice) is a mismatch.
    ///
    /// A vault without a manifest that this device never saw one for isn't sent to the core; it
    /// doesn't depend on the server listing the feature, so a server that stops listing it (or
    /// drops a manifest) is noticed as a rollback.
    public static func verify(_ v: SyncVault, key: VaultKey, remembered: UInt64?, rows: [SyncItem]) -> (status: ManifestStatus, version: UInt64) {
        let seq = UInt64(v.manifestVersion)
        if seq == 0 && (remembered ?? 0) == 0 { return (.none, 0) }
        do {
            let c = try key.manifestVerify(vaultId: v.id, keyEpoch: UInt64(max(0, v.keyEpoch ?? 0)), manifestSeq: seq, sealed: v.manifest,
                                           remembered: remembered, itemsJson: rowsJson(rows))
            guard let status = ManifestStatus(rawValue: c.status) else { return (.mismatch, remembered ?? 0) }
            return (status, c.version)
        } catch {
            return (.mismatch, remembered ?? 0)
        }
    }

    /// The device memory after a check: raised for `ok`, never lowered, untouched otherwise.
    public static func remember(_ memory: inout [String: UInt64], vault: String, status: ManifestStatus, version: UInt64) {
        guard status == .ok, version > (memory[vault] ?? 0) else { return }
        memory[vault] = version
    }

    /// Two device memories as one: the higher version per vault (the app and its AutoFill
    /// extension both write it).
    public static func merged(_ a: [String: UInt64], _ b: [String: UInt64]) -> [String: UInt64] {
        a.merging(b) { max($0, $1) }
    }

    /// Whether this app starts the vault's first manifest after a sync: the server keeps
    /// manifests and says every member's apps know them, the vault has none and this device
    /// never saw one, the account may write, and every row can be put in.
    public static func mayStart(_ v: SyncVault, role: Role, status: ManifestStatus, remembered: UInt64?, rows: [SyncItem], features: [String]) -> Bool {
        features.contains(vaultManifestFeature) && v.manifestVersion == 0 && v.manifestOk == true && v.seq != nil && v.keyEpoch != nil
            && role != .read && status == .none && (remembered ?? 0) == 0 && complete(rows)
    }

    /// The version of a new baseline ("Use the server's copy"): above the row's and above what
    /// this device remembers, so neither still counts as newer.
    public static func baselineSeq(row: Int64, remembered: UInt64?) -> UInt64 {
        max(UInt64(max(0, row)), remembered ?? 0) + 1
    }

    /// The trashed rows the server's retention has run out for (`deleted_at` before
    /// `serverTime - trashDays` days, by the server's clock); none when it keeps the trash
    /// forever (`trashDays` 0) or didn't say.
    public static func dueTrash(_ rows: [SyncItem], serverTime: Int64?, trashDays: Int64?) -> [SyncItem] {
        guard let serverTime, let trashDays, trashDays > 0, serverTime > 0 else { return [] }
        let (span, overflow) = trashDays.multipliedReportingOverflow(by: 86400)
        guard !overflow else { return [] }
        let cutoff = serverTime - span
        return rows.filter { r in r.deletedAt.map { $0 < cutoff } ?? false }
    }

    /// 409 `manifest_conflict` (another write got there first) or 400 `manifest_required` (the
    /// vault got its manifest since this device's copy): sync, check, compute again, resend.
    /// Decided by the code, never the status.
    public static func retry(_ e: ApiError) -> Bool {
        e.code == "manifest_conflict" || e.code == "manifest_required"
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

    /// `features`: the server's `/api/config` `features` as fetched (nil: not fetched, which is
    /// never a refusal). A server with API 2 or later that doesn't list `signed_sharing`, and one
    /// from before API 2 (no `api`, no features), is refused.
    public static func refused(features: [String]?) -> Bool {
        guard let features else { return false }
        return !features.contains(signedSharingFeature)
    }
}
