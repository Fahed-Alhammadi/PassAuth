import Foundation
import PassAuthCore

// Item rollback detection (docs/ARCHITECTURE.md "Item edit counter"). Every item carries an
// encrypted, authenticated edit counter `rev` that the core raises on each encryption. This
// device remembers, per account and next to the offline copy (`SecureStore.readItemRevs`), the
// highest `rev` it saw per item id. A server that serves an older ciphertext of an item (a
// lower `rev`) is noticed: the newer copy this device still has is kept and shown, the item is
// marked, and the app says so. Equal `rev` with other content is an edit by an app from before
// the counter, accepted.

/// What a sync's rollback check found (nil on `VaultData` when nothing).
public struct ItemRollback: Equatable, Sendable {
    /// Items the server sent older versions of.
    public var items: Set<String> = []
    /// Of those, the ones whose newer copy this device kept and shows.
    public var kept: Set<String> = []

    public init(items: Set<String> = [], kept: Set<String> = []) {
        self.items = items
        self.kept = kept
    }

    /// Shown on the item.
    public static let itemWarning = "Your server sent an older version of this item."

    /// The sync-level notice.
    public var notice: String {
        !items.isEmpty && kept == items
            ? "Your server sent older versions of some items. PassAuth kept the newer copies it had."
            : "Your server sent older versions of some items."
    }
}

/// The pure part of the check (unit-tested), the core's `itemRevCheck` applied to a memory.
public enum ItemRevCheck {
    public enum Verdict: String, Sendable { case new, same, newer, rollback }

    /// `itemRevCheck(remembered, served)`; an unknown answer counts as `same` (nothing learnt,
    /// nothing flagged).
    public static func verdict(remembered: UInt64?, served: UInt64) -> Verdict {
        Verdict(rawValue: (try? itemRevCheck(remembered: remembered, served: served)) ?? "same") ?? .same
    }

    /// Learn `served` for `id` (`new` / `newer`); returns the verdict. Never lowers a value.
    public static func observe(_ memory: inout [String: UInt64], id: String, served: UInt64) -> Verdict {
        let v = verdict(remembered: memory[id], served: served)
        if v == .new || v == .newer { memory[id] = served }
        return v
    }

    /// The memory after a copy was checked. Every row seen takes its counter (`observed`: the
    /// memory's counters after `observe` ran over the copy), its vault and the time. An item the
    /// copy no longer has is forgotten only when its absence is authenticated: it was in a vault
    /// of `absentOk` (the vaults whose manifest matched this copy, or that this device just
    /// deleted it from itself). Anything else stays, so a server can't hide an item (or its
    /// vault) for one sync and then serve an old version as new. `dropped`: the ids forgotten.
    public static func settle(_ memory: ItemRevMemory, observed: [String: UInt64], rows: [(id: String, vault: String)], absentOk: Set<String>,
                              now: Int64) -> (memory: ItemRevMemory, dropped: Set<String>) {
        var out = memory
        var present = Set<String>()
        for r in rows {
            present.insert(r.id)
            guard let rev = observed[r.id] else { continue }
            out.items[r.id] = ItemRevMemory.Entry(rev: max(rev, memory.items[r.id]?.rev ?? 0), vault: r.vault, seen: now)
        }
        var dropped = Set<String>()
        for (id, e) in memory.items where !present.contains(id) && !e.vault.isEmpty && absentOk.contains(e.vault) {
            out.items[id] = nil
            dropped.insert(id)
        }
        return (out.capped(), dropped)
    }
}

/// The item edit counters this device remembers for an account, with what forgetting needs: the
/// vault each item was last seen in and when.
public struct ItemRevMemory: Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var rev: UInt64
        /// The vault the item was in when last seen ("" in a memory from before this was kept).
        public var vault: String
        /// When it was last seen in a copy (unix seconds; 0: before this was kept).
        public var seen: Int64

        public init(rev: UInt64, vault: String = "", seen: Int64 = 0) {
            self.rev = rev
            self.vault = vault
            self.seen = seen
        }
    }

    /// The most items remembered: beyond it the ones seen longest ago go first.
    public static let limit = 20_000

    public var items: [String: Entry]

    public init(items: [String: Entry] = [:]) { self.items = items }

    /// The highest counter per item id.
    public var revs: [String: UInt64] { items.mapValues(\.rev) }

    private struct File: Codable {
        var v: Int
        var items: [String: Entry]
    }

    /// A stored memory: this format, or the earlier one (`{id: rev}`, whose counters are kept).
    /// Anything else is empty.
    public static func read(_ data: Data) -> ItemRevMemory {
        if let f = try? JSONDecoder().decode(File.self, from: data), f.v == 2 { return ItemRevMemory(items: f.items) }
        if let old = try? JSONDecoder().decode([String: UInt64].self, from: data) { return ItemRevMemory(items: old.mapValues { Entry(rev: $0) }) }
        return ItemRevMemory()
    }

    public func encoded() -> Data? { try? JSONEncoder().encode(File(v: 2, items: items)) }

    /// At most `limit` items: the most recently seen.
    public func capped(_ limit: Int = ItemRevMemory.limit) -> ItemRevMemory {
        guard items.count > limit else { return self }
        let keep = items.sorted { a, b in a.value.seen != b.value.seen ? a.value.seen > b.value.seen : a.key < b.key }.prefix(limit)
        return ItemRevMemory(items: Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) }))
    }

    /// What is stored with what one process learnt: every id of either, the higher counter, the
    /// vault and time of the later sighting; without `dropped`.
    public static func merged(stored: ItemRevMemory, _ mine: ItemRevMemory, dropped: Set<String> = []) -> ItemRevMemory {
        var out = stored.items
        for (id, e) in mine.items {
            guard let d = out[id] else {
                out[id] = e
                continue
            }
            let later = e.seen >= d.seen ? e : d
            out[id] = Entry(rev: max(e.rev, d.rev), vault: later.vault.isEmpty ? (e.vault.isEmpty ? d.vault : e.vault) : later.vault, seen: later.seen)
        }
        for id in dropped { out[id] = nil }
        return ItemRevMemory(items: out).capped()
    }
}
