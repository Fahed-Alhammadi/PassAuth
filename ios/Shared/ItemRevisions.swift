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

    /// Only the ids still in the copy (items deleted for good or moved out of every vault the
    /// account has are forgotten).
    public static func pruned(_ memory: [String: UInt64], keeping ids: Set<String>) -> [String: UInt64] {
        memory.filter { ids.contains($0.key) }
    }
}
