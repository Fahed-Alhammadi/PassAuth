import Foundation

/// The apps' one item search, the same as the extension's popup (`extension/src/popup/search.ts`): every word of the
/// query (ANDed, case-insensitive) must appear in the item's name, user name, second line (card / identity), any of
/// its websites (full address, or its host without the scheme or "www."), its tags or its folder. Results: items whose
/// name (or a word of it) or a website's host starts with the query first, then the rest in list order.
/// Pure; shared with AutoFill (`AutofillMatcher.search`). Tests: `ItemSearchTests`.
public enum ItemSearch {
    /// The query's words, in lower case.
    public static func words(_ query: String) -> [String] {
        query.lowercased().split(whereSeparator: { $0.isWhitespace || $0.isNewline }).map(String.init)
    }

    /// A website's address without its scheme and a leading "www.", in lower case.
    static func host(_ url: String) -> String {
        var s = url.trimmingCharacters(in: .whitespaces)
        if let r = s.range(of: "^[a-z][a-z0-9+.-]*://", options: [.regularExpression, .caseInsensitive]) {
            s.removeSubrange(r)
        }
        if s.lowercased().hasPrefix("www.") { s.removeFirst(4) }
        return s.lowercased()
    }

    /// The second line of a card or identity (as the extension shows it): brand and last four digits, name and email.
    public static func subtitle(_ i: Item) -> String {
        if let c = i.card {
            let digits = c.number.filter { !$0.isWhitespace }
            return [c.brand, digits.count >= 4 ? "•••• \(digits.suffix(4))" : ""].filter { !$0.isEmpty }.joined(separator: " ")
        }
        if let id = i.identity {
            let name = [id.firstName, id.lastName].filter { !$0.isEmpty }.joined(separator: " ")
            return [name, id.email].filter { !$0.isEmpty }.joined(separator: " · ")
        }
        return ""
    }

    /// The lower-case texts searched for `i`; `extra`: what the list shows for it besides (its subtitle).
    static func fields(_ i: Item, extra: [String]) -> [String] {
        var all = [i.name, i.login?.username ?? "", subtitle(i), i.folder ?? ""]
        for u in i.login?.urls ?? [] { all += [u.url, host(u.url)] }
        all += i.tags
        all += extra
        return all.filter { !$0.isEmpty }.map { $0.lowercased() }
    }

    /// Whether `i` starts with the query: its name, a word of its name, or one of its websites' hosts.
    static func startsWith(_ i: Item, whole: String, first: String) -> Bool {
        let name = i.name.lowercased()
        if name.hasPrefix(whole) { return true }
        let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "._@/-"))
        if name.components(separatedBy: separators).contains(where: { !$0.isEmpty && $0.hasPrefix(first) }) { return true }
        return (i.login?.urls ?? []).contains { !$0.url.isEmpty && host($0.url).hasPrefix(first) }
    }

    /// Whether `i` matches every word of `query` (an empty query matches everything).
    public static func matches(_ i: Item, _ query: String, extra: [String] = []) -> Bool {
        let w = words(query)
        if w.isEmpty { return true }
        let hay = fields(i, extra: extra)
        return w.allSatisfy { word in hay.contains { $0.contains(word) } }
    }

    /// `items` matching `query`, best first (see above). `item`: the vault item of each element;
    /// `extra`: other texts shown for it (searched too).
    public static func search<T>(_ items: [T], _ query: String, item: (T) -> Item, extra: (T) -> [String] = { _ in [] }) -> [T] {
        let w = words(query)
        guard let first = w.first else { return items }
        let whole = w.joined(separator: " ")
        var hits: [(element: T, rank: Int, order: Int)] = []
        for (order, element) in items.enumerated() {
            let i = item(element)
            let hay = fields(i, extra: extra(element))
            guard w.allSatisfy({ word in hay.contains { $0.contains(word) } }) else { continue }
            hits.append((element, startsWith(i, whole: whole, first: first) ? 0 : 1, order))
        }
        return hits.sorted { $0.rank != $1.rank ? $0.rank < $1.rank : $0.order < $1.order }.map(\.element)
    }

    /// Entries matching `query`, best first.
    public static func search(_ entries: [Entry], _ query: String) -> [Entry] {
        search(entries, query, item: \.item)
    }
}
