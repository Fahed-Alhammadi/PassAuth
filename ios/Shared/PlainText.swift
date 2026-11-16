import Foundation

/// Text that came from elsewhere (the server, another device, another member's item), made safe
/// to show or store: the web vault's `web/src/lib/text.ts`, with the same rules.
public enum PlainText {
    /// Format characters (Unicode Cf: bidi embeddings, overrides and isolates, the marks
    /// U+200E/F, zero-width spaces and joiners, the byte order mark) and the Hangul fillers that
    /// render as blanks.
    static func isFormat(_ s: Unicode.Scalar) -> Bool {
        s.properties.generalCategory == .format || [0x115F, 0x1160, 0x3164, 0xFFA0].contains(s.value)
    }

    /// Control characters (Unicode Cc: C0, DEL, C1) and the line and paragraph separators.
    static func isControl(_ s: Unicode.Scalar) -> Bool {
        switch s.properties.generalCategory {
        case .control, .lineSeparator, .paragraphSeparator: true
        default: false
        }
    }

    /// `s` without control and format characters (for file names: nothing is put in their place).
    public static func stripInvisible(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for c in s.unicodeScalars where !isFormat(c) && !isControl(c) { out.append(c) }
        return String(out)
    }

    /// Every run of white space as one space (JavaScript's `\s+` → " ").
    static func foldSpaces(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var space = false
        for c in s.unicodeScalars {
            if c.properties.isWhitespace {
                space = true
                continue
            }
            if space { out.append(" ") }
            space = false
            out.append(c)
        }
        if space { out.append(" ") }
        return String(out)
    }

    static func trim(_ s: String) -> String {
        let scalars = Array(s.unicodeScalars)
        guard let first = scalars.firstIndex(where: { !$0.properties.isWhitespace }),
              let last = scalars.lastIndex(where: { !$0.properties.isWhitespace }) else { return "" }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars[first...last])
        return String(out)
    }

    /// `value` as one line of plain text: format characters removed, control characters and line
    /// breaks turned into spaces, runs of white space folded into one, trimmed, and at most `max`
    /// characters (code points), the last one then an ellipsis.
    public static func oneLine(_ value: String?, max: Int) -> String {
        guard let value else { return "" }
        var spaced = String.UnicodeScalarView()
        for c in value.unicodeScalars where !isFormat(c) { spaced.append(isControl(c) ? " " : c) }
        let s = trim(foldSpaces(String(spaced)))
        let chars = Array(s.unicodeScalars)
        if chars.count <= max { return s }
        var cut = String.UnicodeScalarView()
        cut.append(contentsOf: chars.prefix(Swift.max(0, max - 1)))
        // trimEnd
        var head = String(cut)
        while let l = head.unicodeScalars.last, l.properties.isWhitespace { head.unicodeScalars.removeLast() }
        return head + "…"
    }
}
