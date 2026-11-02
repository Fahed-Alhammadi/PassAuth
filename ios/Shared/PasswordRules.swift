import Foundation
import PassAuthCore

/// A website's password rules in the `passwordrules` language that Safari reads from an
/// `<input passwordrules="…">` attribute and iOS hands to credential providers
/// (`ASGeneratePasswordsRequest`): `required: upper; required: digit; allowed: [-_.];
/// max-consecutive: 2; minlength: 8; maxlength: 16;`. Unknown properties and classes are
/// ignored, as the language asks.
public struct PasswordRules: Equatable, Sendable {
    /// Each `required` line: the password needs at least one character from that set.
    public var required: [Set<Character>] = []
    /// Every character the password may use (allowed + required); nil = any (`unicode`).
    public var allowed: Set<Character>?
    public var minLength: Int?
    public var maxLength: Int?
    public var maxConsecutive: Int?

    public static let upper = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    public static let lower = Set("abcdefghijklmnopqrstuvwxyz")
    public static let digit = Set("0123456789")
    /// The language's `special` class: ``-~!@#$%^&*_+=`|(){}[:;"'<>,.?]`` and space.
    public static let special = Set("-~!@#$%^&*_+=`|(){}[:;\"'<>,.?] ")
    /// U+0020 to U+007E.
    public static let asciiPrintable = Set((0x20...0x7E).map { Character(UnicodeScalar(UInt8($0))) })

    public init() {}

    /// Parse the rules; nil when the text is empty or holds no rule PassAuth understands.
    public static func parse(_ text: String?) -> PasswordRules? {
        guard let text, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        var r = PasswordRules()
        var allowed = Set<Character>()
        var any = false
        var unicode = false
        var sawClasses = false
        for rule in splitRules(text) {
            guard let colon = rule.firstIndex(of: ":") else { continue }
            let name = rule[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(rule[rule.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            switch name {
            case "required", "allowed":
                let (set, isUnicode) = classes(value)
                guard isUnicode || !set.isEmpty else { continue }
                sawClasses = true
                any = true
                if isUnicode { unicode = true }
                allowed.formUnion(set)
                if name == "required" && !isUnicode { r.required.append(set) }
            case "minlength":
                if let n = Int(value), n >= 0 { r.minLength = max(r.minLength ?? 0, n); any = true }
            case "maxlength":
                if let n = Int(value), n > 0 { r.maxLength = min(r.maxLength ?? Int.max, n); any = true }
            case "max-consecutive":
                if let n = Int(value), n > 0 { r.maxConsecutive = min(r.maxConsecutive ?? Int.max, n); any = true }
            default:
                continue
            }
        }
        guard any else { return nil }
        // Without any character class the language allows all printable ASCII.
        r.allowed = unicode ? nil : sawClasses ? allowed : asciiPrintable
        return r
    }

    /// Rules end at `;`, except inside a custom class `[…]`.
    private static func splitRules(_ text: String) -> [String] {
        var out: [String] = []
        var cur = ""
        var inClass = false
        var classStart = false
        for ch in text {
            if inClass {
                cur.append(ch)
                if ch == "]" && !classStart { inClass = false }
                classStart = false
                continue
            }
            if ch == "[" { inClass = true; classStart = true; cur.append(ch); continue }
            if ch == ";" { out.append(cur); cur = ""; continue }
            cur.append(ch)
        }
        if !cur.trimmingCharacters(in: .whitespaces).isEmpty { out.append(cur) }
        return out
    }

    /// The characters of a comma-separated class list (named classes and `[…]`).
    private static func classes(_ value: String) -> (Set<Character>, unicode: Bool) {
        var set = Set<Character>()
        var unicode = false
        var i = value.startIndex
        while i < value.endIndex {
            let ch = value[i]
            if ch == "[" {
                // Custom class: up to the next "]" (a "]" right after "[" belongs to the class).
                var j = value.index(after: i)
                var first = true
                while j < value.endIndex {
                    let c = value[j]
                    if c == "]" && !first { break }
                    if c.isASCII && !c.isWhitespace || c == " " { set.insert(c) }
                    first = false
                    j = value.index(after: j)
                }
                i = j < value.endIndex ? value.index(after: j) : j
                continue
            }
            if ch.isLetter {
                var j = i
                while j < value.endIndex, value[j].isLetter || value[j] == "-" { j = value.index(after: j) }
                switch value[i..<j].lowercased() {
                case "upper": set.formUnion(upper)
                case "lower": set.formUnion(lower)
                case "digit": set.formUnion(digit)
                case "special": set.formUnion(special)
                case "ascii-printable": set.formUnion(asciiPrintable)
                case "unicode": unicode = true
                default: break
                }
                i = j
                continue
            }
            i = value.index(after: i)
        }
        return (set, unicode)
    }

    /// Does the password follow the rules?
    public func accepts(_ password: String) -> Bool {
        let chars = Array(password)
        if let minLength, chars.count < minLength { return false }
        if let maxLength, chars.count > maxLength { return false }
        if let allowed, !chars.allSatisfy(allowed.contains) { return false }
        for set in required where !chars.contains(where: set.contains) { return false }
        if let maxConsecutive {
            var run = 0
            var prev: Character?
            for c in chars {
                run = c == prev ? run + 1 : 1
                prev = c
                if run > maxConsecutive { return false }
            }
        }
        return true
    }
}

/// Password generation for AutoFill (`ASGeneratePasswordsRequest`): the core's generator with
/// the user's generator settings, adapted to the website's password rules when it gives any.
public enum PasswordGeneration {
    public enum Kind: Sendable, Equatable { case strong, alphanumeric, passphrase }

    public struct Candidate: Sendable, Equatable {
        public var kind: Kind
        public var value: String
    }

    /// The core's character sets (crates/core/src/generator.rs).
    static let coreSymbols = Set("!@#$%^&*-_=+?")
    static let ambiguous = Set("Il1O0o")

    /// How to generate for a request: core password options, plus (when the site allows only
    /// some special characters) the set its symbols are drawn from instead.
    public struct Plan: Equatable, Sendable {
        public var options: GeneratorSettings
        /// Special characters to use instead of the core's; nil = the core's own set.
        public var symbolSet: [Character]?
        public var rules: PasswordRules?
        /// The site's rules were given and can be met (false: the user's settings are used).
        public var followsRules: Bool
    }

    /// The rules from the request: the password field's, Safari's known rules for the site
    /// (quirks), then the confirmation field's.
    public static func rules(field: String?, quirks: String?, confirm: String?) -> PasswordRules? {
        PasswordRules.parse(field) ?? PasswordRules.parse(quirks) ?? PasswordRules.parse(confirm)
    }

    /// Map the site's rules onto the core generator's options (length, lower/upper/digits/
    /// symbols on or off), keeping the user's choices where the rules allow. Rules the core
    /// can't express (a required set that no whole character class covers, e.g. `required:
    /// [abc]`; a maximum length under the core's 8; no usable character at all) make the plan
    /// fall back to the user's own generator settings with `followsRules == false`: the
    /// password then may not meet the site's rules, and the generation UI says so.
    public static func plan(rules: PasswordRules?, user: GeneratorSettings) -> Plan {
        var fallback = user
        fallback.passphrase = false
        guard let rules else { return Plan(options: fallback, symbolSet: nil, rules: nil, followsRules: true) }
        let unsatisfiable = Plan(options: fallback, symbolSet: nil, rules: rules, followsRules: false)
        let allowed = rules.allowed
        func allows(_ s: Set<Character>) -> Bool { allowed.map { s.isSubset(of: $0) } ?? true }
        let amb: Set<Character> = user.avoidAmbiguous ? ambiguous : []
        let lowerSet = PasswordRules.lower.subtracting(amb)
        let upperSet = PasswordRules.upper.subtracting(amb)
        let digitSet = PasswordRules.digit.subtracting(amb)
        // Special characters the site accepts (printable ASCII; never a space: hard to see and type).
        let punctuation = PasswordRules.asciiPrintable.subtracting(PasswordRules.upper).subtracting(PasswordRules.lower)
            .subtracting(PasswordRules.digit).subtracting([" "])
        let specials = (allowed ?? punctuation).intersection(punctuation)

        var o = user
        o.passphrase = false
        o.lowercase = user.lowercase && allows(lowerSet)
        o.uppercase = user.uppercase && allows(upperSet)
        o.digits = user.digits && allows(digitSet)
        o.symbols = user.symbols && !specials.isEmpty
        var symbolSet = specials.isSuperset(of: coreSymbols) ? coreSymbols : specials

        // Every required set must contain a whole class that is on (the core puts one
        // character of each class that is on into the password).
        for req in rules.required {
            func covered() -> Bool {
                (o.lowercase && lowerSet.isSubset(of: req)) || (o.uppercase && upperSet.isSubset(of: req))
                    || (o.digits && digitSet.isSubset(of: req)) || (o.symbols && !symbolSet.isEmpty && symbolSet.isSubset(of: req))
            }
            if covered() { continue }
            if allows(lowerSet) && lowerSet.isSubset(of: req) { o.lowercase = true; continue }
            if allows(upperSet) && upperSet.isSubset(of: req) { o.uppercase = true; continue }
            if allows(digitSet) && digitSet.isSubset(of: req) { o.digits = true; continue }
            let s = symbolSet.intersection(req)
            if !s.isEmpty {
                o.symbols = true
                symbolSet = s
                continue
            }
            return unsatisfiable
        }
        if !(o.lowercase || o.uppercase || o.digits || o.symbols) {
            if allows(lowerSet) { o.lowercase = true }
            else if allows(upperSet) { o.uppercase = true }
            else if allows(digitSet) { o.digits = true }
            else if !specials.isEmpty { o.symbols = true }
            else { return unsatisfiable }
        }
        let classes = [o.lowercase, o.uppercase, o.digits, o.symbols].filter { $0 }.count
        let lo = max(rules.minLength ?? 0, 8, classes)
        let hi = min(rules.maxLength ?? 128, 128)
        guard lo <= hi else { return unsatisfiable }
        o.length = min(max(user.length, lo), hi)
        let set: [Character]? = o.symbols && symbolSet != coreSymbols ? symbolSet.sorted() : nil
        return Plan(options: o, symbolSet: set, rules: rules, followsRules: true)
    }

    /// Core options as JSON (same keys as the Generator tab).
    public static func passwordJSON(_ g: GeneratorSettings) -> String {
        let j: JSON = ["length": .int(Int64(g.length)), "uppercase": .bool(g.uppercase), "lowercase": .bool(g.lowercase),
                       "digits": .bool(g.digits), "symbols": .bool(g.symbols), "avoid_ambiguous": .bool(g.avoidAmbiguous)]
        return j.text
    }

    public static func passphraseJSON(_ g: GeneratorSettings) -> String {
        let j: JSON = ["words": .int(Int64(g.words)), "separator": .string(g.separator), "capitalize": .bool(g.capitalize), "include_number": .bool(g.includeNumber)]
        return j.text
    }

    /// One password for the plan. The core picks the symbols; when the site allows only some
    /// special characters, each symbol is replaced by one of those (uniformly, system CSPRNG).
    /// Retried until the site's rules accept it (e.g. `max-consecutive`), nil if they never do.
    public static func password(_ plan: Plan) -> String? {
        for _ in 0..<50 {
            guard var pw = try? generatePassword(optionsJson: passwordJSON(plan.options)) else { return nil }
            if let set = plan.symbolSet, !set.isEmpty {
                var rng = SystemRandomNumberGenerator()
                pw = String(pw.map { coreSymbols.contains($0) ? set.randomElement(using: &rng)! : $0 })
            }
            if !plan.followsRules || plan.rules?.accepts(pw) ?? true { return pw }
        }
        return nil
    }

    /// A passphrase with the user's settings, if the site's rules accept one.
    public static func passphrase(_ user: GeneratorSettings, rules: PasswordRules?) -> String? {
        for _ in 0..<(rules == nil ? 1 : 10) {
            guard let p = try? generatePassphrase(optionsJson: passphraseJSON(user)) else { return nil }
            if rules?.accepts(p) ?? true { return p }
        }
        return nil
    }

    /// The passwords offered for a request, the user's preferred type first: a strong
    /// password, one without special characters (when the strong one has them), and a
    /// passphrase (when the site's rules accept it). With rules that can't be met, the user's
    /// settings are used (see `plan`).
    public static func candidates(rules: PasswordRules?, user: GeneratorSettings) -> (list: [Candidate], plan: Plan) {
        let p = plan(rules: rules, user: user)
        var out: [Candidate] = []
        if let pw = password(p) {
            out.append(Candidate(kind: .strong, value: pw))
        } else if p.followsRules, let pw = password(plan(rules: nil, user: user)) {
            // The rules looked possible but no try passed them (very unlikely): the user's settings.
            out.append(Candidate(kind: .strong, value: pw))
        }
        if p.options.symbols {
            var alnum = p
            alnum.options.symbols = false
            alnum.symbolSet = nil
            let needsSymbols = p.rules?.required.contains { req in
                !(req.isSuperset(of: PasswordRules.lower) || req.isSuperset(of: PasswordRules.upper) || req.isSuperset(of: PasswordRules.digit))
            } ?? false
            if !needsSymbols, alnum.options.lowercase || alnum.options.uppercase || alnum.options.digits, let pw = password(alnum) {
                out.append(Candidate(kind: .alphanumeric, value: pw))
            }
        }
        if let phrase = passphrase(user, rules: p.followsRules ? rules : nil) {
            let c = Candidate(kind: .passphrase, value: phrase)
            if user.passphrase { out.insert(c, at: 0) } else { out.append(c) }
        }
        return (out, p)
    }
}
