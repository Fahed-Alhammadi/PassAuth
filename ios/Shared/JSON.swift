import Foundation

/// A JSON value, for API bodies and responses whose shape is only partly known
/// (KDF parameters and account bundles are passed to the core as JSON text).
public enum JSON: Sendable, Equatable, Codable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSON])
    case object([String: JSON])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let i = try? c.decode(Int64.self) { self = .int(i) }
        else if let d = try? c.decode(Double.self) { self = .double(d) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSON].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSON].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let b): try c.encode(b)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    public static func parse(_ data: Data) throws -> JSON {
        try JSONDecoder().decode(JSON.self, from: data)
    }

    public static func parse(_ text: String) throws -> JSON {
        try parse(Data(text.utf8))
    }

    /// Compact JSON text (keys sorted, slashes unescaped).
    public var text: String {
        String(decoding: data, as: UTF8.self)
    }

    public var data: Data {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? e.encode(self)) ?? Data("null".utf8)
    }

    public subscript(key: String) -> JSON? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var string: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var bool: Bool {
        if case .bool(let b) = self { return b }
        return false
    }

    public var int: Int64 {
        switch self {
        case .int(let i): return i
        case .double(let d): return Int64(d)
        case .string(let s): return Int64(s) ?? 0
        default: return 0
        }
    }

    public var array: [JSON] {
        if case .array(let a) = self { return a }
        return []
    }

    /// `obj.str("key")`: the string at `key`, or "".
    public func str(_ key: String) -> String { self[key]?.string ?? "" }
}

extension JSON: ExpressibleByStringLiteral, ExpressibleByBooleanLiteral, ExpressibleByIntegerLiteral, ExpressibleByDictionaryLiteral, ExpressibleByArrayLiteral, ExpressibleByNilLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
    public init(booleanLiteral value: Bool) { self = .bool(value) }
    public init(integerLiteral value: Int64) { self = .int(value) }
    public init(dictionaryLiteral elements: (String, JSON)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, b in b }))
    }
    public init(arrayLiteral elements: JSON...) { self = .array(elements) }
    public init(nilLiteral: ()) { self = .null }
}
