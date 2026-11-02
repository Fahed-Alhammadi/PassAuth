import Foundation

/// An authenticator key ready for the item's `login.totp` field.
public struct OtpKey: Equatable, Sendable {
    /// What is stored: the full `otpauth://totp/…` URI, or a bare base32 secret.
    public let value: String
    public var issuer = ""
    public var account = ""

    public init(value: String, issuer: String = "", account: String = "") {
        self.value = value
        self.issuer = issuer
        self.account = account
    }

    /// "Example (alice@example.com)", for notices.
    public var label: String {
        if !issuer.isEmpty && !account.isEmpty { return "\(issuer) (\(account))" }
        return issuer.isEmpty ? account : issuer
    }
}

public enum OtpParse: Equatable, Sendable {
    case valid(OtpKey)
    case invalid(String)

    public var key: OtpKey? {
        if case .valid(let k) = self { return k }
        return nil
    }

    public var problem: String? {
        if case .invalid(let r) = self { return r }
        return nil
    }
}

/// Reads authenticator keys from scanned QR codes, the clipboard or typing: `otpauth://totp/…` URIs (kept
/// whole, as the web vault stores them) and plain base32 secrets. The checks mirror the
/// core's TOTP parser (`crates/core/src/totp.rs`), so anything accepted here produces codes.
public enum OtpAuth {
    static let prefix = "otpauth://totp/"

    public static func parse(_ input: String) -> OtpParse {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty { return .invalid("Enter or scan an authenticator key.") }
        let lower = text.lowercased()
        if lower.hasPrefix("otpauth-migration:") {
            return .invalid("This is an authenticator app's export of several accounts. Scan the QR code a website shows when you set up two-step login.")
        }
        if lower.hasPrefix("otpauth://hotp/") {
            return .invalid("This is a counter-based (HOTP) key. PassAuth supports time-based (TOTP) keys only.")
        }
        if lower.hasPrefix(prefix) {
            return parseUri(prefix + text.dropFirst(prefix.count))
        }
        if lower.contains("://") {
            return .invalid("This isn't an authenticator key. Look for a QR code or key on the website's two-step login setup page.")
        }
        let secret = cleanBase32(text)
        if decodeBase32(secret) == nil {
            return .invalid("That isn't a valid authenticator key. Keys use the letters A–Z and digits 2–7.")
        }
        return .valid(OtpKey(value: secret))
    }

    /// True when the stored value produces codes (empty counts as valid: no key).
    public static func isUsable(_ value: String?) -> Bool {
        guard let v = value, !v.trimmingCharacters(in: .whitespaces).isEmpty else { return true }
        return parse(v).key != nil
    }

    /// A valid plain key is stored cleaned up (upper case, no spaces); URIs and anything else stay as typed.
    public static func normalize(_ value: String) -> String {
        parse(value).key?.value ?? value
    }

    private static func parseUri(_ uri: String) -> OtpParse {
        let rest = String(uri.dropFirst(prefix.count))
        let path: String
        let query: String
        if let q = rest.firstIndex(of: "?") {
            path = String(rest[..<q])
            query = String(rest[rest.index(after: q)...])
        } else {
            path = rest
            query = ""
        }
        var secret: String?
        var issuerParam = ""
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let k: String
            let v: String
            if let eq = pair.firstIndex(of: "=") {
                k = pair[..<eq].lowercased()
                v = String(pair[pair.index(after: eq)...])
            } else {
                k = pair.lowercased()
                v = ""
            }
            switch k {
            case "secret": secret = v
            case "issuer": issuerParam = decode(v)
            case "algorithm":
                if !["SHA1", "SHA256", "SHA512"].contains(v.uppercased()) { return .invalid("This key uses an unsupported algorithm (\(v)).") }
            case "digits":
                guard let d = Int(v), (6...10).contains(d) else { return .invalid("This key asks for an unsupported number of digits (\(v)).") }
            case "period":
                if (Int64(v) ?? 0) <= 0 { return .invalid("This key has an invalid period (\(v)).") }
            default: break
            }
        }
        guard let s = secret else { return .invalid("This QR code has no secret key in it.") }
        if decodeBase32(cleanBase32(s)) == nil { return .invalid("The secret key in this QR code isn't valid.") }
        let label = decode(path)
        let issuer: String
        let account: String
        if let colon = label.firstIndex(of: ":") {
            issuer = issuerParam.isEmpty ? label[..<colon].trimmingCharacters(in: .whitespaces) : issuerParam
            account = label[label.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        } else {
            issuer = issuerParam
            account = label.trimmingCharacters(in: .whitespaces)
        }
        return .valid(OtpKey(value: uri, issuer: issuer, account: account))
    }

    /// Percent-decoding without turning "+" into a space.
    private static func decode(_ s: String) -> String { s.removingPercentEncoding ?? s }

    /// Spaces, hyphens and padding removed, upper case (what the core's decoder ignores).
    public static func cleanBase32(_ s: String) -> String {
        String(s.filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }).uppercased()
    }

    /// RFC 4648 base32 without padding, strict like the core's (`data_encoding::BASE32_NOPAD`); nil if invalid or empty.
    public static func decodeBase32(_ s: String) -> [UInt8]? {
        if s.isEmpty || ![0, 2, 4, 5, 7].contains(s.count % 8) { return nil }
        var out: [UInt8] = []
        var buffer: UInt64 = 0
        var bits = 0
        for c in s.unicodeScalars {
            let v: UInt64
            switch c.value {
            case 65...90: v = UInt64(c.value - 65)
            case 50...55: v = UInt64(c.value - 50 + 26)
            default: return nil
            }
            buffer = (buffer << 5) | v
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt64(bits)) & 0xff))
            }
            buffer &= (1 << 16) - 1
        }
        // Leftover bits must be zero (canonical encoding).
        if bits > 0 && (buffer & ((1 << UInt64(bits)) - 1)) != 0 { return nil }
        return out.isEmpty ? nil : out
    }
}
