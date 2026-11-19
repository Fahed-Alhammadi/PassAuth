import Foundation
import Security

/// Two-step login with a security key or passkey, handed to the browser (the "key page"): the
/// server's own page (`/two-step/key`, origin = the relying party) runs the WebAuthn ceremony and
/// sends the assertion back to `passauth://two-step-key#v=1&credential=…`. The app made the
/// `/auth/2fa/passkey/start` call and keeps the two-step token; the page never sees it, so an
/// assertion caught on the way is no use on its own. Servers list `two_step_key_page` in
/// `/api/config` `features` (older servers: the method stays hidden).
public enum SecurityKeyHandoff {
    public static let feature = "two_step_key_page"
    /// The two-step provider name the server lists.
    public static let provider = "passkey"
    public static let callbackScheme = "passauth"
    public static let callbackHost = "two-step-key"

    public static let methodName = "Security key or passkey"
    public static let button = "Use security key"
    public static let explanation = "PassAuth opens your server's page in the browser. Touch your security key or use your passkey there."
    public static let waiting = "Waiting for your security key…"
    public static let mismatch = "This server's address for security keys doesn't match. Use another method."
    /// Under `waiting`: the page is a web page, so say what it never asks for.
    public static let warning = "PassAuth never asks for your master password or Secret Key in the browser."

    /// One hand-off: the page to open (with its fragment), the challenge the answer must carry and
    /// the random `state` the page must echo in its answer (credential or cancel).
    public struct Plan: Equatable, Sendable {
        public let url: URL
        public let challenge: Data
        public let state: String
    }

    /// 16 random bytes from the system CSPRNG, base64url (22 characters).
    public static func newState() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            // No randomness: an empty state makes `plan` refuse to open anything.
            return ""
        }
        return base64urlEncode(Data(bytes))
    }

    /// What came back from the page.
    public enum Answer: Equatable, Sendable {
        /// The assertion JSON, as the web vault sends it to `/auth/2fa/passkey/finish`.
        case credential(JSON)
        /// The user cancelled on the page.
        case cancelled
    }

    /// The page to open for a `/auth/2fa/passkey/start` answer (`{options, key_page}`) from the
    /// server at `server` (the address the app is signing in to). Throws `mismatch` unless
    /// `key_page` is an https URL whose host is both the options' `rpId` and `server`'s host (case
    /// aside; ports aren't compared); throws a generic error for options without a challenge.
    public static func plan(start: JSON, server: String, state: String = newState()) throws -> Plan {
        guard state.count >= 22, base64urlDecode(state) != nil else { throw UserError("Can't start the security key sign-in. Try again.") }
        // `{publicKey: {…}}` as webauthn-rs sends it (a bare publicKey object is read too, as the web page does).
        guard let options = start["options"], case let pk = options["publicKey"] ?? options, case .object = pk,
              let challengeText = pk["challenge"]?.string, let challenge = base64urlDecode(challengeText), !challenge.isEmpty
        else { throw UserError("Your server's answer for security keys can't be used. Use another method.") }
        guard let page = start["key_page"]?.string, let rpId = pk["rpId"]?.string, !rpId.isEmpty,
              let comps = URLComponents(string: page), comps.scheme?.lowercased() == "https",
              let host = comps.host?.lowercased(), host == rpId.lowercased(),
              let serverHost = URLComponents(string: server)?.host?.lowercased(), host == serverHost,
              comps.user == nil, comps.password == nil, comps.fragment == nil
        else { throw UserError(mismatch) }
        var u = comps
        u.percentEncodedFragment = "v=1&options=\(base64urlEncode(options.data))&return=app&state=\(state)"
        guard let url = u.url else { throw UserError(mismatch) }
        return Plan(url: url, challenge: challenge, state: state)
    }

    /// Read the callback for `plan`: nil for anything that isn't an answer to this hand-off
    /// (another address, another version, a credential for another challenge, damaged data).
    public static func answer(_ url: URL, for plan: Plan) -> Answer? {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              comps.scheme?.lowercased() == callbackScheme, comps.host?.lowercased() == callbackHost,
              let fragment = comps.percentEncodedFragment else { return nil }
        var params: [String: String] = [:]
        for pair in fragment.split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard kv.count == 2 else { return nil }
            let key = String(kv[0])
            // A repeated key is not something the page sends.
            guard params[key] == nil else { return nil }
            params[key] = String(kv[1])
        }
        // Only answers that echo this hand-off's state (credential and cancel alike).
        guard params["v"] == "1", let state = params["state"], !plan.state.isEmpty, state == plan.state else { return nil }
        if let error = params["error"] {
            return error == "cancelled" && params["credential"] == nil ? .cancelled : nil
        }
        guard let text = params["credential"], let data = base64urlDecode(text),
              let credential = try? JSON.parse(data), case .object = credential,
              let clientText = credential["response"]?["clientDataJSON"]?.string,
              let clientData = base64urlDecode(clientText), let client = try? JSON.parse(clientData),
              client["type"]?.string == "webauthn.get",
              let got = client["challenge"]?.string, let gotBytes = base64urlDecode(got),
              gotBytes == plan.challenge
        else { return nil }
        return .credential(credential)
    }

    /// Base64url without padding.
    public static func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Base64url with or without padding; nil for anything else.
    public static func base64urlDecode(_ text: String) -> Data? {
        guard !text.isEmpty, text.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == "=") }) else { return nil }
        var s = text.replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if s.count % 4 == 1 { return nil }
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return Data(base64Encoded: s)
    }
}
