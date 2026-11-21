import Foundation
import Security

/// Server, email and Secret Key the desktop app left for this extension's sign-in: the hand-off item it
/// writes for its AutoFill extension (`io.passauth.desktop.handoff` in the AutoFill extension's Keychain
/// group, `autofill_handoff` in desktop/src-tauri). JSON; never tokens or keys.
enum Handoff {
    static let service = "io.passauth.desktop.handoff"

    /// The Keychain group in Info.plist (`PAKeychainGroup`, with the team prefix).
    static var group: String? {
        let g = Bundle.main.object(forInfoDictionaryKey: "PAKeychainGroup") as? String
        return g?.hasPrefix("$(") == false ? g : nil
    }

    /// The hand-off item's JSON, if there is one.
    static func read() -> Data? {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "handoff",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let group { q[kSecAttrAccessGroup as String] = group }
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// The reply to `{type: "handoff"}`: `{server, email, secretKey?}` from `data`, or `{none: true}`
    /// (no item, a cleared one (`{}`), or anything that isn't one).
    static func reply(_ data: Data?) -> [String: Any] {
        guard let data,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let server = obj["server"] as? String, server.hasPrefix("http"),
              let email = obj["email"] as? String, !email.isEmpty
        else { return ["none": true] }
        var out: [String: Any] = ["server": server, "email": email]
        if let sk = obj["secretKey"] as? String, !sk.isEmpty { out["secretKey"] = sk }
        return out
    }
}
