import Foundation
import SafariServices

/// The native side of the Safari extension (the same extension code as Chrome and Firefox, built by
/// `pnpm build:safari` and copied into this bundle by a build phase in project.yml). The extension's
/// `browser.runtime.sendNativeMessage` calls arrive here as `{ type: String, ... }`; the reply is a dictionary.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message = item?.userInfo?[SFExtensionMessageKey] as? [String: Any]
        let reply = NSExtensionItem()
        reply.userInfo = [SFExtensionMessageKey: Self.answer(message)]
        context.completeRequest(returningItems: [reply], completionHandler: nil)
    }

    /// The reply to one message; unknown types get `{ error: "unknown" }`.
    static func answer(_ message: [String: Any]?) -> [String: Any] {
        switch message?["type"] as? String {
        case "ping": return ["ok": true]
        case "handoff": return Handoff.reply(Handoff.read())
        default: return ["error": "unknown"]
        }
    }
}
