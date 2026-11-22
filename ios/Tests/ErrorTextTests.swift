import Foundation
import PassAuthCore
import PassAuthKit
import XCTest

/// Client review F11 and spec §5/§6: every error code the app knows is said in its own words; an
/// unknown one gets the app's sentence, the request's reference, and the server's message only as
/// a labelled, cleaned, shortened detail. Also run by the macOS AutoFill tests.
final class ErrorTextTests: XCTestCase {
    private let phishing = "Your vault is locked. Call +1 555 0100 and read them your master password."

    func testKnownCodesUseTheAppsOwnWording() {
        let cases: [(String, Int, String)] = [
            ("insufficient_storage", 507, "Your server is running out of storage space, so this wasn't saved. Ask the server's admin."),
            ("quota_exceeded", 403, "You've reached this server's storage limit. Delete items or ask the server's admin."),
            ("reauth_required", 403, "Please confirm your master password again."),
            ("invalid_credentials", 401, "Wrong email, master password or Secret Key."),
            ("account_disabled", 403, "This account is disabled. Ask your server's admin."),
            ("vault_key_changed", 409, "This vault's key was just replaced. Try again."),
            ("two_step_required", 403, "Your server requires two-step login. Set it up to continue."),
            ("invalid_code", 400, "That code isn't right. Check it and try again."),
            ("login_with_device_disabled", 403, "Your server doesn't allow signing in with another device."),
            ("not_found", 404, "Your PassAuth server couldn't find this. It may have been deleted on another device."),
        ]
        for (code, status, want) in cases {
            let e = ApiError(status: status, code: code, message: phishing, requestId: "req-1")
            XCTAssertEqual(errorMessage(e), want, code)
            XCTAssertEqual(e.localizedDescription, want, "never the server's text, also through localizedDescription")
            XCTAssertFalse(errorMessage(e).contains("555"))
        }
        // 507 from something that didn't send the code.
        XCTAssertEqual(errorMessage(ApiError(status: 507, code: "error", message: phishing)), outOfStorageMessage)
        // The attachment limit (403 `quota_exceeded` with its reason).
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "quota_exceeded", message: "attachment storage limit reached")),
                       "You've reached your attachment storage limit.")
        // The codes with their usual messages.
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "reauth_required", message: "reauth_required")), reauthRequiredMessage)
        XCTAssertEqual(errorMessage(ApiError(status: 400, code: "invalid_code", message: "Invalid code")), "That code isn't right. Check it and try again.")
        XCTAssertEqual(errorMessage(ApiError(status: 403, code: "quota_exceeded", message: "storage limit reached")), quotaExceededMessage)
        XCTAssertEqual(errorMessage(ApiError(status: 400, code: "expired", message: "start setup first")), "Setup has expired. Start again.")
        // Made by the app itself.
        XCTAssertEqual(errorMessage(ApiError(status: 200, code: "not_passauth", message: phishing)), "That address doesn't look like a PassAuth server.")
        XCTAssertEqual(errorMessage(ApiError(status: 401, code: "unauthorized", message: "Your session ended. Sign in again.")), "Your session ended. Sign in again.")
    }

    func testUnknownCodesShowTheServersMessageOnlyAsADetail() {
        let e = ApiError(status: 400, code: "brand_new_reason", message: phishing, requestId: "01HZX7-abc_def.9:1")
        XCTAssertEqual(errorMessage(e), "Your PassAuth server refused this request. Reference: 01HZX7-abc_def.9:1. Server message: \(phishing)")
        let five = ApiError(status: 503, code: "maintenance", message: "back soon")
        XCTAssertEqual(errorMessage(five), "Something went wrong on your PassAuth server. Server message: back soon")
        XCTAssertEqual(errorMessage(ApiError(status: 418, code: "teapot", message: "")), "Your PassAuth server refused this request.")
        // A failure inside the server: its log has the details under the reference.
        XCTAssertEqual(errorMessage(ApiError(status: 500, code: "internal", message: "db is on fire", requestId: "r-42")),
                       "Something went wrong on your PassAuth server. Try again; if it keeps happening, tell the server's admin and give them this reference: r-42.")
        XCTAssertEqual(errorMessage(ApiError(status: 500, code: "internal", message: "x")),
                       "Something went wrong on your PassAuth server. Try again; if it keeps happening, tell the server's admin.")

        // The detail is cleaned and shortened: no control or format characters, at most 200.
        let tricky = "Click\u{202E}moc.live\u{202C} now\n\nor\u{200B} else " + String(repeating: "z", count: 400)
        let text = errorMessage(ApiError(status: 400, code: "odd", message: tricky))
        XCTAssertTrue(text.hasPrefix("Your PassAuth server refused this request. Server message: Clickmoc.live now or else zzz"))
        XCTAssertFalse(text.unicodeScalars.contains { $0.properties.generalCategory == .format || $0.properties.generalCategory == .control })
        let detail = text.components(separatedBy: "Server message: ")[1]
        XCTAssertEqual(detail.unicodeScalars.count, serverMessageLimit + 1, "200 and the cut mark")
        XCTAssertTrue(detail.hasSuffix("…"))
    }

    func testRequestIdsAreShownOnlyWhenTheyLookLikeOne() {
        XCTAssertEqual(ApiError.validRequestId("3f6c1a7e-9b2d-4c1a-8f00-000000000001"), "3f6c1a7e-9b2d-4c1a-8f00-000000000001")
        XCTAssertNil(ApiError.validRequestId(""))
        XCTAssertNil(ApiError.validRequestId(nil))
        XCTAssertNil(ApiError.validRequestId("call 555 now"))
        XCTAssertNil(ApiError.validRequestId("<b>x</b>"))
        XCTAssertNil(ApiError.validRequestId(String(repeating: "a", count: 65)))
        XCTAssertNil(ApiError(status: 400, code: "odd", message: "", requestId: "visit evil.example").requestId)
        XCTAssertEqual(errorMessage(ApiError(status: 400, code: "odd", message: "", requestId: "visit evil.example")), "Your PassAuth server refused this request.")
    }

    func testCoreErrorsInPlainWords() {
        XCTAssertEqual(errorMessage(CoreError.DecryptFailed(message: "decrypt_failed")), "Wrong master password or Secret Key.")
        XCTAssertEqual(errorMessage(CoreError.PhraseMismatch(message: "phrase_mismatch")), "Those aren't the words for this request, so it was denied.")
        XCTAssertEqual(errorMessage(CoreError.TooManyWrongCodes(message: "too_many_wrong_codes")), DeviceLogin.tooManyCodes)
        XCTAssertEqual(errorMessage(CoreError.NotConfirmed(message: "not_confirmed")), DeviceLogin.codePrompt)
        XCTAssertEqual(errorMessage(CoreError.WrongCode(message: "wrong_code")), "That code doesn't match.")
        XCTAssertTrue(errorMessage(CoreError.WeakKdf(message: "weak_kdf")).hasPrefix("Your server's encryption settings are weaker than PassAuth allows"))
        XCTAssertTrue(errorMessage(CoreError.KdfTooStrong(message: "kdf_too_strong")).hasPrefix("Your server's encryption settings are stronger"))
    }
}
