import Foundation
import PassAuthCore

/// An error response from the server (`{ "error": code, "message": … }`).
public struct ApiError: Error, LocalizedError, Sendable {
    public let status: Int
    public let code: String
    public let message: String
    public var errorDescription: String? { message }
}

/// A user-facing error from the app itself (shown as is).
public struct UserError: Error, LocalizedError, Sendable, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Saving an item failed because it changed on the server since editing started (HTTP 409).
public struct ConflictError: Error, LocalizedError, Sendable {
    public let itemId: String
    public var errorDescription: String? { "This item was changed on another device." }
}

public let secretKeyRequiredMessage = "secret_key_required"

/// The message to show for any error (mirrors the Android app's `errorMessage`).
public func errorMessage(_ error: Error) -> String {
    if let e = error as? UserError {
        if e.message == secretKeyRequiredMessage { return "This account uses a Secret Key. Enter it from your Emergency Kit." }
        if e.message == "email_not_verified" { return "Confirm your email address first, then sign in." }
        return e.message
    }
    if let e = error as? ApiError {
        if e.code == "invalid_credentials" { return "Wrong email, master password or Secret Key." }
        if e.code == "rate_limited" { return "Too many attempts. Wait a moment and try again." }
        if e.code == "email_not_verified" { return "Confirm your email address first, then sign in." }
        let m = e.message.isEmpty ? "Something went wrong" : e.message
        let cap = m.prefix(1).uppercased() + m.dropFirst()
        return cap.hasSuffix(".") ? cap : cap + "."
    }
    if let e = error as? CoreError {
        switch e {
        case .DecryptFailed: return "Wrong master password or Secret Key."
        case .PasswordRequired(let m), .Invalid(let m): return "Something went wrong: \(m)"
        }
    }
    if let e = error as? ConflictError { return e.errorDescription ?? "Conflict." }
    let m = error.localizedDescription
    return m.isEmpty ? "Something went wrong." : m
}
