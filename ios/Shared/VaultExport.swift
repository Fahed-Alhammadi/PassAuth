import Foundation
import PassAuthCore

/// Export formats; the files themselves come from the Rust core (shared with the web vault).
public enum ExportFormat: String, CaseIterable, Identifiable, Sendable {
    case encrypted, json, csv

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .encrypted: "Encrypted JSON (recommended)"
        case .json: "JSON (not encrypted)"
        case .csv: "CSV (not encrypted)"
        }
    }

    public var isEncrypted: Bool { self == .encrypted }
}

public enum VaultExport {
    /// The core rejects shorter export passwords.
    public static let minPassword = 10

    /// passauth-export-YYYY-MM-DD.json / .csv, or …-protected.json (local date).
    public static func fileName(_ format: ExportFormat, date: Date, calendar: Calendar = .current) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        let day = String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
        switch format {
        case .encrypted: return "passauth-export-\(day)-protected.json"
        case .json: return "passauth-export-\(day).json"
        case .csv: return "passauth-export-\(day).csv"
        }
    }

    /// Validation of the export password fields; nil when fine.
    public static func passwordProblem(_ password: String, _ confirm: String) -> String? {
        if password.count < minPassword { return "Use at least \(minPassword) characters for the export password." }
        if password != confirm { return "The export passwords don't match." }
        return nil
    }

    /// Builds the file (CPU-bound: Argon2id for the encrypted format; call off the main thread).
    public static func build(_ format: ExportFormat, itemsJson: String, password: String?) throws -> String {
        switch format {
        case .encrypted: try exportVaultEncrypted(itemsJson: itemsJson, password: password ?? "")
        case .json: try exportVaultJson(itemsJson: itemsJson)
        case .csv: try exportVaultCsv(itemsJson: itemsJson)
        }
    }
}

/// Formatting of an item's previous passwords (`password_history`).
public enum PasswordHistory {
    /// Previous passwords to show, newest first (empty ones are dropped).
    public static func entries(_ history: [PasswordChange]) -> [PasswordChange] {
        history.filter { !$0.password.isEmpty }.sorted { $0.changedAt > $1.changedAt }
    }

    /// The "Password history" row's count.
    public static func summary(_ count: Int) -> String {
        switch count {
        case 0: "No previous passwords"
        case 1: "1 previous password"
        default: "\(count) previous passwords"
        }
    }
}
