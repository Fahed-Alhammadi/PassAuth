import Foundation
import os
import PassAuthCore
import UIKit
import UniformTypeIdentifiers

/// Clipboard copies: this device only (no Universal Clipboard), expiring after the user's
/// clearing delay (seconds, 0 = never). Used by the app and the AutoFill extension.
public enum Clipboard {
    public static func copy(_ text: String, clearAfter: Int) {
        var options: [UIPasteboard.OptionsKey: Any] = [.localOnly: true]
        if clearAfter > 0 { options[.expirationDate] = Date().addingTimeInterval(TimeInterval(clearAfter)) }
        UIPasteboard.general.setItems([[UTType.plainText.identifier: text]], options: options)
    }

    /// The current code of an authenticator key, or nil if the key isn't valid.
    public static func totp(_ secret: String?, at date: Date = Date()) -> String? {
        guard let s = secret?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        return try? totpCode(secret: s, unixSeconds: UInt64(date.timeIntervalSince1970)).code
    }
}

/// Process memory (AutoFill extensions have a hard limit).
public enum MemoryStats {
    /// Current and peak physical footprint in bytes (what the system's memory limit counts).
    public static func footprint() -> (current: UInt64, peak: UInt64) {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        guard kr == KERN_SUCCESS else { return (0, 0) }
        return (info.phys_footprint, UInt64(info.ledger_phys_footprint_peak))
    }

    /// Bytes this process can still allocate before reaching its limit; nil where the system
    /// doesn't say (the simulator, which has no extension memory limit).
    public static func available() -> UInt64? {
        let n = os_proc_available_memory()
        return n > 0 ? UInt64(n) : nil
    }

    public static func mb(_ bytes: UInt64) -> String { String(format: "%.1f MB", Double(bytes) / 1_048_576) }
}
