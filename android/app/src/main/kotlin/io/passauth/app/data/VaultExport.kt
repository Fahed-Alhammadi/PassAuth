package io.passauth.app.data

import io.passauth.core.exportVaultCsv
import io.passauth.core.exportVaultEncrypted
import io.passauth.core.exportVaultJson
import java.time.LocalDate

/** Export formats; the files themselves come from the Rust core (shared with the web vault). */
enum class ExportFormat(val label: String, val mime: String) {
    Encrypted("Encrypted JSON (recommended)", "application/json"),
    Json("JSON (not encrypted)", "application/json"),
    Csv("CSV (not encrypted)", "text/csv"),
    ;

    val encrypted: Boolean get() = this == Encrypted
}

object VaultExport {
    /** The core rejects shorter export passwords. */
    const val MIN_PASSWORD = 10

    /** passauth-export-YYYY-MM-DD.json / .csv, or …-protected.json. */
    fun fileName(format: ExportFormat, date: LocalDate): String = when (format) {
        ExportFormat.Encrypted -> "passauth-export-$date-protected.json"
        ExportFormat.Json -> "passauth-export-$date.json"
        ExportFormat.Csv -> "passauth-export-$date.csv"
    }

    /** Validation of the export password fields; null when fine. */
    fun passwordProblem(password: String, confirm: String): String? = when {
        password.length < MIN_PASSWORD -> "Use at least $MIN_PASSWORD characters for the export password."
        password != confirm -> "The export passwords don't match."
        else -> null
    }

    /** Builds the file (CPU-bound: Argon2id for the encrypted format; call off the main thread). */
    fun build(format: ExportFormat, itemsJson: String, password: String?): String = when (format) {
        ExportFormat.Encrypted -> exportVaultEncrypted(itemsJson, requireNotNull(password))
        ExportFormat.Json -> exportVaultJson(itemsJson)
        ExportFormat.Csv -> exportVaultCsv(itemsJson)
    }
}
