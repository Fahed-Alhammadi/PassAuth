package io.passauth.app

import io.passauth.app.data.ExportFormat
import io.passauth.app.data.VaultExport
import java.time.LocalDate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VaultExportTest {
    @Test
    fun fileNames() {
        val d = LocalDate.of(2026, 11, 1)
        assertEquals("passauth-export-2026-11-01.json", VaultExport.fileName(ExportFormat.Json, d))
        assertEquals("passauth-export-2026-11-01-protected.json", VaultExport.fileName(ExportFormat.Encrypted, d))
        assertEquals("passauth-export-2026-11-01.csv", VaultExport.fileName(ExportFormat.Csv, d))
    }

    @Test
    fun exportPasswordRules() {
        assertEquals("Use at least 10 characters for the export password.", VaultExport.passwordProblem("short", "short"))
        assertEquals("The export passwords don't match.", VaultExport.passwordProblem("long enough 1", "long enough 2"))
        assertNull(VaultExport.passwordProblem("long enough", "long enough"))
    }
}
