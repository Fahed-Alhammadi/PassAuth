package io.passauth.app.ui.settings

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.ExportFormat
import io.passauth.app.data.UserException
import io.passauth.app.data.VaultExport
import io.passauth.app.ui.Route
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.Alert
import io.passauth.app.ui.components.AlertKind
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.ErrorText
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.PasswordField
import io.passauth.app.ui.components.SelectField
import io.passauth.app.ui.errorMessage
import java.time.LocalDate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Settings → Vault options → Export: the core builds the file (same formats as
 * the web vault), the user picks where it goes with the Storage Access Framework.
 * PassAuth never writes the export anywhere itself.
 */
@Composable
fun ExportScreen(ctx: UiCtx) {
    val context = LocalContext.current
    val vault by ctx.repo.vault.collectAsStateWithLifecycle()
    val lock = (LocalContext.current.applicationContext as io.passauth.app.PassAuthApp).graph.lock
    val count = vault?.entries?.size ?: 0
    var format by rememberSaveable { mutableStateOf(ExportFormat.Encrypted) }
    var exportPassword by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var master by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // The finished file, held in memory only between "Export" and the file picker's answer.
    var pending by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun write(uri: Uri?) {
        val content = pending
        pending = null
        if (uri == null || content == null) {
            busy = false
            if (content != null) ctx.notify("Export cancelled.")
            return
        }
        scope.launch {
            try {
                withContext(Dispatchers.IO) {
                    context.contentResolver.openOutputStream(uri, "wt")?.use { it.write(content.toByteArray()) }
                        ?: throw UserException("PassAuth couldn't write to that file.")
                }
                exportPassword = ""; confirm = ""; master = ""
                ctx.notify("Vault exported.")
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                error = errorMessage(e)
            } finally {
                busy = false
            }
        }
    }
    val saveJson = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { write(it) }
    val saveCsv = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { write(it) }

    fun export() {
        if (busy) return
        error = null
        if (count == 0) return run { error = "Your vault has no items to export." }
        if (format.encrypted) VaultExport.passwordProblem(exportPassword, confirm)?.let { return run { error = it } }
        if (master.isEmpty()) return run { error = "Enter your master password to export." }
        busy = true
        scope.launch {
            try {
                ctx.repo.verifyMasterPassword(master)
                val items = ctx.repo.itemsJsonForExport()
                val f = format
                val pw = exportPassword
                pending = withContext(Dispatchers.Default) { VaultExport.build(f, items, pw.takeIf { f.encrypted }) }
                val name = VaultExport.fileName(f, LocalDate.now())
                lock.expectSystemScreen()
                if (f == ExportFormat.Csv) saveCsv.launch(name) else saveJson.launch(name)
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                pending = null
                error = errorMessage(e)
                busy = false
            }
        }
    }

    Scaffold(topBar = { PageBar("Export vault", onBack = { ctx.go(Route.Settings("vault")) }) }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CardSection(null) {
                Column(Modifier.padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "Exports the $count item${if (count == 1) "" else "s"} in all vaults of ${ctx.state.email}. " +
                            "You choose where the file is saved.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    SelectField("File format", ExportFormat.entries.map { it to it.label }, format, { format = it; error = null })
                    when (format) {
                        ExportFormat.Encrypted -> {
                            Muted("The file is encrypted with an export password. You need that password to import it again; it isn't your master password.")
                            PasswordField(exportPassword, { exportPassword = it }, "Export password", imeAction = ImeAction.Next)
                            PasswordField(confirm, { confirm = it }, "Confirm password", imeAction = ImeAction.Next)
                            Muted("At least ${VaultExport.MIN_PASSWORD} characters.")
                        }
                        ExportFormat.Json, ExportFormat.Csv -> Alert(
                            "This file is not encrypted. Anyone who gets it can read every password in it. " +
                                "Keep it somewhere safe and delete it when you're done.",
                            AlertKind.Error,
                        )
                    }
                    if (format == ExportFormat.Csv) {
                        Alert("CSV holds logins and secure notes only. Cards, identities and SSH keys are left out; choose JSON for a full export.")
                    }
                    PasswordField(master, { master = it }, "Master password", onImeAction = ::export)
                    Muted("Confirm it's you before your vault leaves PassAuth.")
                    ErrorText(error)
                    Button(onClick = ::export, enabled = !busy) { Text(if (busy) "Exporting…" else "Export vault") }
                }
            }
        }
    }
}
