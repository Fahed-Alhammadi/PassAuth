package io.passauth.app.ui.vault

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.webkit.MimeTypeMap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.passauth.app.data.Attachment
import io.passauth.app.data.AttachmentManager
import io.passauth.app.data.Attachments
import io.passauth.app.data.DownloadedFile
import io.passauth.app.data.Item
import io.passauth.app.data.StoredAttachment
import io.passauth.app.data.UserException
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.DecisionSheet
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.PromptText
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.components.Tile
import io.passauth.app.ui.components.WarningNote
import io.passauth.app.ui.errorMessage
import io.passauth.app.ui.settings.formatBytes
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Space
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** What the file sheet does with the downloaded file. */
private enum class FileAction { Open, Share, Save }

/** The attachment endpoint of an item's own file. */
fun attachmentPath(id: String) = "/attachments/${java.net.URLEncoder.encode(id, "UTF-8")}"

/**
 * The files of an item (servers with `attachments`; the web vault's `Attachments.tsx`): each with
 * its size and, when the server no longer has it, a mark; tap for Open, Share, Save to device and
 * (with write access) Delete. "Add file" picks one with Android's file picker; uploads show their
 * progress here. [path] is where an attachment is downloaded from; [readOnly] for a grantor's vault
 * opened through emergency access (no server list, no changes).
 */
@Composable
fun AttachmentsCard(
    ctx: UiCtx,
    itemId: String,
    item: Item,
    canWrite: Boolean,
    readOnly: Boolean = false,
    path: (Attachment) -> String = { attachmentPath(it.id) },
) {
    val files: AttachmentManager = ctx.graph.files
    val list = remember(item) { Attachments.read(item) }
    val uploads by files.uploads.collectAsStateWithLifecycle()
    val mine = uploads.filter { it.itemId == itemId }
    var features by remember { mutableStateOf<List<String>?>(null) }
    var stored by remember { mutableStateOf<List<StoredAttachment>?>(null) }
    var refresh by remember { mutableIntStateOf(0) }
    var open by remember { mutableStateOf<Attachment?>(null) }
    var cleaning by remember { mutableStateOf(false) }
    val context = LocalContext.current

    LaunchedEffect(Unit) { features = runCatching { ctx.repo.features() }.getOrNull() }
    LaunchedEffect(item, refresh, readOnly) {
        if (readOnly) return@LaunchedEffect
        stored = runCatching { ctx.repo.storedAttachments(itemId) }.getOrNull()
    }
    val enabled = features?.contains(Attachments.FEATURE) == true
    val missing = stored?.let { Attachments.missingOnServer(list, it) }.orEmpty()
    val leftovers = if (canWrite && !readOnly) stored?.let { Attachments.leftovers(item, it, System.currentTimeMillis() / 1000) }.orEmpty() else emptyList()
    if (list.isEmpty() && mine.isEmpty() && leftovers.isEmpty() && (!enabled || !canWrite || readOnly)) return

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) ctx.launch { files.attach(itemId, uri) }
    }

    CardSection("Attachments") {
        list.forEachIndexed { n, a ->
            if (n > 0) HorizontalDivider(color = PassAuthTheme.colors.line)
            val gone = a.id in missing
            Row(
                Modifier.fillMaxWidth().heightIn(min = 56.dp)
                    .clickable(role = Role.Button, onClickLabel = "Open file options") { open = a }
                    .padding(vertical = 8.dp)
                    .semantics(mergeDescendants = true) {},
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Space.m),
            ) {
                Icon(Icons.Outlined.Description, null, tint = MaterialTheme.colorScheme.primary)
                Column(Modifier.weight(1f)) {
                    Text(a.name, style = MaterialTheme.typography.bodyLarge, maxLines = 2, overflow = TextOverflow.MiddleEllipsis)
                    Text(
                        if (gone) "${formatBytes(a.size)} · No longer on the server" else formatBytes(a.size),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (gone) MaterialTheme.colorScheme.error else PassAuthTheme.colors.muted,
                    )
                }
            }
        }
        mine.forEach { t ->
            if (list.isNotEmpty() || mine.first() !== t) HorizontalDivider(color = PassAuthTheme.colors.line)
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(t.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.MiddleEllipsis)
                        Text(
                            when (t.state) {
                                "queued" -> "Waiting to upload…"
                                "uploading" -> "Encrypting and uploading… ${(t.fraction * 100).toInt()}%"
                                "saving" -> "Adding it to the item…"
                                else -> t.error ?: "The upload failed."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = if (t.state == "failed") MaterialTheme.colorScheme.error else PassAuthTheme.colors.muted,
                        )
                    }
                    if (t.state != "saving") {
                        IconButton(onClick = { files.cancel(t.key) }) {
                            Icon(Icons.Outlined.Close, if (t.state == "failed") "Dismiss ${t.name}" else "Stop uploading ${t.name}")
                        }
                    }
                }
                if (t.state == "uploading" || t.state == "saving") {
                    LinearProgressIndicator(progress = { t.fraction }, modifier = Modifier.fillMaxWidth().padding(top = 4.dp))
                }
            }
        }
        if (leftovers.isNotEmpty()) {
            HorizontalDivider(color = PassAuthTheme.colors.line)
            Column(Modifier.padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val n = leftovers.size
                Text(
                    "${if (n == 1) "A finished upload" else "$n finished uploads"} ${if (n == 1) "isn't" else "aren't"} listed in this item and ${if (n == 1) "counts" else "count"} toward your storage.",
                    style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted,
                )
                TextButton(
                    onClick = {
                        cleaning = true
                        ctx.launch {
                            try {
                                // What's unlisted now: another device may have saved the item with one of them meanwhile.
                                ctx.repo.sync()
                                val latest = ctx.repo.vault.value?.get(itemId) ?: throw UserException("This item is no longer in your vault. It may have been deleted on another device.")
                                val now = Attachments.leftovers(latest.item, ctx.repo.storedAttachments(itemId), System.currentTimeMillis() / 1000)
                                now.forEach { ctx.repo.deleteStoredAttachment(it.id) }
                                ctx.notify(if (now.isEmpty()) "Nothing to delete: they're listed in the item now." else "Deleted.")
                            } finally {
                                cleaning = false
                                refresh++
                            }
                        }
                    },
                    enabled = !cleaning,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) { Text(if (cleaning) "Deleting…" else "Delete them") }
            }
        }
        if (enabled && canWrite && !readOnly) {
            if (list.isNotEmpty() || mine.isNotEmpty() || leftovers.isNotEmpty()) HorizontalDivider(color = PassAuthTheme.colors.line)
            OutlinedButton(onClick = { pick.launch(arrayOf("*/*")) }, modifier = Modifier.padding(vertical = 8.dp).heightIn(min = 48.dp)) {
                Icon(Icons.Outlined.AttachFile, null)
                Text("Add file", Modifier.padding(start = Space.s))
            }
        }
    }

    open?.let { a ->
        FileSheet(ctx, context, itemId, a, path(a), gone = a.id in missing, canDelete = canWrite && !readOnly, onDeleted = { refresh++ }) { open = null }
    }
}

/** One file's options: Open, Share, Save to device, Delete. Downloads show their progress here. */
@Composable
private fun FileSheet(
    ctx: UiCtx,
    context: android.content.Context,
    itemId: String,
    a: Attachment,
    path: String,
    gone: Boolean,
    canDelete: Boolean,
    onDeleted: () -> Unit,
    close: () -> Unit,
) {
    val files = ctx.graph.files
    var busy by remember { mutableStateOf<String?>(null) }
    var progress by remember { mutableFloatStateOf(0f) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf<DownloadedFile?>(null) }

    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(mimeOf(a.name))) { uri: Uri? ->
        val file = saving ?: return@rememberLauncherForActivityResult
        saving = null
        if (uri == null) {
            files.discard(file)
            busy = null
            return@rememberLauncherForActivityResult
        }
        ctx.scope.launch {
            try {
                files.saveTo(file, uri)
                ctx.notify("Saved.")
                close()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = AttachmentManager.fileError(e)
            } finally {
                busy = null
            }
        }
    }

    fun run(action: FileAction) {
        if (busy != null) return
        error = null
        progress = 0f
        busy = "Downloading…"
        ctx.scope.launch {
            try {
                val got = files.download(path, itemId, a) { progress = it }
                // The vault may have locked as the download ended: nothing is handed out then.
                if (!files.isCurrent(got)) {
                    files.discard(got)
                    throw UserException(AttachmentManager.LOCKED_TEXT)
                }
                val file = got.file
                when (action) {
                    FileAction.Save -> {
                        saving = got
                        busy = "Saving…"
                        save.launch(file.name)
                        return@launch
                    }
                    FileAction.Open, FileAction.Share -> {
                        val uri = FileProvider.getUriForFile(context, context.packageName + ".files", file)
                        val intent = if (action == FileAction.Open) {
                            Intent(Intent.ACTION_VIEW).setDataAndType(uri, mimeOf(file.name))
                        } else {
                            val send = Intent(Intent.ACTION_SEND).setType(mimeOf(file.name)).putExtra(Intent.EXTRA_STREAM, uri)
                                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            send.clipData = android.content.ClipData.newRawUri(a.name, uri)
                            Intent.createChooser(send, "Share ${a.name}")
                        }
                        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        try {
                            ctx.activity.startActivity(intent)
                            close()
                        } catch (_: ActivityNotFoundException) {
                            files.discard(got)
                            error = "No app on this phone can open this file. Save it to your device instead."
                        }
                    }
                }
                busy = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                error = AttachmentManager.fileError(e)
                busy = null
            }
        }
    }

    if (confirmDelete) {
        DecisionSheet(
            onDismiss = { confirmDelete = false },
            title = "Delete this file?",
            subtitle = a.name,
            tile = { Tile(icon = Icons.Outlined.Delete, danger = true) },
            error = error,
            dismissable = busy == null,
            actions = {
                PrimaryButton(if (busy != null) "Deleting…" else "Delete file", {
                    busy = "Deleting…"
                    ctx.scope.launch {
                        try {
                            files.remove(itemId, a.id)
                            ctx.notify("File deleted.")
                            onDeleted()
                            close()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            error = errorMessage(e)
                        } finally {
                            busy = null
                        }
                    }
                }, busy = busy != null, danger = true)
                QuietActions { QuietButton("Cancel", { confirmDelete = false }, enabled = busy == null) }
            },
        ) { PromptText("It's removed from this item and deleted from your server, for everyone who can open the item.") }
        return
    }

    DecisionSheet(
        onDismiss = close,
        title = a.name,
        subtitle = formatBytes(a.size),
        tile = { Tile(icon = Icons.Outlined.Description) },
        error = error,
        dismissable = busy == null,
        actions = {
            if (!gone) {
                PrimaryButton(busy ?: "Open", { run(FileAction.Open) }, busy = busy != null, icon = Icons.Outlined.OpenInNew)
                QuietActions {
                    QuietButton("Share", { run(FileAction.Share) }, enabled = busy == null, icon = Icons.Outlined.Share)
                    QuietButton("Save to device", { run(FileAction.Save) }, enabled = busy == null, icon = Icons.Outlined.Download)
                    if (canDelete) QuietButton("Delete…", { confirmDelete = true }, enabled = busy == null, danger = true)
                }
            } else {
                QuietActions {
                    QuietButton("Close", close)
                    if (canDelete) QuietButton("Delete…", { confirmDelete = true }, danger = true)
                }
            }
        },
    ) {
        if (gone) WarningNote("This file is no longer on the server. An earlier version of the item may have listed it.")
        if (busy == "Downloading…") {
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth().semantics { contentDescription = "Downloading, ${(progress * 100).toInt()} percent" },
            )
        } else if (!gone) {
            PromptText("Opening or sharing hands a decrypted copy to another app. PassAuth deletes its own copy when the vault locks.")
        }
    }
}

/** The file's type by its extension, for the apps that open it. */
private fun mimeOf(name: String): String =
    name.substringAfterLast('.', "").lowercase().takeIf { it.isNotEmpty() }?.let { MimeTypeMap.getSingleton().getMimeTypeFromExtension(it) } ?: "application/octet-stream"
