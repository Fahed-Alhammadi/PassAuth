package io.passauth.app.ui.vault

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color as AndroidColor
import android.net.Uri
import android.provider.Settings
import android.view.ViewGroup
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import io.passauth.app.data.OtpAuth
import io.passauth.app.data.OtpKey
import io.passauth.app.data.OtpParse
import io.passauth.app.data.QrDecoder
import io.passauth.app.ui.UiCtx
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.theme.PassAuthTheme
import java.util.concurrent.Executors

/** The item editor's authenticator key: type it, scan its QR code or paste it. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TotpInput(ctx: UiCtx, value: String, onChange: (String) -> Unit) {
    val context = LocalContext.current
    var scanning by remember { mutableStateOf(false) }
    var denied by remember { mutableStateOf(false) }
    val accept = { key: OtpKey ->
        onChange(key.value)
        ctx.notify(if (key.label.isNotEmpty()) "Authenticator key added for ${key.label}." else "Authenticator key added.")
    }
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) scanning = true else denied = true
    }

    TextInput(value, onChange, "Authenticator key (TOTP)", mono = true)
    val problem = remember(value) { (OtpAuth.parse(value) as? OtpParse.Invalid)?.reason?.takeIf { value.isNotBlank() } }
    if (problem != null) {
        Text(problem, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedButton(onClick = {
            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                scanning = true
            } else {
                permission.launch(Manifest.permission.CAMERA)
            }
        }) {
            Icon(Icons.Outlined.QrCodeScanner, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text("Scan QR code")
        }
        OutlinedButton(onClick = {
            val clip = context.getSystemService(ClipboardManager::class.java)?.primaryClip
            val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
            when (val r = OtpAuth.parse(text)) {
                is OtpParse.Valid -> accept(r.key)
                is OtpParse.Invalid -> ctx.notify(if (text.isBlank()) "The clipboard is empty." else r.reason)
            }
        }) {
            Icon(Icons.Outlined.ContentPaste, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text("Paste")
        }
    }

    if (scanning) {
        QrScanDialog(onKey = { scanning = false; accept(it) }, onDismiss = { scanning = false })
    }
    if (denied) {
        AlertDialog(
            onDismissRequest = { denied = false },
            title = { Text("Camera access is off") },
            text = {
                Text(
                    "PassAuth uses the camera only to read the QR code and never keeps pictures. " +
                        "Allow camera access in Android settings, or type or paste the key instead: " +
                        "on the website, look for \"Can't scan?\" or \"Enter a setup key\".",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    denied = false
                    runCatching {
                        context.startActivity(
                            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)),
                        )
                    }
                }) { Text("Open settings") }
            },
            dismissButton = { TextButton(onClick = { denied = false }) { Text("Type the key") } },
        )
    }
}

/**
 * Full-screen camera preview that reads an authenticator QR code. Frames are
 * analysed in memory one at a time (latest only) and never stored; the
 * luminance buffer is wiped when the scanner closes. The dialog inherits the
 * activity's FLAG_SECURE, and the preview uses a TextureView so it's covered too.
 */
@Composable
private fun QrScanDialog(onKey: (OtpKey) -> Unit, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val onKeyNow by rememberUpdatedState(onKey)
    var message by remember { mutableStateOf<String?>(null) }
    var cameraError by remember { mutableStateOf<String?>(null) }
    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
            setBackgroundColor(AndroidColor.BLACK)
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        }
    }

    DisposableEffect(Unit) {
        val executor = Executors.newSingleThreadExecutor()
        val decoder = QrDecoder()
        var buffer = ByteArray(0)
        var done = false
        var lastRejected: String? = null
        var provider: ProcessCameraProvider? = null
        val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
        val analysis = ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
        analysis.setAnalyzer(executor) { image ->
            try {
                if (done) return@setAnalyzer
                val plane = image.planes[0]
                val size = plane.rowStride * image.height
                if (buffer.size != size) buffer = ByteArray(size)
                val y = plane.buffer
                y.rewind()
                y.get(buffer, 0, minOf(y.remaining(), size))
                val text = decoder.decode(buffer, image.width, image.height, plane.rowStride) ?: return@setAnalyzer
                when (val r = OtpAuth.parse(text)) {
                    is OtpParse.Valid -> {
                        done = true
                        ContextCompat.getMainExecutor(context).execute { onKeyNow(r.key) }
                    }
                    is OtpParse.Invalid -> if (text != lastRejected) {
                        lastRejected = text
                        ContextCompat.getMainExecutor(context).execute { message = r.reason }
                    }
                }
            } finally {
                image.close()
            }
        }
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener({
            val p = runCatching { future.get() }.getOrNull() ?: return@addListener run { cameraError = "The camera couldn't be started." }
            provider = p
            val selector = when {
                runCatching { p.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) }.getOrDefault(false) -> CameraSelector.DEFAULT_BACK_CAMERA
                runCatching { p.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) }.getOrDefault(false) -> CameraSelector.DEFAULT_FRONT_CAMERA
                else -> null
            }
            if (selector == null) {
                cameraError = "No camera found. Type or paste the key instead."
                return@addListener
            }
            runCatching { p.bindToLifecycle(lifecycleOwner, selector, preview, analysis) }
                .onFailure { cameraError = "The camera couldn't be started. Type or paste the key instead." }
        }, ContextCompat.getMainExecutor(context))
        onDispose {
            done = true
            analysis.clearAnalyzer()
            provider?.unbind(preview, analysis)
            executor.execute { buffer.fill(0) }
            executor.shutdown()
        }
    }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            AndroidView({ previewView }, Modifier.fillMaxSize())
            // Viewfinder
            Box(
                Modifier.align(Alignment.Center).size(240.dp)
                    .border(BorderStroke(3.dp, Color.White.copy(alpha = 0.9f)), RoundedCornerShape(20.dp)),
            )
            Column(
                Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp),
                verticalArrangement = Arrangement.SpaceBetween,
            ) {
                IconButton(onClick = onDismiss, modifier = Modifier.background(Color.Black.copy(alpha = 0.5f), RoundedCornerShape(24.dp))) {
                    Icon(Icons.Outlined.Close, contentDescription = "Close scanner", tint = Color.White)
                }
                Column(
                    Modifier.fillMaxWidth().background(Color.Black.copy(alpha = 0.6f), RoundedCornerShape(14.dp)).padding(14.dp)
                        .semantics { liveRegion = LiveRegionMode.Polite },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        cameraError ?: "Point the camera at the QR code from the website's two-step login setup.",
                        color = Color.White, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge,
                    )
                    message?.let { Text(it, color = PassAuthTheme.colors.warn, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium) }
                }
            }
        }
    }
}
