package io.passauth.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import io.passauth.app.data.ThemeMode

/** Brand colours from assets/passauth-logo.svg and the web vault's CSS tokens (web/src/styles/app.css). */
object Brand {
    val Navy = Color(0xFF082052)
    val Blue = Color(0xFF0866ED)
    val Cyan = Color(0xFF23D5F4)
    /** The logo's shield gradient (TOTP ring, accents). */
    val ringBrush get() = Brush.linearGradient(listOf(Blue, Cyan))
}

/** Extra tokens Material 3 has no slot for. */
@Immutable
data class PassAuthColors(
    val header: Color,
    val onHeader: Color,
    val muted: Color,
    val line: Color,
    val ok: Color,
    val okSoft: Color,
    val warn: Color,
)

private val LightScheme = lightColorScheme(
    primary = Color(0xFF0866ED),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE3EEFF),
    onPrimaryContainer = Color(0xFF0650C4),
    // Selected states (navigation bar, segmented buttons) use the accent, as in the web vault.
    secondary = Color(0xFF0650C4),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE3EEFF),
    onSecondaryContainer = Color(0xFF0650C4),
    background = Color(0xFFF4F7FC),
    onBackground = Color(0xFF0B1A3A),
    surface = Color(0xFFF4F7FC),
    onSurface = Color(0xFF0B1A3A),
    surfaceVariant = Color(0xFFEAF0F9),
    onSurfaceVariant = Color(0xFF3A4A68),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color.White,
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFEAF0F9),
    surfaceContainerHighest = Color(0xFFE1E9F5),
    outline = Color(0xFF64748F),
    outlineVariant = Color(0xFFD6DFEC),
    error = Color(0xFFB3261E),
    onError = Color.White,
    errorContainer = Color(0xFFFBE3E1),
    onErrorContainer = Color(0xFFB3261E),
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF3D8BFF),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF13284D),
    onPrimaryContainer = Color(0xFF8CBCFF),
    secondary = Color(0xFF8CBCFF),
    onSecondary = Color(0xFF0A1120),
    secondaryContainer = Color(0xFF13284D),
    onSecondaryContainer = Color(0xFF8CBCFF),
    background = Color(0xFF0A1120),
    onBackground = Color(0xFFE7EDF7),
    surface = Color(0xFF0A1120),
    onSurface = Color(0xFFE7EDF7),
    surfaceVariant = Color(0xFF19253B),
    onSurfaceVariant = Color(0xFFB3C0D6),
    surfaceContainerLowest = Color(0xFF0A1120),
    surfaceContainerLow = Color(0xFF111B2E),
    surfaceContainer = Color(0xFF111B2E),
    surfaceContainerHigh = Color(0xFF19253B),
    surfaceContainerHighest = Color(0xFF22304A),
    outline = Color(0xFF8090AB),
    outlineVariant = Color(0xFF26344D),
    error = Color(0xFFF2867D),
    onError = Color(0xFF3D2222),
    errorContainer = Color(0xFF3D2222),
    onErrorContainer = Color(0xFFF2867D),
)

private val LightExtra = PassAuthColors(
    header = Color(0xFF082052), onHeader = Color.White, muted = Color(0xFF64748F), line = Color(0xFFD6DFEC),
    ok = Color(0xFF0F766E), okSoft = Color(0xFFD9F2EF), warn = Color(0xFF9A5B00),
)
private val DarkExtra = PassAuthColors(
    header = Color(0xFF070F20), onHeader = Color(0xFFE7EDF7), muted = Color(0xFF8090AB), line = Color(0xFF26344D),
    ok = Color(0xFF5EEAD4), okSoft = Color(0xFF123634), warn = Color(0xFFF5B85C),
)

val LocalPassAuthColors = staticCompositionLocalOf { LightExtra }

object PassAuthTheme {
    val colors: PassAuthColors @Composable get() = LocalPassAuthColors.current
}

@Composable
fun isDark(mode: ThemeMode) = when (mode) {
    ThemeMode.System -> isSystemInDarkTheme()
    ThemeMode.Light -> false
    ThemeMode.Dark -> true
}

@Composable
fun PassAuthTheme(mode: ThemeMode, content: @Composable () -> Unit) {
    val dark = isDark(mode)
    val scheme: ColorScheme = if (dark) DarkScheme else LightScheme
    CompositionLocalProvider(LocalPassAuthColors provides if (dark) DarkExtra else LightExtra) {
        MaterialTheme(colorScheme = scheme, typography = Typography(), content = content)
    }
}
