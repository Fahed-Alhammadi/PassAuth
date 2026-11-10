package io.passauth.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ColorScheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.passauth.app.data.ThemeMode

/** Brand colours from assets/passauth-logo.svg and the web vault's CSS tokens (web/src/styles/app.css). */
object Brand {
    val Navy = Color(0xFF082052)
    val Blue = Color(0xFF0866ED)
    val Cyan = Color(0xFF23D5F4)
    /** The logo's shield gradient (TOTP ring, accents). */
    val ringBrush get() = Brush.linearGradient(listOf(Blue, Cyan))
}

/** The spacing scale every screen uses (4 / 8 / 12 / 16 / 24 / 32). */
object Space {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
    val xxl = 32.dp
}

/** Corner radii: 8 for controls (text boxes, tiles, notices), 12 for grouped cards, 16 for sheets and dialogs. */
object Radius {
    val control = 8.dp
    val card = 12.dp
    val sheet = 16.dp
}

// Material components pick their corners from here: text boxes and menus 8, cards 12, dialogs and
// bottom sheets 16. Buttons keep Material's full rounding.
private val PassAuthShapes = Shapes(
    extraSmall = RoundedCornerShape(Radius.control),
    small = RoundedCornerShape(Radius.control),
    medium = RoundedCornerShape(Radius.card),
    large = RoundedCornerShape(Radius.sheet),
    extraLarge = RoundedCornerShape(Radius.sheet),
)

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
    /** Floating surfaces (sheets, prompts over other apps): one style, raised from the page in dark mode. */
    val sheet: Color,
    /** A grouped card on a sheet, and its hairline. */
    val sheetCard: Color,
    val sheetLine: Color,
    /** Behind a sheet. */
    val scrim: Color,
    /** Letter and symbol tiles on the page or a sheet (on a card they use surfaceVariant). */
    val tile: Color,
)

// Neutral surfaces like the iOS app (light: gray page with white cards; dark: true black with
// raised grays, no tinted backgrounds); the PassAuth blue is the only accent, lighter in dark mode.
// Text pairs meet WCAG AA (≥4.5:1) on their surfaces.
private val LightScheme = lightColorScheme(
    primary = Color(0xFF0866ED),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE7F0FE),
    onPrimaryContainer = Color(0xFF0553C9),
    // Selected states (navigation bar, segmented buttons) use the accent, as in the web vault.
    secondary = Color(0xFF0553C9),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE7F0FE),
    onSecondaryContainer = Color(0xFF0553C9),
    background = Color(0xFFF2F2F7),
    onBackground = Color(0xFF1C1C1E),
    surface = Color(0xFFF2F2F7),
    onSurface = Color(0xFF1C1C1E),
    surfaceVariant = Color(0xFFEDEDF2),
    onSurfaceVariant = Color(0xFF48484D),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color.White,
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFEDEDF2),
    surfaceContainerHighest = Color(0xFFE5E5EA),
    outline = Color(0xFF6C6C72),
    outlineVariant = Color(0xFFD8D8DE),
    error = Color(0xFFC4251B),
    onError = Color.White,
    errorContainer = Color(0xFFFDE7E5),
    onErrorContainer = Color(0xFFC4251B),
)

private val DarkScheme = darkColorScheme(
    primary = Color(0xFF3B8CFA),
    // Dark text on the bright accent: white on #3B8CFA is only 3.3:1, this is 5.7:1.
    onPrimary = Color(0xFF0A1120),
    primaryContainer = Color(0xFF1C2633),
    onPrimaryContainer = Color(0xFF8EC2FF),
    secondary = Color(0xFF8EC2FF),
    onSecondary = Color.Black,
    secondaryContainer = Color(0xFF1C2633),
    onSecondaryContainer = Color(0xFF8EC2FF),
    background = Color.Black,
    onBackground = Color(0xFFF2F2F7),
    surface = Color.Black,
    onSurface = Color(0xFFF2F2F7),
    surfaceVariant = Color(0xFF2C2C2E),
    onSurfaceVariant = Color(0xFFC7C7CC),
    surfaceContainerLowest = Color.Black,
    surfaceContainerLow = Color(0xFF1C1C1E),
    surfaceContainer = Color(0xFF1C1C1E),
    surfaceContainerHigh = Color(0xFF2C2C2E),
    surfaceContainerHighest = Color(0xFF3A3A3C),
    outline = Color(0xFF9B9BA1),
    outlineVariant = Color(0xFF38383A),
    error = Color(0xFFFF6B60),
    onError = Color.Black,
    errorContainer = Color(0xFF3A1D1B),
    onErrorContainer = Color(0xFFFF8A80),
)

// The top bar uses the page colour and follows light and dark mode (no separate header colour).
private val LightExtra = PassAuthColors(
    header = Color(0xFFF2F2F7), onHeader = Color(0xFF1C1C1E), muted = Color(0xFF6C6C72), line = Color(0xFFD8D8DE),
    ok = Color(0xFF1F7A35), okSoft = Color(0xFFE3F3E6), warn = Color(0xFF965A00),
    sheet = Color(0xFFF2F2F7), sheetCard = Color.White, sheetLine = Color(0xFFD8D8DE),
    scrim = Color(0x66000000), tile = Color(0xFFE5E5EA),
)
private val DarkExtra = PassAuthColors(
    header = Color.Black, onHeader = Color(0xFFF2F2F7), muted = Color(0xFF9B9BA1), line = Color(0xFF38383A),
    ok = Color(0xFF4CD964), okSoft = Color(0xFF15301B), warn = Color(0xFFFFB340),
    sheet = Color(0xFF1C1C1E), sheetCard = Color(0xFF2C2C2E), sheetLine = Color(0xFF48484A),
    scrim = Color(0x99000000), tile = Color(0xFF3A3A3C),
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
        MaterialTheme(colorScheme = scheme, typography = Typography(), shapes = PassAuthShapes, content = content)
    }
}
