package io.passauth.app.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearOutSlowInEasing
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.SheetValue
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Radius
import io.passauth.app.ui.theme.Space

// The anatomy every PassAuth prompt follows ("decision sheet"), in the Material idiom:
//   1. brand bar: the logo and "PassAuth" at the leading edge, close at the trailing edge
//      (prompts over other apps; a sheet inside the app has the drag handle instead);
//   2. context row (PromptHeader): what is being decided and for which site, leading-aligned;
//   3. choices: one grouped card of rows with a radio mark (ChoiceRow);
//   4. verification (master password) right above the actions;
//   5. actions: one filled button (PrimaryButton), quiet text buttons on a row beneath it
//      (QuietActions), errors just above them. The actions stay put while the content scrolls.

/** True inside a sheet: grouped cards and tiles use the sheet's colours. */
val LocalOnSheet = staticCompositionLocalOf { false }

/** Large text: tiles and icons step aside so the words get the whole width. */
@Composable
fun largeText(): Boolean = LocalDensity.current.fontScale >= 1.5f

/** A rounded tile with a symbol, or the first letter of [text] (a site, an item). */
@Composable
fun Tile(text: String = "", icon: ImageVector? = null, size: Dp = 40.dp, onCard: Boolean = false, danger: Boolean = false) {
    val color = if (onCard && !LocalOnSheet.current) MaterialTheme.colorScheme.surfaceVariant else PassAuthTheme.colors.tile
    Box(Modifier.size(size).background(color, RoundedCornerShape(Radius.control)), contentAlignment = Alignment.Center) {
        if (icon != null) {
            Icon(icon, null, Modifier.size(size * 0.5f), tint = if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        } else {
            // Sized to the tile, not the font scale: it is a picture of the site, the name is next to it.
            val sp = with(LocalDensity.current) { (size * 0.42f).toSp() }
            Text(
                (text.trim().firstOrNull() ?: '?').uppercase(),
                color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold, fontSize = sp, maxLines = 1,
            )
        }
    }
}

/** The context row of a prompt: tile, what is being decided, and the site or account beneath. */
@Composable
fun PromptHeader(title: String, subtitle: String? = null, modifier: Modifier = Modifier, tile: (@Composable () -> Unit)? = null) {
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.m)) {
        if (tile != null && !largeText()) tile()
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, modifier = Modifier.semantics { heading() })
            if (!subtitle.isNullOrEmpty()) {
                Text(
                    subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = if (largeText()) Int.MAX_VALUE else 2, overflow = TextOverflow.MiddleEllipsis,
                )
            }
        }
    }
}

/** A sentence-case label above a grouped card. */
@Composable
fun GroupLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(start = Space.xs).semantics { heading() },
    )
}

/** A grouped card: rows on one surface with a hairline, no shadow. Rows bring their own padding. */
@Composable
fun GroupCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val sheet = LocalOnSheet.current
    val c = PassAuthTheme.colors
    Surface(
        shape = RoundedCornerShape(Radius.card),
        color = if (sheet) c.sheetCard else MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, if (sheet) c.sheetLine else c.line),
        modifier = modifier.fillMaxWidth(),
    ) { Column(content = content) }
}

/** The hairline between two rows of a card, inset to the text column. */
@Composable
fun RowDivider(inset: Dp = Space.l) {
    val c = PassAuthTheme.colors
    HorizontalDivider(Modifier.padding(start = inset), color = if (LocalOnSheet.current) c.sheetLine else c.line)
}

/** The start of the text column of a row with a 40 dp tile (for [RowDivider]). */
val TileRowInset = Space.l + 40.dp + Space.m

/** A row of a choice list: tile, title, detail and the radio mark of the selected row. */
@Composable
fun ChoiceRow(
    title: String,
    detail: String,
    selected: Boolean,
    onClick: () -> Unit,
    enabled: Boolean = true,
    icon: ImageVector? = null,
) {
    val big = largeText()
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp)
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onClick)
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.m),
    ) {
        if (!big) Tile(title, icon, onCard = true)
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, maxLines = if (big) Int.MAX_VALUE else 1, overflow = TextOverflow.Ellipsis)
            if (detail.isNotEmpty()) {
                Text(
                    detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = if (big) Int.MAX_VALUE else 1, overflow = TextOverflow.Ellipsis,
                )
            }
        }
        // The row is the control; the mark shows the state (never colour alone).
        RadioButton(selected = selected, onClick = null, enabled = enabled)
    }
}

/** The one filled button of a prompt. */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    busy: Boolean = false,
    danger: Boolean = false,
    icon: ImageVector? = null,
) {
    val colors = if (danger) {
        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
    } else {
        ButtonDefaults.buttonColors()
    }
    Button(onClick = onClick, enabled = enabled && !busy, colors = colors, modifier = modifier.fillMaxWidth().heightIn(min = 48.dp)) {
        if (busy) {
            CircularProgressIndicator(Modifier.size(18.dp), color = LocalContentColor.current, strokeWidth = 2.dp)
            Spacer(Modifier.size(Space.s))
        } else if (icon != null) {
            Icon(icon, null, Modifier.size(18.dp))
            Spacer(Modifier.size(Space.s))
        }
        Text(text)
    }
}

/** The quiet actions under the primary button: text buttons on one row (wrapping when large text doesn't fit). */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun QuietActions(modifier: Modifier = Modifier, content: @Composable RowScope.() -> Unit) {
    FlowRow(
        modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(Space.s, Alignment.CenterHorizontally),
        content = { content() },
    )
}

/** One quiet action: a text button with a full-size touch target. */
@Composable
fun QuietButton(text: String, onClick: () -> Unit, enabled: Boolean = true, icon: ImageVector? = null, danger: Boolean = false) {
    TextButton(
        onClick = onClick, enabled = enabled, modifier = Modifier.heightIn(min = 48.dp),
        colors = if (danger) ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error) else ButtonDefaults.textButtonColors(),
    ) {
        if (icon != null) {
            Icon(icon, null, Modifier.size(18.dp))
            Spacer(Modifier.size(Space.s))
        }
        Text(text)
    }
}

/**
 * A prompt over another app (autofill, passkeys): a sheet anchored to the bottom of the
 * screen (centred on wide screens) above a scrim, with the brand bar, scrolling content and
 * pinned actions. Tapping the scrim or the close mark calls [onClose].
 */
@Composable
fun PromptSheet(
    onClose: () -> Unit,
    closeLabel: String = "Cancel",
    canClose: Boolean = true,
    error: String? = null,
    actions: @Composable ColumnScope.() -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = PassAuthTheme.colors
    // Slides in once; "remove animations" in Android's settings turns this off (Compose follows it).
    val shown = remember { MutableTransitionState(false).apply { targetState = true } }
    BoxWithConstraints(Modifier.fillMaxSize()) {
        val wide = maxWidth >= 600.dp
        AnimatedVisibility(shown, enter = fadeIn(tween(150)), exit = fadeOut(tween(120))) {
            Box(Modifier.fillMaxSize().background(c.scrim).pointerInput(canClose) { detectTapGestures { if (canClose) onClose() } })
        }
        Box(
            Modifier.fillMaxSize()
                .windowInsetsPadding(WindowInsets.safeDrawing.only(if (wide) WindowInsetsSides.Horizontal + WindowInsetsSides.Vertical else WindowInsetsSides.Horizontal + WindowInsetsSides.Top))
                .padding(top = Space.xl, bottom = if (wide) Space.xl else 0.dp),
            contentAlignment = if (wide) Alignment.Center else Alignment.BottomCenter,
        ) {
            AnimatedVisibility(
                shown,
                enter = slideInVertically(tween(180, easing = LinearOutSlowInEasing)) { it / 4 } + fadeIn(tween(150)),
                exit = fadeOut(tween(120)),
            ) {
                Surface(
                    color = c.sheet,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                    shape = if (wide) RoundedCornerShape(Radius.sheet) else RoundedCornerShape(topStart = Radius.sheet, topEnd = Radius.sheet),
                    shadowElevation = 8.dp,
                    modifier = Modifier.widthIn(max = 560.dp).fillMaxWidth().semantics { paneTitle = "PassAuth" },
                ) {
                    CompositionLocalProvider(LocalOnSheet provides true) {
                        Column {
                            Row(
                                Modifier.fillMaxWidth().padding(start = Space.l, end = Space.xs, top = Space.xs).heightIn(min = 48.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                LogoMark(24.dp)
                                Spacer(Modifier.size(Space.s))
                                Text("PassAuth", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                                IconButton(onClick = onClose, enabled = canClose) { Icon(Icons.Outlined.Close, contentDescription = closeLabel) }
                            }
                            Column(
                                Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()).padding(horizontal = Space.l).padding(top = Space.s),
                                verticalArrangement = Arrangement.spacedBy(Space.l),
                                content = content,
                            )
                            Column(
                                Modifier.padding(start = Space.l, end = Space.l, top = Space.l, bottom = Space.s),
                                verticalArrangement = Arrangement.spacedBy(Space.xs),
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                if (error != null) {
                                    ErrorText(error)
                                    Spacer(Modifier.size(Space.s))
                                }
                                actions()
                            }
                            // The sheet's colour runs under the navigation bar and the keyboard; its content stays above them.
                            if (!wide) Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing))
                        }
                    }
                }
            }
        }
    }
}

/**
 * A decision inside the app (confirmations, pickers, re-entering the master password): a
 * Material bottom sheet with the context row, the content, and the actions beneath it.
 * [dismissable] false keeps it open while work is running.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DecisionSheet(
    onDismiss: () -> Unit,
    title: String,
    subtitle: String? = null,
    tile: (@Composable () -> Unit)? = null,
    error: String? = null,
    dismissable: Boolean = true,
    actions: @Composable ColumnScope.() -> Unit,
    content: @Composable ColumnScope.() -> Unit = {},
) {
    val c = PassAuthTheme.colors
    // While work is running the sheet can't be swiped, tapped or backed away.
    val open = rememberUpdatedState(dismissable)
    val keep = remember { { v: SheetValue -> open.value || v != SheetValue.Hidden } }
    val state = rememberModalBottomSheetState(skipPartiallyExpanded = true, confirmValueChange = keep)
    ModalBottomSheet(
        onDismissRequest = { if (dismissable) onDismiss() },
        sheetState = state,
        sheetGesturesEnabled = dismissable,
        properties = ModalBottomSheetProperties(shouldDismissOnBackPress = dismissable),
        containerColor = c.sheet,
        contentColor = MaterialTheme.colorScheme.onSurface,
        scrimColor = c.scrim,
        tonalElevation = 0.dp,
    ) {
        CompositionLocalProvider(LocalOnSheet provides true) {
            Column(Modifier.widthIn(max = 560.dp).fillMaxWidth()) {
                Column(
                    Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState()).padding(horizontal = Space.l),
                    verticalArrangement = Arrangement.spacedBy(Space.l),
                ) {
                    PromptHeader(title, subtitle, tile = tile)
                    content()
                }
                Column(
                    Modifier.padding(start = Space.l, end = Space.l, top = Space.l, bottom = Space.s),
                    verticalArrangement = Arrangement.spacedBy(Space.xs),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    if (error != null) {
                        ErrorText(error)
                        Spacer(Modifier.size(Space.s))
                    }
                    actions()
                }
            }
        }
    }
}

/** Body text of a prompt. */
@Composable
fun PromptText(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = modifier)
}
