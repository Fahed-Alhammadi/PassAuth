package io.passauth.app.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Casino
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.passauth.app.R
import io.passauth.app.data.IconLoader
import io.passauth.app.ui.theme.Brand
import io.passauth.app.ui.theme.PassAuthTheme
import io.passauth.app.ui.theme.Radius
import io.passauth.app.ui.theme.Space

/** Text sized in dp: drawn inside fixed-size shapes, so it must not grow with the system font scale. */
@Composable
private fun fixedSp(size: Dp) = with(androidx.compose.ui.platform.LocalDensity.current) { size.toSp() }

@Composable
fun LogoMark(size: Dp, modifier: Modifier = Modifier) {
    Image(painterResource(R.drawable.logo_mark), contentDescription = null, modifier = modifier.size(size * 128 / 144, size))
}

/** Initials from the profile name ("Fahed Alhammadi" -> "FA"), else from the email. */
fun initials(name: String, email: String): String {
    val words = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    if (words.size > 1) return "${words.first()[0]}${words.last()[0]}".uppercase()
    if (words.size == 1) return words[0].take(2).uppercase()
    val parts = email.substringBefore('@').split(Regex("[._-]+")).filter { it.isNotEmpty() }
    val s = if (parts.size > 1) "${parts[0][0]}${parts[1][0]}" else parts.firstOrNull()?.take(2).orEmpty()
    return s.ifEmpty { "?" }.uppercase()
}

@Composable
fun Avatar(text: String, size: Dp = 36.dp, modifier: Modifier = Modifier) {
    Box(
        modifier.size(size).clip(CircleShape).background(androidx.compose.ui.graphics.Brush.linearGradient(listOf(Brand.Blue, Brand.Cyan))),
        contentAlignment = Alignment.Center,
    ) {
        // Sized to the circle, not the font scale (the account menu button has its own description).
        Text(text, color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = fixedSp(size * 0.38f), maxLines = 1)
    }
}

/** Site icon from the server, or the item's first letter. */
@Composable
fun SiteIcon(host: String, name: String, server: String, enabled: Boolean, icons: IconLoader, size: Dp = 36.dp) {
    val bitmap by produceState<ImageBitmap?>(icons.cached(server, host)?.getOrNull(), host, server, enabled) {
        if (enabled && host.isNotEmpty() && server.isNotEmpty()) value = icons.load(server, host)
    }
    val shape = RoundedCornerShape(8.dp)
    Box(
        Modifier.size(size).clip(shape).background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val b = bitmap
        if (enabled && b != null) {
            Image(b, contentDescription = null, modifier = Modifier.size(size * 0.6f))
        } else {
            Text(
                (name.trim().firstOrNull() ?: '?').uppercase(),
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold,
                fontSize = fixedSp(size * 0.42f),
            )
        }
    }
}

/** Countdown for a verification code, drawn in the PassAuth shield gradient. */
@Composable
fun TotpRing(remaining: Int, period: Int, size: Dp = 30.dp) {
    val low = remaining <= 5
    val track = MaterialTheme.colorScheme.outlineVariant
    val lowColor = MaterialTheme.colorScheme.error
    Box(Modifier.size(size).semantics { contentDescription = "$remaining seconds left" }, contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size)) {
            val stroke = 3.dp.toPx()
            drawCircle(track, style = Stroke(stroke), radius = this.size.minDimension / 2 - stroke)
            val inset = stroke
            val sweep = 360f * remaining / period.coerceAtLeast(1)
            val arcSize = androidx.compose.ui.geometry.Size(this.size.width - inset * 2, this.size.height - inset * 2)
            val topLeft = androidx.compose.ui.geometry.Offset(inset, inset)
            if (low) {
                drawArc(lowColor, -90f, sweep, false, topLeft, arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
            } else {
                drawArc(Brand.ringBrush, -90f, sweep, false, topLeft, arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
            }
        }
        Text("$remaining", fontSize = fixedSp(11.dp), lineHeight = fixedSp(12.dp), color = if (low) lowColor else MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    onGenerate: (() -> Unit)? = null,
    imeAction: androidx.compose.ui.text.input.ImeAction = androidx.compose.ui.text.input.ImeAction.Done,
    onImeAction: () -> Unit = {},
    mono: Boolean = false,
) {
    var show by rememberSaveable { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        modifier = modifier.fillMaxWidth(),
        textStyle = if (mono) MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = imeAction),
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(onAny = { onImeAction() }),
        trailingIcon = {
            Row {
                if (onGenerate != null) {
                    IconButton(onClick = onGenerate) { Icon(Icons.Outlined.Casino, contentDescription = "Generate password") }
                }
                IconButton(onClick = { show = !show }) {
                    Icon(
                        if (show) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                        contentDescription = if (show) "Hide ${label.lowercase()}" else "Show ${label.lowercase()}",
                    )
                }
            }
        },
    )
}

@Composable
fun TextInput(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    mono: Boolean = false,
    singleLine: Boolean = true,
    minLines: Int = 1,
    placeholder: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: androidx.compose.ui.text.input.ImeAction = androidx.compose.ui.text.input.ImeAction.Next,
    onImeAction: (() -> Unit)? = null,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        singleLine = singleLine,
        minLines = minLines,
        modifier = modifier.fillMaxWidth(),
        textStyle = if (mono) MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyLarge,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false, imeAction = if (singleLine) imeAction else androidx.compose.ui.text.input.ImeAction.Default),
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(onAny = { onImeAction?.invoke() }),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun <T> SelectField(label: String, options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit, modifier: Modifier = Modifier) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { open = it }, modifier = modifier) {
        OutlinedTextField(
            value = options.firstOrNull { it.first == selected }?.second.orEmpty(),
            onValueChange = {},
            readOnly = true,
            // Long choices wrap instead of being cut off at large font sizes.
            singleLine = false,
            maxLines = 3,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            modifier = Modifier.menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable).fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (v, text) ->
                DropdownMenuItem(text = { Text(text) }, onClick = { onSelect(v); open = false })
            }
        }
    }
}

@Composable
fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit, help: String? = null) {
    Row(
        Modifier.fillMaxWidth().clickable { onChange(!checked) }.padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            if (help != null) Text(help, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit, help: String? = null) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { onChange(!checked) }.padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Column(Modifier.weight(1f).padding(top = 12.dp)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            if (help != null) Text(help, style = MaterialTheme.typography.bodySmall, color = PassAuthTheme.colors.muted)
        }
    }
}

enum class AlertKind { Info, Ok, Error }

@Composable
fun Alert(text: String, kind: AlertKind = AlertKind.Info, modifier: Modifier = Modifier) {
    val (bg, fg) = when (kind) {
        AlertKind.Info -> MaterialTheme.colorScheme.primaryContainer to MaterialTheme.colorScheme.onPrimaryContainer
        AlertKind.Ok -> PassAuthTheme.colors.okSoft to PassAuthTheme.colors.ok
        AlertKind.Error -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
    }
    Surface(color = bg, contentColor = fg, shape = RoundedCornerShape(Radius.control), modifier = modifier.fillMaxWidth()) {
        Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(Space.m))
    }
}

@Composable
fun ErrorText(error: String?) {
    if (error != null) Alert(error, AlertKind.Error)
}

/** A titled grouped card (sentence-case title above, hairline, no shadow), like the other clients' groups. */
@Composable
fun CardSection(title: String?, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxWidth()) {
        if (title != null) GroupLabel(title, Modifier.padding(bottom = Space.s))
        GroupCard { Column(Modifier.padding(horizontal = Space.l, vertical = Space.s), content = content) }
    }
}

/**
 * One row's part of a grouped card in a lazy list: the card's fill and hairline for this
 * row (rounded at the first and last row), and the divider above it, inset to the text column.
 */
fun Modifier.cardSegment(first: Boolean, last: Boolean, fill: Color, line: Color, dividerInset: Dp, radius: Dp = Radius.card): Modifier {
    val top = if (first) radius else 0.dp
    val bottom = if (last) radius else 0.dp
    return this
        .clip(RoundedCornerShape(topStart = top, topEnd = top, bottomStart = bottom, bottomEnd = bottom))
        .drawBehind {
            val w = size.width
            val h = size.height
            val sw = 1.dp.toPx()
            val half = sw / 2
            val t = top.toPx()
            val b = bottom.toPx()
            drawRect(fill)
            val p = androidx.compose.ui.graphics.Path()
            p.moveTo(half, if (last) h - b else h)
            p.lineTo(half, if (first) t else 0f)
            if (first) {
                p.arcTo(androidx.compose.ui.geometry.Rect(half, half, 2 * t - half, 2 * t - half), 180f, 90f, false)
                p.lineTo(w - t, half)
                p.arcTo(androidx.compose.ui.geometry.Rect(w - 2 * t + half, half, w - half, 2 * t - half), 270f, 90f, false)
            } else {
                p.moveTo(w - half, 0f)
            }
            p.lineTo(w - half, if (last) h - b else h)
            if (last) {
                p.arcTo(androidx.compose.ui.geometry.Rect(w - 2 * b + half, h - 2 * b + half, w - half, h - half), 0f, 90f, false)
                p.lineTo(b, h - half)
                p.arcTo(androidx.compose.ui.geometry.Rect(half, h - 2 * b + half, 2 * b - half, h - half), 90f, 90f, false)
            }
            drawPath(p, line, style = Stroke(sw))
            if (!first) drawLine(line, androidx.compose.ui.geometry.Offset(dividerInset.toPx(), half), androidx.compose.ui.geometry.Offset(w - sw, half), sw)
        }
}

/** One labelled value with actions, inside a card. */
@Composable
fun KeyValue(label: String, actions: @Composable RowScope.() -> Unit = {}, content: @Composable ColumnScope.() -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        // Label and value are read together ("Username, alice"), then the actions.
        Column(Modifier.weight(1f).semantics(mergeDescendants = true) {}) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            content()
        }
        Row(verticalAlignment = Alignment.CenterVertically, content = actions)
    }
}

@Composable
fun ValueText(text: String, mono: Boolean = false, maxLines: Int = Int.MAX_VALUE, description: String? = null) {
    Text(
        text,
        style = MaterialTheme.typography.bodyLarge.let { if (mono) it.copy(fontFamily = FontFamily.Monospace) else it },
        maxLines = maxLines,
        overflow = TextOverflow.Ellipsis,
        // e.g. a masked secret is read as "hidden", not as a row of bullets.
        modifier = if (description != null) Modifier.semantics { contentDescription = description } else Modifier,
    )
}
