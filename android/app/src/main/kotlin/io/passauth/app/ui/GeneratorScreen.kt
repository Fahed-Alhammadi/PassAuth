package io.passauth.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.passauth.app.ui.auth.StrengthMeter
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.ui.Alignment
import io.passauth.app.ui.components.GroupCard
import io.passauth.app.ui.components.PrimaryButton
import io.passauth.app.ui.components.QuietActions
import io.passauth.app.ui.components.QuietButton
import io.passauth.app.ui.theme.Space
import io.passauth.app.ui.components.AccountMenu
import io.passauth.app.ui.components.CardSection
import io.passauth.app.ui.components.PageBar
import io.passauth.app.ui.components.TextInput
import io.passauth.app.ui.components.ToggleRow
import io.passauth.core.generatePassphrase
import io.passauth.core.generatePassword
import kotlin.math.roundToInt
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

@Composable
fun GeneratorScreen(ctx: UiCtx) {
    var passphrase by rememberSaveable { mutableStateOf(false) }
    var length by rememberSaveable { mutableIntStateOf(20) }
    var upper by rememberSaveable { mutableStateOf(true) }
    var lower by rememberSaveable { mutableStateOf(true) }
    var digits by rememberSaveable { mutableStateOf(true) }
    var symbols by rememberSaveable { mutableStateOf(true) }
    var avoidAmbiguous by rememberSaveable { mutableStateOf(false) }
    var words by rememberSaveable { mutableIntStateOf(5) }
    var separator by rememberSaveable { mutableStateOf("-") }
    var capitalize by rememberSaveable { mutableStateOf(true) }
    var number by rememberSaveable { mutableStateOf(true) }
    var value by rememberSaveable { mutableStateOf("") }
    var seed by rememberSaveable { mutableIntStateOf(0) }

    LaunchedEffect(passphrase, length, upper, lower, digits, symbols, avoidAmbiguous, words, separator, capitalize, number, seed) {
        value = runCatching {
            if (passphrase) {
                generatePassphrase(buildJsonObject {
                    put("words", words); put("separator", separator); put("capitalize", capitalize); put("include_number", number)
                }.toString())
            } else {
                generatePassword(buildJsonObject {
                    put("length", length); put("uppercase", upper); put("lowercase", lower)
                    put("digits", digits); put("symbols", symbols); put("avoid_ambiguous", avoidAmbiguous)
                }.toString())
            }
        }.getOrElse { "" }
    }
    SecureWindow()

    Scaffold(topBar = { PageBar("Generator", brand = true) { AccountMenu(ctx) } }) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(!passphrase, { passphrase = false }, SegmentedButtonDefaults.itemShape(0, 2)) { Text("Password") }
                SegmentedButton(passphrase, { passphrase = true }, SegmentedButtonDefaults.itemShape(1, 2)) { Text("Passphrase") }
            }
            GroupCard {
                SelectionContainer {
                    Text(
                        value, style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace, textAlign = TextAlign.Center,
                        modifier = Modifier.padding(Space.xl).fillMaxWidth(),
                    )
                }
            }
            StrengthMeter(value)
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                PrimaryButton(if (passphrase) "Copy passphrase" else "Copy password", { ctx.copy(value, if (passphrase) "Passphrase" else "Password") }, icon = Icons.Outlined.ContentCopy)
                QuietActions { QuietButton("Regenerate", { seed++ }, icon = Icons.Outlined.Refresh) }
            }
            CardSection("Options") {
                Column(Modifier.padding(vertical = 8.dp)) {
                    if (passphrase) {
                        Text("Words: $words", style = MaterialTheme.typography.labelLarge)
                        Slider(words.toFloat(), { words = it.roundToInt() }, valueRange = 3f..12f)
                        TextInput(separator, { separator = it.take(3) }, "Word separator")
                        ToggleRow("Capitalize words", capitalize, { capitalize = it })
                        ToggleRow("Include a number", number, { number = it })
                    } else {
                        Text("Length: $length", style = MaterialTheme.typography.labelLarge)
                        Slider(length.toFloat(), { length = it.roundToInt() }, valueRange = 8f..64f)
                        ToggleRow("Uppercase (A-Z)", upper, { upper = it || !(lower || digits || symbols) })
                        ToggleRow("Lowercase (a-z)", lower, { lower = it || !(upper || digits || symbols) })
                        ToggleRow("Numbers (0-9)", digits, { digits = it || !(upper || lower || symbols) })
                        ToggleRow("Symbols (!@#…)", symbols, { symbols = it || !(upper || lower || digits) })
                        ToggleRow("Avoid ambiguous characters", avoidAmbiguous, { avoidAmbiguous = it }, help = "Leaves out characters that look alike, such as l, 1, O and 0.")
                    }
                }
            }
        }
    }
}
