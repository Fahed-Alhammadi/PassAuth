package io.passauth.app.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.graphics.drawable.Icon
import android.service.autofill.Dataset
import android.service.autofill.Field
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.Presentations
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import io.passauth.app.MainActivity
import io.passauth.app.R
import io.passauth.app.data.Entry
import io.passauth.app.data.Settings

/** Builds autofill responses: datasets with drop-down and keyboard (inline) presentations. */
class AutofillResponses(private val context: Context, private val inline: InlineSuggestionsRequest?) {
    private var inlineIndex = 0

    /** Opening PassAuth from a long-pressed keyboard suggestion. */
    private val attribution: PendingIntent by lazy {
        PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun menu(title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.title, title)
            setTextViewText(R.id.subtitle, subtitle.orEmpty())
            setViewVisibility(R.id.subtitle, if (subtitle.isNullOrEmpty()) android.view.View.GONE else android.view.View.VISIBLE)
        }

    @SuppressLint("RestrictedApi")
    private fun inlineFor(title: String, subtitle: String?): InlinePresentation? {
        val req = inline ?: return null
        val specs = req.inlinePresentationSpecs
        if (specs.isEmpty() || inlineIndex >= req.maxSuggestionCount) return null
        val spec: InlinePresentationSpec = specs[minOf(inlineIndex, specs.size - 1)]
        inlineIndex++
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(title)
            .apply { if (!subtitle.isNullOrEmpty()) setSubtitle(subtitle) }
            .setStartIcon(Icon.createWithResource(context, R.drawable.logo_mark))
            .setContentDescription(listOfNotNull(title, subtitle).joinToString(", "))
            .build()
        return InlinePresentation(content.slice, spec, false)
    }

    private fun presentations(title: String, subtitle: String?): Presentations =
        Presentations.Builder().setMenuPresentation(menu(title, subtitle)).apply {
            inlineFor(title, subtitle)?.let { setInlinePresentation(it) }
        }.build()

    private fun subtitle(e: Entry) = e.item.login?.username?.takeIf { it.isNotEmpty() } ?: e.item.siteHost.ifEmpty { null }

    /**
     * A dataset that fills [e] right away, or (when [auth] is set) asks PassAuth on
     * selection: used for logins with a verification code, so the code is fresh and
     * can be copied at the moment the user picks the login.
     */
    @Suppress("DEPRECATION")
    fun dataset(e: Entry, form: LoginForm<AutofillId>, auth: IntentSender?, otpCode: String? = null): Dataset? {
        val login = e.item.login ?: return null
        val title = e.item.name.ifEmpty { "Untitled" }
        val b = Dataset.Builder(presentations(title, subtitle(e))).setId(e.id)
        var any = false
        if (auth != null) {
            (form.fillIds + listOfNotNull(form.otp?.id)).forEach { b.setValue(it, null); any = true }
            b.setAuthentication(auth)
        } else {
            form.username?.let { f -> if (login.username.isNotEmpty()) { b.setField(f.id, text(login.username)); any = true } }
            if (login.password.isNotEmpty()) form.passwords.forEach { f -> b.setField(f.id, text(login.password)); any = true }
            if (otpCode != null) form.otp?.let { f -> b.setField(f.id, text(otpCode)); any = true }
        }
        return if (any) b.build() else null
    }

    /** A dataset that only opens PassAuth (nothing is filled). */
    @Suppress("DEPRECATION")
    fun openDataset(ids: List<AutofillId>, auth: IntentSender): Dataset? {
        if (ids.isEmpty()) return null
        val b = Dataset.Builder(presentations("Open PassAuth", null)).setId("open")
        ids.forEach { b.setValue(it, null) }
        return b.setAuthentication(auth).build()
    }

    fun lockedPresentations(email: String): Presentations = presentations("PassAuth is locked", "Unlock to fill · $email".trimEnd(' ', '·'))

    private fun text(v: String) = Field.Builder().setValue(AutofillValue.forText(v)).build()

    companion object {
        /** Login fields to save (password required, username optional), with "Never" adding the site to the never-save list. */
        fun saveInfo(form: LoginForm<AutofillId>, never: IntentSender?): SaveInfo? {
            val pw = form.password ?: return null
            var type = SaveInfo.SAVE_DATA_TYPE_PASSWORD
            if (form.username != null) type = type or SaveInfo.SAVE_DATA_TYPE_USERNAME
            return SaveInfo.Builder(type, form.passwords.map { it.id }.toTypedArray())
                .apply { form.username?.let { setOptionalIds(arrayOf(it.id)) } }
                // Many apps don't finish the activity after signing in; save when the form disappears.
                .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
                .apply { if (never != null) setNegativeAction(SaveInfo.NEGATIVE_BUTTON_STYLE_NEVER, never) }
                .build()
        }

        /** Should a login with a verification code go through PassAuth on selection? */
        fun wantsTotpAuth(e: Entry, form: LoginForm<*>, settings: Settings): Boolean =
            !e.item.login?.totp.isNullOrBlank() && (settings.autoCopyTotp || form.otp != null)

        fun FillResponse.Builder.addAll(datasets: List<Dataset?>): FillResponse.Builder {
            datasets.filterNotNull().forEach { addDataset(it) }
            return this
        }
    }
}
