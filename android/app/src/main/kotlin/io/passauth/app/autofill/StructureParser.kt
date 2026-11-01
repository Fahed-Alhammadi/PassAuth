package io.passauth.app.autofill

import android.app.assist.AssistStructure
import android.view.View
import android.view.autofill.AutofillId

/** What an autofill request is about: the app, its web domain (if web content) and its text fields. */
data class ParsedStructure(
    val packageName: String,
    val webDomain: String?,
    val webScheme: String?,
    val fields: List<FieldInfo<AutofillId>>,
    /** Title of the app's window, a name for new logins when the app's label isn't visible to PassAuth. */
    val windowTitle: String? = null,
) {
    val form: LoginForm<AutofillId> by lazy { FieldClassifier.parse(fields) }
}

/** Reads an [AssistStructure] into [FieldInfo]s (visible, enabled, editable text fields in order). */
object StructureParser {
    fun parse(structure: AssistStructure): ParsedStructure {
        val found = mutableListOf<Pair<FieldInfo<AutofillId>, String?>>()
        var domain: String? = null
        var scheme: String? = null
        // The focused field's web domain wins; otherwise the first one seen.
        var focusedDomain: String? = null
        var focusedScheme: String? = null

        fun visit(node: AssistStructure.ViewNode, parentDomain: String?, parentScheme: String?) {
            if (node.visibility != View.VISIBLE) return
            val nodeDomain = node.webDomain?.takeIf { it.isNotBlank() } ?: parentDomain
            val nodeScheme = if (node.webDomain?.isNotBlank() == true) node.webScheme else parentScheme
            if (nodeDomain != null && domain == null) {
                domain = nodeDomain
                scheme = nodeScheme
            }
            val id = node.autofillId
            if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT && node.isEnabled) {
                val html = node.htmlInfo
                val attrs = html?.attributes?.associate { it.first.lowercase() to it.second.orEmpty() }.orEmpty()
                val f = FieldInfo(
                    id = id,
                    autofillHints = node.autofillHints?.toList().orEmpty(),
                    inputType = node.inputType,
                    idEntry = node.idEntry,
                    hint = node.hint,
                    label = node.contentDescription?.toString(),
                    htmlTag = html?.tag,
                    htmlAttrs = attrs,
                    value = node.autofillValue?.takeIf { it.isText }?.textValue?.toString(),
                    focused = node.isFocused,
                )
                found += f to nodeDomain
                if (node.isFocused && nodeDomain != null) {
                    focusedDomain = nodeDomain
                    focusedScheme = nodeScheme
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i), nodeDomain, nodeScheme)
        }

        for (i in 0 until structure.windowNodeCount) {
            visit(structure.getWindowNodeAt(i).rootViewNode, null, null)
        }
        val webDomain = focusedDomain ?: domain
        return ParsedStructure(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webDomain = webDomain,
            webScheme = if (focusedDomain != null) focusedScheme else scheme,
            // Only fields of that one site (or of the app itself): never fill into a frame of another domain.
            fields = found.filter { (_, d) -> d.equals(webDomain, ignoreCase = true) }.map { it.first },
            windowTitle = (0 until structure.windowNodeCount).firstNotNullOfOrNull { i ->
                structure.getWindowNodeAt(i).title?.toString()?.trim()?.takeIf { it.isNotEmpty() && !it.contains('/') }
            },
        )
    }
}
