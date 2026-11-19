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

/**
 * One view of a request, reduced to what the parser reads (an [AssistStructure.ViewNode] in the
 * service, plain values in tests). [field]: the text field it is (null when it isn't an enabled,
 * autofillable text field); [children] are read only when visited.
 */
interface StructureNode<T> {
    val visible: Boolean
    val webDomain: String?
    val webScheme: String?
    val field: FieldInfo<T>?
    val children: List<StructureNode<T>>
}

/** The web domain and fields found in a request (see [StructureParser.collect]). */
data class Collected<T>(val webDomain: String?, val webScheme: String?, val fields: List<FieldInfo<T>>)

/** Reads an [AssistStructure] into [FieldInfo]s (visible, enabled, editable text fields in order). */
object StructureParser {
    fun parse(structure: AssistStructure): ParsedStructure {
        val roots = (0 until structure.windowNodeCount).map { ViewNodeAdapter(structure.getWindowNodeAt(it).rootViewNode) }
        val c = collect(roots)
        return ParsedStructure(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webDomain = c.webDomain,
            webScheme = c.webScheme,
            fields = c.fields,
            windowTitle = (0 until structure.windowNodeCount).firstNotNullOfOrNull { i ->
                structure.getWindowNodeAt(i).title?.toString()?.trim()?.takeIf { it.isNotEmpty() && !it.contains('/') }
            },
        )
    }

    /**
     * The page's web domain and the fields that belong to it.
     *
     * - Web content (a browser or WebView reporting it natively): the web domain is set on the
     *   content's root node and holds for everything under it. The focused field's domain wins,
     *   else the first one seen; only fields of that one domain are kept (never a frame of another).
     * - Compatibility mode (browsers that don't report web content themselves): Android reads the
     *   address bar and sets the domain on that one text field, a leaf outside the page. That field
     *   is the address bar: never a login field. Its domain is the page's only when no web content
     *   reported one, and only when every such address bar agrees; the page's fields then are the
     *   ones without a domain of their own.
     */
    fun <T> collect(roots: List<StructureNode<T>>): Collected<T> {
        val found = mutableListOf<Pair<FieldInfo<T>, String?>>()
        var domain: String? = null
        var scheme: String? = null
        var focusedDomain: String? = null
        var focusedScheme: String? = null
        val urlBars = mutableListOf<Pair<String, String?>>()

        fun visit(node: StructureNode<T>, parentDomain: String?, parentScheme: String?) {
            if (!node.visible) return
            val own = node.webDomain?.takeIf { it.isNotBlank() }
            val f = node.field
            val children = node.children
            // A text field (not web content) that carries a domain of its own and has nothing under it: an address bar.
            if (own != null && f != null && f.htmlTag == null && children.isEmpty()) {
                urlBars += own to node.webScheme
                return
            }
            val nodeDomain = own ?: parentDomain
            val nodeScheme = if (own != null) node.webScheme else parentScheme
            if (nodeDomain != null && domain == null) {
                domain = nodeDomain
                scheme = nodeScheme
            }
            if (f != null) {
                found += f to nodeDomain
                if (f.focused && nodeDomain != null) {
                    focusedDomain = nodeDomain
                    focusedScheme = nodeScheme
                }
            }
            for (child in children) visit(child, nodeDomain, nodeScheme)
        }

        roots.forEach { visit(it, null, null) }
        val content = focusedDomain ?: domain
        if (content != null) {
            return Collected(content, if (focusedDomain != null) focusedScheme else scheme, found.filter { (_, d) -> d.equals(content, ignoreCase = true) }.map { it.first })
        }
        val bar = urlBars.map { it.first.lowercase() }.distinct().singleOrNull()
        if (bar != null) {
            val barScheme = urlBars.firstOrNull { it.first.equals(bar, ignoreCase = true) }?.second
            return Collected(urlBars.first().first, barScheme, found.map { it.first })
        }
        // Address bars that disagree: no domain, so a browser gets nothing.
        return Collected(null, null, found.map { it.first })
    }

    /** An [AssistStructure.ViewNode] as a [StructureNode]. */
    private class ViewNodeAdapter(private val node: AssistStructure.ViewNode) : StructureNode<AutofillId> {
        override val visible: Boolean get() = node.visibility == View.VISIBLE
        override val webDomain: String? get() = node.webDomain
        override val webScheme: String? get() = node.webScheme
        override val field: FieldInfo<AutofillId>? by lazy {
            val id = node.autofillId
            if (id == null || node.autofillType != View.AUTOFILL_TYPE_TEXT || !node.isEnabled) return@lazy null
            val html = node.htmlInfo
            val attrs = html?.attributes?.associate { it.first.lowercase() to it.second.orEmpty() }.orEmpty()
            FieldInfo(
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
                maxLength = node.maxTextLength.takeIf { it > 0 } ?: attrs["maxlength"]?.trim()?.toIntOrNull()?.takeIf { it > 0 } ?: 0,
            )
        }
        override val children: List<StructureNode<AutofillId>> get() = (0 until node.childCount).map { ViewNodeAdapter(node.getChildAt(it)) }
    }
}
