/**
 * The Firebase settings of one Android app from a `google-services.json` file (Firebase console →
 * Project settings → Your apps), for sign-in request notifications (FCM). The file is never
 * committed (it stays in `Keys/`; CI writes it from the `GOOGLE_SERVICES_JSON` secret); the build
 * reads `android/app/google-services.json` when it exists and puts the client whose package name
 * is the variant's applicationId into BuildConfig. Without the file (or without a matching
 * client) the fields are empty and the app doesn't offer notifications.
 *
 * No google-services Gradle plugin: it would also generate resources and wire analytics.
 *
 * Shared by the Gradle build (buildSrc) and the app's unit tests; keep it plain Kotlin.
 */
data class FirebaseClientConfig(
    /** `client_info.mobilesdk_app_id` ("1:<number>:android:<hex>"). */
    val appId: String,
    /** `api_key[0].current_key`. */
    val apiKey: String,
    /** `project_info.project_id`. */
    val projectId: String,
    /** `project_info.project_number`: the FCM sender id. */
    val senderId: String,
) {
    companion object {
        /** The client for [packageName] in a `google-services.json` text; null when there is none or the file is incomplete. */
        fun parse(json: String, packageName: String): FirebaseClientConfig? {
            val root = MiniJson.parse(json) as? Map<*, *> ?: return null
            val project = root["project_info"] as? Map<*, *> ?: return null
            val projectId = project["project_id"] as? String ?: return null
            val senderId = project["project_number"] as? String ?: return null
            val clients = root["client"] as? List<*> ?: return null
            for (c in clients) {
                val client = c as? Map<*, *> ?: continue
                val info = client["client_info"] as? Map<*, *> ?: continue
                val pkg = (info["android_client_info"] as? Map<*, *>)?.get("package_name") as? String
                if (pkg != packageName) continue
                val appId = info["mobilesdk_app_id"] as? String ?: return null
                val apiKey = ((client["api_key"] as? List<*>)?.firstOrNull() as? Map<*, *>)?.get("current_key") as? String ?: return null
                val config = FirebaseClientConfig(appId, apiKey, projectId, senderId)
                return config.takeIf { it.complete }
            }
            return null
        }

        /** A Java string literal for a BuildConfig field. */
        fun literal(value: String): String = buildString {
            append('"')
            for (ch in value) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\n' -> append("\\n")
                    else -> if (ch < ' ') append("\\u%04x".format(ch.code)) else append(ch)
                }
            }
            append('"')
        }
    }

    private val complete: Boolean
        get() = listOf(appId, apiKey, projectId, senderId).all { it.isNotBlank() && it.none(Char::isWhitespace) }

    override fun toString() = "FirebaseClientConfig($appId, $projectId)"
}

/** A small JSON reader (objects → Map, arrays → List, strings, numbers as their text, booleans, null). */
internal class MiniJson private constructor(private val s: String) {
    private var i = 0

    companion object {
        fun parse(text: String): Any? = try {
            MiniJson(text).run {
                val v = value()
                space()
                if (i != s.length) null else v
            }
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: IndexOutOfBoundsException) {
            null
        }
    }

    private fun space() {
        while (i < s.length && s[i].isWhitespace()) i++
    }

    private fun value(): Any? {
        space()
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> word("true", true)
            'f' -> word("false", false)
            'n' -> word("null", null)
            else -> if (c == '-' || c.isDigit()) num() else throw IllegalArgumentException("unexpected $c")
        }
    }

    private fun word(w: String, v: Any?): Any? {
        require(s.startsWith(w, i)) { "bad literal" }
        i += w.length
        return v
    }

    private fun num(): String {
        val start = i
        while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
        return s.substring(start, i)
    }

    private fun str(): String {
        i++ // "
        val out = StringBuilder()
        while (true) {
            val c = s[i++]
            when (c) {
                '"' -> return out.toString()
                '\\' -> when (val e = s[i++]) {
                    'n' -> out.append('\n')
                    't' -> out.append('\t')
                    'r' -> out.append('\r')
                    'b' -> out.append('\b')
                    'f' -> out.append('\u000c')
                    'u' -> {
                        out.append(s.substring(i, i + 4).toInt(16).toChar())
                        i += 4
                    }
                    else -> out.append(e)
                }
                else -> out.append(c)
            }
        }
    }

    private fun obj(): Map<String, Any?> {
        i++ // {
        val out = LinkedHashMap<String, Any?>()
        space()
        if (s[i] == '}') {
            i++
            return out
        }
        while (true) {
            space()
            require(s[i] == '"') { "key expected" }
            val k = str()
            space()
            require(s[i++] == ':') { ": expected" }
            out[k] = value()
            space()
            when (s[i++]) {
                ',' -> continue
                '}' -> return out
                else -> throw IllegalArgumentException(", or } expected")
            }
        }
    }

    private fun arr(): List<Any?> {
        i++ // [
        val out = ArrayList<Any?>()
        space()
        if (s[i] == ']') {
            i++
            return out
        }
        while (true) {
            out.add(value())
            space()
            when (s[i++]) {
                ',' -> continue
                ']' -> return out
                else -> throw IllegalArgumentException(", or ] expected")
            }
        }
    }
}
