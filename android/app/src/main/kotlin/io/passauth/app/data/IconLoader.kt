package io.passauth.app.data

import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import java.net.URLEncoder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Website icons from the user's PassAuth server (`/api/icons/{host}`), which
 * learns the website addresses but never the vault contents. Misses are cached
 * too, so a missing icon is only requested once per app run.
 */
class IconLoader(private val http: OkHttpClient) {
    private val cache = LruCache<String, Result<ImageBitmap>>(300)

    fun cached(server: String, host: String): Result<ImageBitmap>? = cache.get("$server|$host")

    suspend fun load(server: String, host: String): ImageBitmap? {
        val key = "$server|$host"
        cache.get(key)?.let { return it.getOrNull() }
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val url = "$server/api/icons/${URLEncoder.encode(host, "UTF-8")}"
                http.newCall(Request.Builder().url(url).build()).execute().use { r ->
                    check(r.isSuccessful)
                    val bytes = r.body.bytes()
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size)!!.asImageBitmap()
                }
            }
        }
        cache.put(key, result)
        return result.getOrNull()
    }
}
