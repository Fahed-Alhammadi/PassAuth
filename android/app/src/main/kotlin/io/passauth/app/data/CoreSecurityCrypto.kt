package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.CoreException
import io.passauth.core.MasterKeys
import io.passauth.core.NewAccount
import io.passauth.core.deriveMasterKeys
import io.passauth.core.opaqueLoginFinish
import io.passauth.core.opaqueLoginStart
import io.passauth.core.opaqueRegisterFinish
import io.passauth.core.opaqueRegisterStart
import kotlinx.serialization.json.JsonObject

/**
 * [SecurityCrypto] with the Rust core. [account] is the unlocked account (needed to
 * re-wrap its key); every handle is destroyed when its step is closed.
 * Callers run it off the main thread (Argon2id).
 */
class CoreSecurityCrypto(private val account: Account?) : SecurityCrypto {
    override fun loginProof(password: String, secretKey: String?, prelogin: JsonObject): LoginProof {
        val skRequired = prelogin.bool("secret_key_required")
        val master = deriveMasterKeys(password, secretKey, prelogin.str("account_id"), prelogin["kdf"].toString(), skRequired)
        val start = try {
            opaqueLoginStart(master)
        } catch (e: Exception) {
            master.destroy()
            throw e
        }
        return object : LoginProof {
            override val message = start.message

            override fun finish(serverMessage: String): String = try {
                opaqueLoginFinish(start.state, master, serverMessage)
            } catch (_: CoreException) {
                throw UserException("Wrong master password or Secret Key.")
            }

            override fun close() {
                start.state.fill(0)
                master.destroy()
            }
        }
    }

    override fun rewrap(bundleJson: String, newPassword: String, withSecretKey: Boolean, existingSecretKey: String?): Rewrapped {
        val unlocked = account ?: throw UserException("Unlock your vault first.")
        val next: NewAccount = unlocked.rewrap(bundleJson, newPassword, withSecretKey, existingSecretKey)
        return CoreRewrapped(next)
    }
}

private class CoreRewrapped(private val next: NewAccount) : Rewrapped {
    private val master: MasterKeys get() = next.master
    private var state: ByteArray? = null

    override val bundleJson: String get() = next.bundleJson
    override val secretKey: String? get() = next.secretKey

    override fun registerStart(): String {
        val start = opaqueRegisterStart(master)
        state = start.state
        return start.message
    }

    override fun registerFinish(serverMessage: String): String {
        val s = state ?: error("registerStart first")
        return opaqueRegisterFinish(s, master, serverMessage)
    }

    override fun close() {
        state?.fill(0)
        state = null
        // The new handles: the session keeps using its own Account (same keys).
        next.destroy()
    }
}
