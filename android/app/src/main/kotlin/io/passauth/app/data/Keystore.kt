package io.passauth.app.data

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.io.encoding.Base64

/** AES-256-GCM keys held by the Android Keystore (never exported). */
object Keystore {
    private const val PROVIDER = "AndroidKeyStore"
    private const val STORE_ALIAS = "passauth.store"
    private const val BIO_PREFIX = "passauth.bio."
    private const val TRANSFORM = "AES/GCM/NoPadding"

    private val ks: KeyStore get() = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun spec(alias: String, configure: KeyGenParameterSpec.Builder.() -> Unit = {}) =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .apply(configure)
            .build()

    private fun generate(spec: KeyGenParameterSpec): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }

    /** Key for the app's stored state (tokens, settings, cached ciphertext). */
    @Synchronized
    fun storeKey(): SecretKey =
        (ks.getKey(STORE_ALIAS, null) as SecretKey?) ?: generate(spec(STORE_ALIAS))

    /** IV (12 bytes) followed by ciphertext and tag. */
    fun encrypt(key: SecretKey, plain: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
        return c.iv + c.doFinal(plain)
    }

    fun decrypt(key: SecretKey, blob: ByteArray): ByteArray {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, 12))
        return c.doFinal(blob, 12, blob.size - 12)
    }

    // ------------------------------------------------------- biometric unlock

    /**
     * A fresh key that can only be used after a strong biometric authentication,
     * and is destroyed when biometrics change (a new fingerprint is enrolled).
     */
    fun newBiometricKey(accountId: String): SecretKey {
        deleteBiometricKey(accountId)
        return generate(spec(BIO_PREFIX + accountId) {
            setUserAuthenticationRequired(true)
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            setInvalidatedByBiometricEnrollment(true)
        })
    }

    fun biometricKey(accountId: String): SecretKey? = ks.getKey(BIO_PREFIX + accountId, null) as SecretKey?

    fun deleteBiometricKey(accountId: String) {
        runCatching { ks.deleteEntry(BIO_PREFIX + accountId) }
    }

    /** Cipher for BiometricPrompt's CryptoObject: encrypt (enable) or decrypt (unlock). */
    fun biometricCipher(key: SecretKey, sealed: Sealed? = null): Cipher =
        Cipher.getInstance(TRANSFORM).apply {
            if (sealed == null) init(Cipher.ENCRYPT_MODE, key)
            else init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Base64.decode(sealed.iv)))
        }

    fun seal(cipher: Cipher, plain: ByteArray) =
        Sealed(Base64.encode(cipher.iv), Base64.encode(cipher.doFinal(plain)))

    fun open(cipher: Cipher, sealed: Sealed): ByteArray = cipher.doFinal(Base64.decode(sealed.data))
}
