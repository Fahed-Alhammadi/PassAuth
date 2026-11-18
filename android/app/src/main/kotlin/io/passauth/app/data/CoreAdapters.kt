package io.passauth.app.data

import io.passauth.core.Account
import io.passauth.core.EmergencyKey
import io.passauth.core.EncryptedItem
import io.passauth.core.FileDecryptor
import io.passauth.core.FileEncryptor
import io.passauth.core.VaultKey
import io.passauth.core.sendDecrypt
import io.passauth.core.sendEncrypt
import io.passauth.core.sendNewKey
import io.passauth.core.sendPasswordSalt
import io.passauth.core.sendPasswordVerifier
import io.passauth.core.sendPasswordKeys
import io.passauth.core.sendEncryptV2
import io.passauth.core.sendOpen
import io.passauth.core.sendFieldVersion

/*
 * The core's handles behind the interfaces the Send, attachment and emergency flows are written
 * against (so those flows are JVM-tested with fakes). Every handle is closed by its user.
 */

class EncryptingCipher(key: String, itemId: String, attachmentId: String) : FileCipher {
    private val e = FileEncryptor(key, itemId, attachmentId)
    override fun push(chunk: ByteArray): ByteArray = e.push(chunk)
    override fun finish(): ByteArray = e.finish()
    override fun close() = e.close()
}

class DecryptingCipher(key: String, itemId: String, attachmentId: String) : FileCipher {
    private val d = FileDecryptor(key, itemId, attachmentId)
    override fun push(chunk: ByteArray): ByteArray = d.push(chunk)
    override fun finish(): ByteArray = d.finish()
    override fun close() = d.close()
}

class CoreSendCrypto(private val account: Account) : SendCrypto {
    override fun newKey(): String = sendNewKey()
    override fun encrypt(key: String, field: String, plain: String): String = sendEncrypt(key, field, plain)
    override fun decrypt(key: String, field: String, cipher: String): String = sendDecrypt(key, field, cipher)
    override fun wrap(key: String): String = account.wrapSendKey(key)
    override fun unwrap(wrapped: String): String = account.unwrapSendKey(wrapped)
    override fun passwordSalt(): String = sendPasswordSalt()
    override fun verifier(password: String, salt: String): String = sendPasswordVerifier(password, salt)
    override fun passwordKeys(password: String, salt: String, key: String): SendKeys =
        sendPasswordKeys(password, salt, key).let { SendKeys(it.verifier, it.contentKey) }
    override fun encryptV2(contentKey: String, field: String, plain: String): String = sendEncryptV2(contentKey, field, plain)
    override fun open(key: String, contentKey: String?, field: String, cipher: String): String = sendOpen(key, contentKey, field, cipher)
    override fun fieldVersion(cipher: String): Int = sendFieldVersion(cipher).toInt()
    override fun wrapContent(contentKey: String): String = account.wrapSendContentKey(contentKey)
    override fun unwrapContent(wrapped: String): String = account.unwrapSendContentKey(wrapped)
}

/** [vaultKey]: the key this app holds now for a vault of its own (null when it has none). */
class CoreEmergencyCrypto(private val account: Account, private val vaultKey: (String) -> VaultKey?) : EmergencyCrypto {
    override fun newEmergencyKey(grantId: String): NewEmergencyKeyHandle {
        val made = account.newEmergencyKey(grantId)
        return NewEmergencyKeyHandle(made.wrapped, CoreEmergencyKey(made.key, vaultKey))
    }

    override fun openEmergencyKey(grantId: String, wrapped: String): EmergencyKeyHandle =
        CoreEmergencyKey(account.openEmergencyKey(grantId, wrapped), vaultKey)

    override fun sealRoster(json: String): String = account.sealEmergencyRoster(json)
    override fun openRoster(sealed: String): String = account.openEmergencyRoster(sealed)

    override fun openSealedEmergencyKey(grantorId: String, grantId: String, sealed: String): EmergencyKeyHandle =
        CoreEmergencyKey(account.openSealedEmergencyKey(grantorId, grantId, sealed), vaultKey)
}

private class CoreEmergencyKey(private val key: EmergencyKey, private val vaultKey: (String) -> VaultKey?) : EmergencyKeyHandle {
    override fun sealFor(contactKey: String, grantorId: String, grantId: String): String = key.sealFor(contactKey, grantorId, grantId)

    override fun wrapVaultKey(vaultId: String): String {
        val vk = vaultKey(vaultId) ?: throw UserException(EmergencyClient.VAULTS_CHANGED)
        return key.wrapVaultKey(vk, vaultId)
    }

    override fun openVaultKey(vaultId: String, wrapped: String): OpenedVaultKey = CoreOpenedVaultKey(key.openVaultKey(vaultId, wrapped))

    override fun close() = key.close()
}

private class CoreOpenedVaultKey(private val key: VaultKey) : OpenedVaultKey {
    override fun decryptMeta(vaultId: String, meta: String): String = key.decryptMeta(vaultId, meta)
    override fun decryptItem(id: String, vaultId: String, key: String, data: String): String = this.key.decryptItem(EncryptedItem(id, vaultId, key, data))
    override fun manifestMatches(vaultId: String, keyEpoch: Long, manifestSeq: Long, sealed: String?, itemsJson: String): Boolean =
        this.key.manifestVerify(vaultId, keyEpoch.toULong(), manifestSeq.toULong(), sealed, null, itemsJson).status == "ok"
    override fun close() = key.close()
}
