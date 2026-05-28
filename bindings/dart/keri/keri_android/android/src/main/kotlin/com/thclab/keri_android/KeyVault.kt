package com.thclab.keri_android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Persists per-alias key material. The Ed25519 seed is encrypted under a
 * master AES-GCM key in AndroidKeyStore that requires biometric auth on every
 * use; the public key is stored alongside in cleartext for fast lookup.
 */
class KeyVault(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun hasKey(label: String): Boolean = prefs.contains(prefKey(label))

    fun listLabels(): List<String> =
        prefs.all.keys
            .filter { it.startsWith(LABEL_PREFIX) }
            .map { it.removePrefix(LABEL_PREFIX) }
            .sorted()

    fun getPublicKey(label: String): ByteArray {
        val entry = readEntry(label) ?: error("No key for label '$label'")
        return Base64.decode(entry.getString(JSON_PUB), Base64.NO_WRAP)
    }

    /** Store a freshly-generated keypair. The provided [cipher] must be biometric-unlocked
     *  and initialised in ENCRYPT_MODE; this method finalises encryption of the seed. */
    fun store(label: String, publicKey: ByteArray, seed: ByteArray, cipher: Cipher) {
        val ciphertext = cipher.doFinal(seed)
        val iv = cipher.iv
        val json = JSONObject().apply {
            put(JSON_PUB, Base64.encodeToString(publicKey, Base64.NO_WRAP))
            put(JSON_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            put(JSON_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
        }
        prefs.edit().putString(prefKey(label), json.toString()).apply()
    }

    /** Decrypt the stored seed for [label] using a biometric-unlocked DECRYPT cipher
     *  that was initialised with the stored IV. */
    fun decryptSeed(label: String, cipher: Cipher): ByteArray {
        val entry = readEntry(label) ?: error("No key for label '$label'")
        val ct = Base64.decode(entry.getString(JSON_CT), Base64.NO_WRAP)
        return cipher.doFinal(ct)
    }

    /** Read the IV for [label] so a DECRYPT cipher can be initialised before
     *  prompting the user for biometrics. */
    fun readIv(label: String): ByteArray {
        val entry = readEntry(label) ?: error("No key for label '$label'")
        return Base64.decode(entry.getString(JSON_IV), Base64.NO_WRAP)
    }

    fun delete(label: String) {
        prefs.edit().remove(prefKey(label)).apply()
    }

    /** Returns a Cipher initialised in ENCRYPT_MODE with the master key.
     *  Must be passed to BiometricPrompt before use. */
    fun newEncryptCipher(): Cipher {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        return cipher
    }

    /** Returns a Cipher initialised in DECRYPT_MODE with the master key + given IV.
     *  Must be passed to BiometricPrompt before use. */
    fun newDecryptCipher(iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher
    }

    private fun readEntry(label: String): JSONObject? =
        prefs.getString(prefKey(label), null)?.let { JSONObject(it) }

    private fun prefKey(label: String): String = "$LABEL_PREFIX$label"

    private fun masterKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        ks.getKey(MASTER_KEY_ALIAS, null)?.let { return it as SecretKey }

        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()
        )
        return kg.generateKey()
    }

    private companion object {
        const val PREFS_NAME = "keri_android_vault"
        const val LABEL_PREFIX = "key_"
        const val JSON_PUB = "pub"
        const val JSON_IV = "iv"
        const val JSON_CT = "ct"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val MASTER_KEY_ALIAS = "keri_master_v1"
        const val AES_GCM_TRANSFORM = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}
