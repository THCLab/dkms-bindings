package com.thclab.keri_android

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.ConcurrentHashMap

/**
 * Software Ed25519 keys whose seeds are encrypted under an AndroidKeyStore
 * AES-GCM master key. A short-lived in-memory cache holds the decrypted seed
 * so a burst of sign calls (KERI inception / rotation involves several) only
 * triggers one biometric prompt.
 */
class BouncyCastleEd25519Backend(
    context: Context,
    private val ttlMillis: Long = 10_000,
) : KeystoreBackend {

    override val algorithm: String = "Ed25519"

    private val ed25519: Ed25519Backend = Ed25519Backend()
    private val vault: KeyVault = KeyVault(context.applicationContext)
    private val cache = SeedCache(ttlMillis)

    override fun createKey(
        activity: FragmentActivity,
        label: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        if (vault.hasKey(label)) { onError("Key '$label' already exists"); return }
        val material = ed25519.generateKeyPair()
        val cipher = vault.newEncryptCipher()
        BiometricHelper(activity).authenticate(
            cipher,
            title = "Create KERI key (Ed25519)",
            subtitle = "Authenticate to store '$label' securely",
            onSuccess = { unlocked ->
                try {
                    vault.store(label, material.publicKey, material.seed, unlocked)
                    cache.put(label, material.seed.copyOf())
                    onSuccess(material.publicKey)
                } catch (e: Exception) {
                    onError(e.message ?: "Failed to store key")
                } finally {
                    zeroize(material.seed)
                }
            },
            onError = { msg -> zeroize(material.seed); onError(msg) },
        )
    }

    override fun getPublicKey(label: String): ByteArray = vault.getPublicKey(label)

    override fun sign(
        activity: FragmentActivity,
        label: String,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        cache.get(label)?.let { cached ->
            try { onSuccess(ed25519.sign(cached, message)) }
            catch (e: Exception) { onError(e.message ?: "Signing failed (cached)") }
            return
        }
        if (!vault.hasKey(label)) { onError("No key for label '$label'"); return }
        val iv = vault.readIv(label)
        val cipher = vault.newDecryptCipher(iv)
        BiometricHelper(activity).authenticate(
            cipher,
            title = "Sign with KERI key (Ed25519)",
            subtitle = "Authenticate to sign with '$label'",
            onSuccess = { unlocked ->
                var seed: ByteArray? = null
                try {
                    seed = vault.decryptSeed(label, unlocked)
                    cache.put(label, seed.copyOf())
                    onSuccess(ed25519.sign(seed, message))
                } catch (e: Exception) {
                    onError(e.message ?: "Signing failed")
                } finally {
                    seed?.let { zeroize(it) }
                }
            },
            onError = onError,
        )
    }

    override fun deleteKey(label: String) {
        cache.invalidate(label)
        vault.delete(label)
    }

    override fun listLabels(): List<String> = vault.listLabels()

    private fun zeroize(bytes: ByteArray) { for (i in bytes.indices) bytes[i] = 0 }
}

/** Per-label seed cache that zeroes its entries after [ttlMillis]. */
private class SeedCache(private val ttlMillis: Long) {
    private val entries = ConcurrentHashMap<String, ByteArray>()
    private val handler = Handler(Looper.getMainLooper())

    fun get(label: String): ByteArray? = entries[label]

    fun put(label: String, seed: ByteArray) {
        entries.put(label, seed)?.let { prev ->
            for (i in prev.indices) prev[i] = 0
        }
        handler.postDelayed({ invalidate(label) }, ttlMillis)
    }

    fun invalidate(label: String) {
        entries.remove(label)?.let { seed ->
            for (i in seed.indices) seed[i] = 0
        }
    }
}
