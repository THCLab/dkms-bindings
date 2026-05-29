package com.thclab.keri.keystore

import android.content.Context
import androidx.fragment.app.FragmentActivity

/**
 * Algo-aware router. `createKey(label, algo)` records the chosen algorithm in
 * a SharedPreferences index so subsequent `sign`/`getPublicKey`/`deleteKey`
 * calls (which arrive with just a label) know which backend owns the secret.
 *
 * Two backends are wired:
 *   - "Ed25519"        → [BouncyCastleEd25519Backend] (software, seed-wrap)
 *   - "EcdsaSecp256r1" → [NativeP256Backend] (hardware AndroidKeyStore)
 */
class KeriKeyProvider(context: Context) {

    private val appContext: Context = context.applicationContext
    private val index = appContext.getSharedPreferences(INDEX_PREFS, Context.MODE_PRIVATE)

    private val backends: Map<String, KeystoreBackend> = mapOf(
        "Ed25519" to BouncyCastleEd25519Backend(appContext),
        "EcdsaSecp256r1" to NativeP256Backend(),
    )

    fun createKey(
        activity: FragmentActivity,
        label: String,
        algo: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val backend = backends[algo]
            ?: return onError("Unknown algorithm '$algo'")
        backend.createKey(activity, label, { pub ->
            // Record only after the backend confirmed creation, so a failed
            // biometric doesn't leave a dangling index entry.
            index.edit().putString(label, algo).apply()
            onSuccess(pub)
        }, onError)
    }

    fun getPublicKey(label: String): ByteArray =
        backendForLabel(label).getPublicKey(label)

    fun getPublicKeyWithAlgo(label: String): Pair<ByteArray, String> {
        val algo = index.getString(label, null)
            ?: error("No registered backend for label '$label'")
        val backend = backends[algo]
            ?: error("Index references missing backend '$algo' for label '$label'")
        return backend.getPublicKey(label) to algo
    }

    fun sign(
        activity: FragmentActivity,
        label: String,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val backend = try { backendForLabel(label) }
        catch (e: Exception) { return onError(e.message ?: "unknown label '$label'") }
        backend.sign(activity, label, message, onSuccess, onError)
    }

    fun deleteKey(label: String) {
        try { backendForLabel(label).deleteKey(label) } catch (_: Exception) { /* idempotent */ }
        index.edit().remove(label).apply()
    }

    /**
     * Returns every label tracked in the index. Backend-side enumeration is
     * not consulted because the index is the source of truth: a label only
     * gets recorded after createKey succeeds.
     */
    fun listKeys(): List<String> = index.all.keys.sorted()

    private fun backendForLabel(label: String): KeystoreBackend {
        val algo = index.getString(label, null)
            ?: error("No registered backend for label '$label'")
        return backends[algo]
            ?: error("Index references missing backend '$algo' for label '$label'")
    }

    private companion object {
        const val INDEX_PREFS = "keri_label_algorithm_index"
    }
}
