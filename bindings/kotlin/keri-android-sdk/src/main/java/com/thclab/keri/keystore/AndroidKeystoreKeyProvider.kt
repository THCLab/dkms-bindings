package com.thclab.keri.keystore

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.thclab.keri.uniffi.KeyProvider
import com.thclab.keri.uniffi.KeyProviderException
import com.thclab.keri.uniffi.PublicKey
import com.thclab.keri.uniffi.SignatureAlgo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * UniFFI [KeyProvider] implementation that delegates to [KeriKeyProvider] —
 * the same Android Keystore + biometric backends used by the Flutter plugin,
 * exposed here as suspend functions Rust can drive natively.
 *
 * The activity is supplied late (via [activityProvider]) because biometric
 * prompts need a `FragmentActivity`, while the SDK is typically owned by a
 * `ViewModel`. Callers should clear the reference on `onDestroy`.
 */
class AndroidKeystoreKeyProvider(
    context: Context,
    private val activityProvider: () -> FragmentActivity?,
) : KeyProvider {

    /**
     * Direct access to the underlying keystore. Exposes the same five
     * primitives Rust calls into, useful for demo / diagnostics screens
     * (e.g. exercising the Android Keystore without going through the
     * full KERI identifier lifecycle).
     */
    val keystore = KeriKeyProvider(context)
    private val inner get() = keystore

    private fun requireActivity(): FragmentActivity =
        activityProvider()
            ?: throw KeyProviderException.Backend(
                "no FragmentActivity bound; cannot show biometric prompt"
            )

    override suspend fun createKey(label: String, algorithm: SignatureAlgo): PublicKey =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                inner.createKey(
                    requireActivity(),
                    label,
                    algorithm.toLabel(),
                    onSuccess = { bytes -> cont.resume(PublicKey(bytes, algorithm)) },
                    onError = { msg -> cont.resumeWithException(KeyProviderException.Backend(msg)) },
                )
            }
        }

    override suspend fun openKey(label: String): PublicKey {
        val (bytes, algoStr) = inner.getPublicKeyWithAlgo(label)
        return PublicKey(bytes, algoStr.fromLabel())
    }

    override suspend fun sign(label: String, message: ByteArray): ByteArray =
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { cont ->
                inner.sign(
                    requireActivity(),
                    label,
                    message,
                    onSuccess = { cont.resume(it) },
                    onError = { msg ->
                        cont.resumeWithException(KeyProviderException.AuthFailed(msg))
                    },
                )
            }
        }

    override suspend fun deleteKey(label: String) {
        inner.deleteKey(label)
    }

    override suspend fun listKeys(): List<String> = inner.listKeys()
}

private fun SignatureAlgo.toLabel(): String = when (this) {
    SignatureAlgo.ED25519 -> "Ed25519"
    SignatureAlgo.ECDSA_SECP256K1 -> "EcdsaSecp256k1"
    SignatureAlgo.ECDSA_SECP256R1 -> "EcdsaSecp256r1"
}

private fun String.fromLabel(): SignatureAlgo = when (this) {
    "Ed25519" -> SignatureAlgo.ED25519
    "EcdsaSecp256k1" -> SignatureAlgo.ECDSA_SECP256K1
    "EcdsaSecp256r1", "P256" -> SignatureAlgo.ECDSA_SECP256R1
    else -> error("unknown algorithm label '$this'")
}
