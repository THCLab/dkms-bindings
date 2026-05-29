package com.thclab.keri.keystore

import androidx.fragment.app.FragmentActivity

/**
 * Algorithm-agnostic contract the [KeriKeyProvider] router calls into.
 *
 * Two concrete backends:
 *   - [BouncyCastleEd25519Backend] — software Ed25519 with the seed wrapped
 *     under an AndroidKeyStore-backed AES-GCM master key (biometric-gated).
 *   - [NativeP256Backend] — hardware P-256 in AndroidKeyStore directly, with
 *     time-bound biometric auth (no software seed exists).
 *
 * Both expose async create/sign because either may need a biometric prompt;
 * the cheap reads (publicKey/list/delete) stay synchronous.
 */
interface KeystoreBackend {
    val algorithm: String

    fun createKey(
        activity: FragmentActivity,
        label: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    )

    fun getPublicKey(label: String): ByteArray

    fun sign(
        activity: FragmentActivity,
        label: String,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    )

    fun deleteKey(label: String)

    fun listLabels(): List<String>
}
