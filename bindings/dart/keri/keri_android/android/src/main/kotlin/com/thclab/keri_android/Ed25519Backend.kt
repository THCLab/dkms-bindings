package com.thclab.keri_android

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

data class Ed25519KeyMaterial(val publicKey: ByteArray, val seed: ByteArray)

/**
 * Ed25519 keygen + signing via BouncyCastle.
 *
 * BC was chosen over the JCA `Ed25519` provider that ships on API 33+ because on
 * Android 14 AndroidKeyStore registers itself as a provider for "Ed25519" and
 * intercepts plain `KeyPairGenerator.getInstance("Ed25519")` calls, then throws
 * `IllegalStateException("Not initialized")` because it expects KeyGenParameterSpec
 * setup. Pinning a provider by name (e.g. "AndroidOpenSSL") is not stable across
 * vendor builds, so BC gives us one consistent path on every API level.
 */
class Ed25519Backend {

    private val rng = SecureRandom()

    fun generateKeyPair(): Ed25519KeyMaterial {
        val priv = Ed25519PrivateKeyParameters(rng)
        val pub: Ed25519PublicKeyParameters = priv.generatePublicKey()
        return Ed25519KeyMaterial(pub.encoded, priv.encoded)
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == 32) { "Ed25519 seed must be 32 bytes" }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val signer = Ed25519Signer().apply {
            init(true, priv)
            update(message, 0, message.size)
        }
        return signer.generateSignature()
    }
}
