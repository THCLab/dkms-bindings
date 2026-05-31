package com.thclab.keri.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Hardware-backed P-256 keys via AndroidKeyStore.
 *
 * The private key never leaves the secure element. `setUserAuthenticationParameters`
 * binds the key to a time-bounded biometric auth: after one successful prompt,
 * the next [TIME_BOUND_SECONDS] of signs go through silently — the validity
 * window is enforced by KeyMint, not by us.
 *
 * On `UserNotAuthenticatedException` we issue a plain `BiometricPrompt` (no
 * `CryptoObject`) which authorises *all* time-bound keys for the validity
 * window, then retry the sign.
 */
class NativeP256Backend : KeystoreBackend {

    override val algorithm: String = "EcdsaSecp256r1"

    override fun createKey(
        activity: FragmentActivity,
        label: String,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        try {
            val alias = ksAlias(label)
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE,
            )
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        TIME_BOUND_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG,
                    )
                    .setInvalidatedByBiometricEnrollment(true)
                    .build()
            )
            val kp = kpg.generateKeyPair()
            onSuccess(compressedPublicKey(kp.public as ECPublicKey))
        } catch (e: Exception) {
            onError(e.message ?: "P-256 keygen failed")
        }
    }

    override fun getPublicKey(label: String): ByteArray {
        val ks = openKeystore()
        val cert = ks.getCertificate(ksAlias(label))
            ?: error("No P-256 key for label '$label'")
        return compressedPublicKey(cert.publicKey as ECPublicKey)
    }

    override fun sign(
        activity: FragmentActivity,
        label: String,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val priv = try {
            (openKeystore().getKey(ksAlias(label), null) as? PrivateKey)
                ?: return onError("No P-256 key for label '$label'")
        } catch (e: Exception) {
            return onError(e.message ?: "Cannot load P-256 key")
        }

        try {
            onSuccess(doSign(priv, message))
        } catch (_: UserNotAuthenticatedException) {
            promptThenRetry(activity, priv, message, onSuccess, onError)
        } catch (e: Exception) {
            onError(e.message ?: "Signing failed")
        }
    }

    override fun deleteKey(label: String) {
        try { openKeystore().deleteEntry(ksAlias(label)) } catch (_: Exception) { /* idempotent */ }
    }

    override fun listLabels(): List<String> {
        val ks = openKeystore()
        val result = mutableListOf<String>()
        val enumeration = ks.aliases()
        while (enumeration.hasMoreElements()) {
            val a = enumeration.nextElement()
            if (a.startsWith(LABEL_PREFIX)) result.add(a.removePrefix(LABEL_PREFIX))
        }
        return result.sorted()
    }

    private fun promptThenRetry(
        activity: FragmentActivity,
        priv: PrivateKey,
        message: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign with KERI key (P-256)")
            .setSubtitle("Authenticate to unlock signing for $TIME_BOUND_SECONDS s")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val cb = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                try {
                    onSuccess(doSign(priv, message))
                } catch (e: Exception) {
                    onError(e.message ?: "Signing failed after auth")
                }
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                onError("Biometric error $code: $msg")
            }
        }
        // No CryptoObject — authorises every time-bound key for the validity window.
        BiometricPrompt(activity, executor, cb).authenticate(info)
    }

    private fun doSign(priv: PrivateKey, message: ByteArray): ByteArray {
        // AndroidKeyStore reliably implements "SHA256withECDSA" but not
        // "SHA256withECDSAinP1363Format" across all OEMs. Sign in DER and
        // convert to the IEEE P1363 raw R||S form (64 bytes) that keri-core
        // expects for P-256, matching the p256 crate's `Signature::as_ref()`.
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(priv)
        sig.update(message)
        return derEcdsaToP1363(sig.sign(), 32)
    }

    /**
     * Convert `SEQUENCE { INTEGER r, INTEGER s }` (ECDSA DER) into a
     * fixed-width `r || s` of `2 * componentSize` bytes. ASN.1 INTEGERs are
     * big-endian, two's-complement, may have a leading 0x00 to keep them
     * non-negative; we strip that and left-pad to `componentSize`.
     */
    private fun derEcdsaToP1363(der: ByteArray, componentSize: Int): ByteArray {
        var i = 0
        require(der[i++].toInt() == 0x30) { "ECDSA DER: not a SEQUENCE" }
        // Length octet — short form expected for ECDSA P-256/P-384 sizes.
        val seqLen = readDerLength(der, i).also { i += it.second }.first
        require(seqLen <= der.size - i) { "ECDSA DER: truncated SEQUENCE" }

        require(der[i++].toInt() == 0x02) { "ECDSA DER: expected INTEGER for r" }
        val rLen = readDerLength(der, i).also { i += it.second }.first
        val r = der.copyOfRange(i, i + rLen); i += rLen

        require(der[i++].toInt() == 0x02) { "ECDSA DER: expected INTEGER for s" }
        val sLen = readDerLength(der, i).also { i += it.second }.first
        val s = der.copyOfRange(i, i + sLen); i += sLen

        return stripAndPad(r, componentSize) + stripAndPad(s, componentSize)
    }

    /** Returns (length, octetsConsumed) for a DER length field starting at [offset]. */
    private fun readDerLength(buf: ByteArray, offset: Int): Pair<Int, Int> {
        val first = buf[offset].toInt() and 0xff
        if (first < 0x80) return first to 1
        val n = first and 0x7f
        var len = 0
        for (k in 1..n) len = (len shl 8) or (buf[offset + k].toInt() and 0xff)
        return len to (1 + n)
    }

    private fun stripAndPad(raw: ByteArray, target: Int): ByteArray {
        // Drop leading zero sign byte if present.
        val trimmed = if (raw.isNotEmpty() && raw[0] == 0.toByte() && raw.size > 1) {
            raw.copyOfRange(1, raw.size)
        } else raw
        return when {
            trimmed.size == target -> trimmed
            trimmed.size < target -> ByteArray(target - trimmed.size) + trimmed
            else -> error("ECDSA component too large: ${trimmed.size} > $target")
        }
    }

    /** SEC1 compressed point: 33 bytes, 0x02/0x03 prefix + 32-byte X (big-endian). */
    private fun compressedPublicKey(pub: ECPublicKey): ByteArray {
        val w = pub.w
        val xBytes = unsignedBigEndian(w.affineX, 32)
        val prefix: Byte = if (w.affineY.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + xBytes
    }

    private fun unsignedBigEndian(n: BigInteger, size: Int): ByteArray {
        val raw = n.toByteArray()
        // BigInteger.toByteArray may include a leading zero sign byte
        // or be shorter than `size`; normalise to fixed-width big-endian.
        return when {
            raw.size == size -> raw
            raw.size == size + 1 && raw[0] == 0.toByte() -> raw.copyOfRange(1, raw.size)
            raw.size < size -> ByteArray(size - raw.size) + raw
            else -> error("BigInteger ${raw.size} bytes does not fit in $size")
        }
    }

    private fun openKeystore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun ksAlias(label: String): String = LABEL_PREFIX + label

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val LABEL_PREFIX = "keri_p256_"
        // After one successful biometric, KeyMint authorises the
        // key for this many seconds. Bumped from 10s to 5 min so
        // interactive flows (message compose → send, KERI rotation
        // wizards) don't re-prompt while the user is still in the
        // same task. The hardware enforces the bound; we cannot
        // extend it further without re-prompting.
        const val TIME_BOUND_SECONDS = 300
    }
}
