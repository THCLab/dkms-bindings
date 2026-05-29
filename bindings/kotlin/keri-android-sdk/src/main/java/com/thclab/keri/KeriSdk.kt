package com.thclab.keri

import com.thclab.keri.uniffi.FfiCredentialStatus
import com.thclab.keri.uniffi.FfiIdentifierConfig
import com.thclab.keri.uniffi.FfiRotationConfig
import com.thclab.keri.uniffi.FfiSignedEnvelope
import com.thclab.keri.uniffi.FfiVerifiedPayload
import com.thclab.keri.uniffi.KeriMobileSdk
import com.thclab.keri.uniffi.KeyProvider
import com.thclab.keri.uniffi.SignatureAlgo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * High-level Kotlin facade for the KERI mobile SDK.
 *
 * Wraps the UniFFI-generated [KeriMobileSdk] so callers never have to import
 * the `com.thclab.keri.uniffi` package directly. All operations that hit the
 * network or trigger a biometric prompt are `suspend` and safe to call from
 * any coroutine context.
 */
class KeriSdk private constructor(
    private val inner: KeriMobileSdk,
    @Suppress("unused") private val provider: KeyProvider,
) {

    // All UniFFI async calls are hopped to Dispatchers.IO. The generated
    // suspend funs poll the Rust future on whatever thread invoked them; if
    // that thread is Main, any host callback that needs Main (e.g. biometric
    // prompts) deadlocks because the Rust adapter blocks the polling thread
    // waiting for the foreign-callback future to complete.
    suspend fun createIdentifier(
        alias: String,
        witnessUrls: List<String>,
        watcherUrls: List<String>,
        witnessThreshold: ULong,
        algorithm: SignatureAlgo,
    ): String = withContext(Dispatchers.IO) {
        inner.createIdentifier(
            alias,
            FfiIdentifierConfig(witnessUrls, witnessThreshold, watcherUrls, algorithm),
        )
    }

    fun loadIdentifier(alias: String): String = inner.loadIdentifier(alias)
    fun listAliases(): List<String> = inner.listAliases()

    suspend fun sign(alias: String, data: ByteArray): FfiSignedEnvelope =
        withContext(Dispatchers.IO) { inner.sign(alias, data) }

    fun verify(alias: String, cesr: ByteArray): FfiVerifiedPayload =
        inner.verify(alias, cesr)

    suspend fun rotateKeys(
        alias: String,
        witnessToAdd: List<String> = emptyList(),
        witnessToRemove: List<String> = emptyList(),
        witnessThreshold: ULong,
    ) = withContext(Dispatchers.IO) {
        inner.rotateKeys(
            alias,
            FfiRotationConfig(witnessToAdd, witnessToRemove, witnessThreshold),
        )
    }

    suspend fun inceptRegistry(alias: String): String =
        withContext(Dispatchers.IO) { inner.inceptRegistry(alias) }

    suspend fun issueCredential(alias: String, credentialSaid: String) =
        withContext(Dispatchers.IO) { inner.issueCredential(alias, credentialSaid) }

    suspend fun revokeCredential(alias: String, credentialSaid: String) =
        withContext(Dispatchers.IO) { inner.revokeCredential(alias, credentialSaid) }

    suspend fun checkCredential(
        alias: String,
        registryId: String,
        credentialSaid: String,
    ): FfiCredentialStatus = withContext(Dispatchers.IO) {
        inner.checkCredential(alias, registryId, credentialSaid)
    }

    fun getCredentialStatus(alias: String, credentialSaid: String): FfiCredentialStatus =
        inner.getCredentialStatus(alias, credentialSaid)

    fun showKel(alias: String): String = inner.showKel(alias)

    fun wipe() = inner.wipe()

    companion object {
        /**
         * Open (or create) a KERI store at [dbPath] and bind the host key
         * provider. The provider must be set before any identifier operation;
         * passing it here makes registration impossible to forget.
         */
        fun open(dbPath: String, provider: KeyProvider): KeriSdk {
            val inner = KeriMobileSdk(dbPath)
            inner.registerKeyProvider(provider)
            return KeriSdk(inner, provider)
        }
    }
}
