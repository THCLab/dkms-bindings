package com.thclab.keri

import com.thclab.keri.uniffi.FfiCredentialStatus
import com.thclab.keri.uniffi.FfiDelegationConfig
import com.thclab.keri.uniffi.FfiDelegationRequest
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

    /**
     * Joiner side of an out-of-band delegated-AID pairing.
     *
     * Step 1 — ingest the delegator's KEL bytes (the QR invite carries
     * them inline) so the delegator's seal can be validated locally
     * later. Must be preceded by [requestDelegation] which mints the
     * alias.
     */
    suspend fun importDelegatorKel(alias: String, kelCesr: String) =
        withContext(Dispatchers.IO) { inner.importDelegatorKel(alias, kelCesr) }

    /**
     * Step 2 — mint a delegated AID under [alias] delegated by
     * [delegatorAid]. Returns the delegated prefix and the CESR `dip`
     * event for out-of-band transport to the delegator.
     *
     * Witness lists are typically empty for QR-based pairings — the
     * primary device carries the full KEL inside the invite, so no
     * witness round-trip is needed during the exchange.
     */
    suspend fun requestDelegation(
        alias: String,
        delegatorAid: String,
        witnessUrls: List<String> = emptyList(),
        witnessThreshold: ULong = 0u,
        algorithm: SignatureAlgo,
    ): FfiDelegationRequest = withContext(Dispatchers.IO) {
        inner.requestDelegation(
            alias,
            FfiDelegationConfig(delegatorAid, witnessUrls, witnessThreshold, algorithm),
        )
    }

    /**
     * Step 3 — apply the delegator's signed `ixn` (CESR) returned by
     * the primary to the alias's escrowed `dip`, finalising the
     * delegated AID.
     */
    suspend fun finalizeDelegation(alias: String, delegatorSealCesr: String) =
        withContext(Dispatchers.IO) { inner.finalizeDelegation(alias, delegatorSealCesr) }

    /**
     * Atomic combo of [requestDelegation] + [importDelegatorKel] so
     * the redb on `<alias>/db` stays open under one Controller for
     * both phases. Use this in QR-pairing flows where the two
     * operations would otherwise happen across separate FFI calls
     * and race on the redb in-process lock registry.
     */
    suspend fun requestDelegationWithKel(
        alias: String,
        delegatorAid: String,
        delegatorKelCesr: String,
        witnessUrls: List<String> = emptyList(),
        witnessThreshold: ULong = 0u,
        algorithm: SignatureAlgo,
    ): FfiDelegationRequest = withContext(Dispatchers.IO) {
        inner.requestDelegationWithKel(
            alias,
            FfiDelegationConfig(delegatorAid, witnessUrls, witnessThreshold, algorithm),
            delegatorKelCesr,
        )
    }

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
