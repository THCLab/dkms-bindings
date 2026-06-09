package com.thclab.keri

import com.thclab.keri.uniffi.FfiCredentialStatus
import com.thclab.keri.uniffi.FfiDelegationConfig
import com.thclab.keri.uniffi.FfiDelegationRequest
import com.thclab.keri.uniffi.FfiGroupRotationConfig
import com.thclab.keri.uniffi.FfiIdentifierConfig
import com.thclab.keri.uniffi.FfiKelHead
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

    /**
     * Drive a KEL rotation event on a multi-sig group AID this alias
     * is a signing member of. Used by the device-removal flow to drop
     * a device's key from the group's signers.
     *
     * For a 1-of-N group this completes on the acting member's
     * signature alone. For k-of-N (k >= 2) the surviving co-signers
     * must independently trigger the same rotation; witnesses collect
     * the signatures.
     */
    suspend fun rotateGroup(
        alias: String,
        groupAid: String,
        newParticipants: List<String>,
        newSignatureThreshold: ULong,
        newNextThreshold: ULong? = null,
        witnessToAdd: List<String> = emptyList(),
        witnessToRemove: List<String> = emptyList(),
        witnessThreshold: ULong? = null,
    ) = withContext(Dispatchers.IO) {
        inner.rotateGroup(
            alias,
            groupAid,
            FfiGroupRotationConfig(
                newParticipants,
                newSignatureThreshold,
                newNextThreshold,
                witnessToAdd,
                witnessToRemove,
                witnessThreshold,
            ),
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
     * Publish a finalised delegated AID's `dip` to its witnesses so a
     * remote watcher can fetch the KEL. The out-of-band pairing flow
     * completes the `dip` locally only; without this a third party
     * resolving the AID through a watcher gets `KELNotFound`. Call
     * after [finalizeDelegation]. Requires the AID to have been minted
     * with witnesses and the delegator KEL to be present locally.
     */
    suspend fun publishDelegationToWitnesses(alias: String, delegatorAid: String) =
        withContext(Dispatchers.IO) { inner.publishDelegationToWitnesses(alias, delegatorAid) }

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

    /**
     * Export the CESR-encoded KEL for `aid`, read from `viaAlias`'s
     * redb. Used by higher-level callers (cyfron-core / cyfron-mobile-ffi)
     * that want to parse the byte stream into a human-readable event
     * summary for a UI. Throws when no KEL is stored locally for `aid`
     * under `viaAlias`.
     */
    fun exportKelCesrFor(viaAlias: String, aid: String): ByteArray =
        inner.exportKelCesrFor(viaAlias, aid)

    // ── Watcher / KEL discovery surface ─────────────────────────────
    //
    // These mirror cyfron_core::keri::KeriController's same-named methods
    // so messaging code that runs in-process on the phone produces the
    // same wire output as the desktop daemon.

    /**
     * LocationScheme JSON strings for the witnesses configured for
     * `alias`, in creation order. Each element is a JSON object
     * `{eid, scheme, url}` — the OOBI-array element shape mesagkesto
     * register/authenticate expect.
     */
    fun listWitnesses(alias: String): List<String> = inner.listWitnesses(alias)

    /** AID prefixes of the watchers configured for `alias`. */
    fun listWatchers(alias: String): List<String> = inner.listWatchers(alias)

    /**
     * LocationScheme JSON strings for the watchers configured for
     * `alias`, in authorisation order. Each entry is a JSON object
     * `{eid, scheme, url}` — same shape as [listWitnesses]. Empty for
     * aliases that pre-date watcher persistence.
     */
    fun listWatcherLocations(alias: String): List<String> =
        inner.listWatcherLocations(alias)

    /** Whether `alias` has at least one watcher. Auth gates on this. */
    fun hasWatcher(alias: String): Boolean = inner.hasWatcher(alias)

    /**
     * Authorise an additional watcher for `alias` post-creation.
     * Resolves the OOBI at `watcherUrl`, signs the end-role reply, and
     * appends the LocationScheme to the persisted list so subsequent
     * [listWatcherLocations] calls reflect it.
     */
    suspend fun addWatcher(alias: String, watcherUrl: String) =
        withContext(Dispatchers.IO) { inner.addWatcher(alias, watcherUrl) }

    /**
     * Drop a watcher from `alias`'s persisted list, identified by
     * `watcherEid` (the EID field of its LocationScheme). Config-layer
     * remove only — the device stops querying it and
     * [listWatcherLocations] no longer includes it. Idempotent: a no-op
     * if no entry with that EID is present.
     */
    fun removeWatcher(alias: String, watcherEid: String) =
        inner.removeWatcher(alias, watcherEid)

    /** (sn, said) of the latest KEL event known for `aid` under `viaAlias`. */
    fun kelHead(viaAlias: String, aid: String): FfiKelHead? =
        inner.kelHead(viaAlias, aid)

    /**
     * Ask `viaAlias`'s watcher(s) to refresh and import `targetAid`'s KEL.
     * Returns only after a watcher responded and a KEL is stored locally.
     */
    suspend fun queryKelFor(viaAlias: String, targetAid: String) =
        withContext(Dispatchers.IO) { inner.queryKelFor(viaAlias, targetAid) }

    /**
     * Record an OOBI in `viaAlias`'s local controller. Accepts a
     * LocationScheme JSON (`{eid, scheme, url}`) or an EndRole JSON
     * (`{cid, eid, role}`). First step of the cyfron peer-onboarding
     * chain: resolveOobi → sendOobiToWatcher → queryKelFor.
     */
    suspend fun resolveOobi(viaAlias: String, oobiJson: String) =
        withContext(Dispatchers.IO) { inner.resolveOobi(viaAlias, oobiJson) }

    /**
     * Push an OOBI to `viaAlias`'s authorised watcher so the watcher
     * can fetch / verify the referenced KEL on demand. Without this
     * step `queryKelFor` returns `InvalidSignature` (the watcher
     * can't validate a KEL it never fetched).
     */
    suspend fun sendOobiToWatcher(viaAlias: String, oobiJson: String) =
        withContext(Dispatchers.IO) { inner.sendOobiToWatcher(viaAlias, oobiJson) }

    /**
     * Sign `json` and return mesagkesto's expected wire form
     * `<JSON_payload><CESR_signatures>` concatenated. Payload is the
     * exact bytes the caller passed in — no `{"p":…}` envelope.
     */
    suspend fun signToCesr(alias: String, json: String): String =
        withContext(Dispatchers.IO) { inner.signToCesr(alias, json) }

    fun wipe() = inner.wipe()

    /**
     * Delete a single identifier (recursively forgets `<db>/<alias>`).
     * Use to roll back a half-minted delegated AID when a device-join
     * fails before completion so retries don't pile up orphans.
     */
    fun deleteIdentifier(alias: String) = inner.deleteIdentifier(alias)

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
