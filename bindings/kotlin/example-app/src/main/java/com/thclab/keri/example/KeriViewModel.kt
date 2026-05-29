package com.thclab.keri.example

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.thclab.keri.KeriSdk
import com.thclab.keri.keystore.AndroidKeystoreKeyProvider
import com.thclab.keri.uniffi.SignatureAlgo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val IDENT_ALIAS = "alice"
private const val TEST_KEY_LABEL = "demo"

private val DEFAULT_WITNESSES = listOf(
    "https://witness1.dkms.colossi.network",
    "https://witness2.dkms.colossi.network",
    "https://witness3.dkms.colossi.network",
)

/** Snapshot of the smoke test screen mirroring the Dart `_SmokeTestPageState`. */
data class SmokeState(
    val algorithm: SignatureAlgo = SignatureAlgo.ED25519,
    val algorithmLabel: String = "Ed25519 (software)",

    val bootStatus: String = "not initialised",
    val rustStatus: String = "idle",
    val keystoreStatus: String = "idle",
    val identStatus: String = "idle",
    val rotateStatus: String = "idle",
    val wipeStatus: String = "idle",
    val kelStatus: String = "idle",

    val witnessUrls: List<String> = DEFAULT_WITNESSES,
    val witnessThreshold: String = "1",

    val rustAliases: List<String> = emptyList(),
    val keystoreLabels: List<String> = emptyList(),

    val lastPublicKey: ByteArray? = null,
    val lastSignature: ByteArray? = null,
    val lastAid: String? = null,

    /** When non-null, the smoke screen pops a modal dialog with this text. */
    val kelDump: String? = null,
) {
    // Generated equals/hashCode for ByteArray fields is broken; we never
    // compare instances for equality so leave the defaults.
}

class KeriViewModel(app: Application) : AndroidViewModel(app) {

    private val provider = AndroidKeystoreKeyProvider(
        context = app,
        activityProvider = { MainActivity.current },
    )

    // Lazily created on first use so users can hit "Wipe" before booting.
    private var sdk: KeriSdk? = null
    private val dbPath: String = File(app.filesDir, "keri-db").absolutePath

    private val _state = MutableStateFlow(SmokeState())
    val state: StateFlow<SmokeState> = _state.asStateFlow()

    // ----- setup -----

    fun setAlgorithm(algo: SignatureAlgo, label: String) {
        _state.update { it.copy(algorithm = algo, algorithmLabel = label) }
    }

    fun setWitnessUrl(index: Int, url: String) {
        _state.update {
            val updated = it.witnessUrls.toMutableList()
            if (index in updated.indices) updated[index] = url
            it.copy(witnessUrls = updated)
        }
    }

    fun addWitnessField() {
        _state.update { it.copy(witnessUrls = it.witnessUrls + "") }
    }

    fun removeWitnessField(index: Int) {
        _state.update {
            val updated = it.witnessUrls.toMutableList()
            if (index in updated.indices) updated.removeAt(index)
            it.copy(witnessUrls = updated)
        }
    }

    fun setWitnessThreshold(value: String) {
        _state.update { it.copy(witnessThreshold = value) }
    }

    fun clearKelDump() = _state.update { it.copy(kelDump = null) }

    // ----- bootstrap -----

    private suspend fun ensureSdk(): KeriSdk {
        sdk?.let { return it }
        _state.update { it.copy(bootStatus = "creating SDK + registering key provider...") }
        val newSdk = withContext(Dispatchers.IO) { KeriSdk.open(dbPath, provider) }
        sdk = newSdk
        _state.update { it.copy(bootStatus = "SDK ready") }
        return newSdk
    }

    fun initSdk() = viewModelScope.launch {
        try { ensureSdk() } catch (t: Throwable) {
            _state.update { it.copy(bootStatus = "error: ${t.message}") }
        }
    }

    // ----- end-to-end -----

    fun createIdentifier() = viewModelScope.launch {
        _state.update { it.copy(identStatus = "creating identifier (biometric x2)...") }
        try {
            val sdk = ensureSdk()
            val urls = activeWitnessUrls()
            val threshold = witnessThresholdValue()
            val aid = sdk.createIdentifier(
                alias = IDENT_ALIAS,
                witnessUrls = urls,
                watcherUrls = emptyList(),
                witnessThreshold = threshold,
                algorithm = _state.value.algorithm,
            )
            _state.update { it.copy(lastAid = aid, identStatus = "AID: $aid") }
            refreshRustAliasesInternal(sdk)
            listKeystoreInternal()
        } catch (t: Throwable) {
            _state.update { it.copy(identStatus = "error: ${t.message}") }
        }
    }

    fun rotateIdentifier() = viewModelScope.launch {
        _state.update { it.copy(rotateStatus = "rotating (biometric x2)...") }
        try {
            val sdk = ensureSdk()
            sdk.rotateKeys(
                alias = IDENT_ALIAS,
                witnessThreshold = witnessThresholdValue(),
            )
            _state.update { it.copy(rotateStatus = "rotated") }
            listKeystoreInternal()
        } catch (t: Throwable) {
            _state.update { it.copy(rotateStatus = "error: ${t.message}") }
        }
    }

    fun showKel() = viewModelScope.launch {
        _state.update { it.copy(kelStatus = "loading...") }
        try {
            val sdk = ensureSdk()
            val dump = withContext(Dispatchers.IO) { sdk.showKel(IDENT_ALIAS) }
            _state.update { it.copy(kelStatus = "ok", kelDump = dump) }
        } catch (t: Throwable) {
            _state.update { it.copy(kelStatus = "error: ${t.message}") }
        }
    }

    // ----- Rust FFI inspection -----

    fun refreshRustAliases() = viewModelScope.launch {
        _state.update { it.copy(rustStatus = "running...", rustAliases = emptyList()) }
        try {
            refreshRustAliasesInternal(ensureSdk())
        } catch (t: Throwable) {
            _state.update { it.copy(rustStatus = "error: ${t.message}") }
        }
    }

    private suspend fun refreshRustAliasesInternal(sdk: KeriSdk) {
        val aliases = withContext(Dispatchers.IO) { sdk.listAliases() }
        _state.update { it.copy(rustAliases = aliases, rustStatus = "ok — ${aliases.size} aliases") }
    }

    // ----- direct Android Keystore ops on 'demo' label -----

    fun listKeystore() = viewModelScope.launch { listKeystoreInternal() }

    private suspend fun listKeystoreInternal() {
        _state.update { it.copy(keystoreStatus = "listing...") }
        val labels = withContext(Dispatchers.IO) { provider.keystore.listKeys() }
        _state.update { it.copy(keystoreLabels = labels, keystoreStatus = "ok — ${labels.size} keys") }
    }

    fun createTestKey() = viewModelScope.launch {
        _state.update { it.copy(keystoreStatus = "creating (biometric)...") }
        try {
            val algoStr = _state.value.algorithm.toLabel()
            val pubAtCreate = withContext(Dispatchers.Main) {
                suspendCallback { onOk, onErr ->
                    provider.keystore.createKey(MainActivity.current!!, TEST_KEY_LABEL, algoStr, onOk, onErr)
                }
            }
            val pubAtRead = provider.keystore.getPublicKey(TEST_KEY_LABEL)
            val match = pubAtCreate.contentEquals(pubAtRead)
            _state.update {
                it.copy(
                    lastPublicKey = pubAtCreate,
                    keystoreStatus = "create vs read match=$match\n" +
                        "create=${hex(pubAtCreate)}\nread  =${hex(pubAtRead)}",
                )
            }
        } catch (t: Throwable) {
            _state.update { it.copy(keystoreStatus = "error: ${t.message}") }
        }
    }

    fun signTest() = viewModelScope.launch {
        _state.update { it.copy(keystoreStatus = "signing (biometric)...") }
        try {
            val msg = "hello keri".toByteArray()
            val sig = withContext(Dispatchers.Main) {
                suspendCallback { onOk, onErr ->
                    provider.keystore.sign(MainActivity.current!!, TEST_KEY_LABEL, msg, onOk, onErr)
                }
            }
            _state.update {
                it.copy(
                    lastSignature = sig,
                    keystoreStatus = "signed (${sig.size} bytes). sig=${hex(sig)}",
                )
            }
        } catch (t: Throwable) {
            _state.update { it.copy(keystoreStatus = "error: ${t.message}") }
        }
    }

    fun deleteTestKey() = viewModelScope.launch {
        _state.update { it.copy(keystoreStatus = "deleting...") }
        try {
            withContext(Dispatchers.IO) { provider.keystore.deleteKey(TEST_KEY_LABEL) }
            _state.update {
                it.copy(
                    lastPublicKey = null,
                    lastSignature = null,
                    keystoreStatus = "deleted",
                )
            }
            listKeystoreInternal()
        } catch (t: Throwable) {
            _state.update { it.copy(keystoreStatus = "error: ${t.message}") }
        }
    }

    // ----- wipe -----

    fun wipeAll() = viewModelScope.launch {
        _state.update { it.copy(wipeStatus = "wiping...") }
        try {
            withContext(Dispatchers.IO) {
                sdk?.wipe()
                val labels = provider.keystore.listKeys()
                labels.forEach { provider.keystore.deleteKey(it) }
                _state.update {
                    it.copy(
                        wipeStatus = "wiped — Rust db deleted, ${labels.size} keystore labels removed",
                        rustStatus = "idle",
                        keystoreStatus = "idle",
                        identStatus = "idle",
                        rotateStatus = "idle",
                        kelStatus = "idle",
                        rustAliases = emptyList(),
                        keystoreLabels = emptyList(),
                        lastPublicKey = null,
                        lastSignature = null,
                        lastAid = null,
                    )
                }
            }
        } catch (t: Throwable) {
            _state.update { it.copy(wipeStatus = "error: ${t.message}") }
        }
    }

    // ----- helpers -----

    private fun activeWitnessUrls(): List<String> =
        _state.value.witnessUrls.map { it.trim() }.filter { it.isNotEmpty() }

    private fun witnessThresholdValue(): ULong =
        _state.value.witnessThreshold.trim().toULongOrNull() ?: 0UL
}

private inline fun <T> MutableStateFlow<T>.update(transform: (T) -> T) {
    while (true) {
        val cur = value
        if (compareAndSet(cur, transform(cur))) return
    }
}

internal fun SignatureAlgo.toLabel(): String = when (this) {
    SignatureAlgo.ED25519 -> "Ed25519"
    SignatureAlgo.ECDSA_SECP256K1 -> "EcdsaSecp256k1"
    SignatureAlgo.ECDSA_SECP256R1 -> "EcdsaSecp256r1"
}

internal fun hex(data: ByteArray?): String {
    if (data == null) return "∅"
    val preview = if (data.size > 16) data.copyOf(16) else data
    val s = preview.joinToString("") { "%02x".format(it) }
    return if (data.size > 16) "$s…(${data.size} bytes)" else s
}

/** Bridges a callback-style API to a suspend point. */
private suspend fun <T> suspendCallback(
    block: (onSuccess: (T) -> Unit, onError: (String) -> Unit) -> Unit,
): T = suspendCancellableCoroutine { cont ->
    block(
        { value -> cont.resume(value) },
        { msg -> cont.resumeWithException(RuntimeException(msg)) },
    )
}
