package com.thclab.keri.example.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.thclab.keri.example.KeriViewModel
import com.thclab.keri.example.SmokeState
import com.thclab.keri.example.hex
import kotlinx.coroutines.flow.StateFlow

/** Mirrors Dart's `SmokeTestPage` — six sections, status text per section. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SmokeTestScreen(
    stateFlow: StateFlow<SmokeState>,
    vm: KeriViewModel,
    onBack: () -> Unit,
) {
    val state by stateFlow.collectAsState()
    var showWipeConfirm by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("KERI smoke test — ${state.algorithmLabel}") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back to algorithm picker")
                    }
                },
            )
        },
    ) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            // ----- Bootstrap -----
            SectionTitle("Bootstrap")
            Text("SDK:  ${state.bootStatus}")
            Text("Wipe: ${state.wipeStatus}")
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { showWipeConfirm = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB71C1C)),
            ) {
                Text("🗑  Wipe all app data")
            }
            Spacer(Modifier.height(8.dp))
            Button(onClick = vm::initSdk, modifier = Modifier.fillMaxWidth()) {
                Text("Init SDK + register key provider")
            }

            SectionDivider()

            // ----- Witnesses -----
            SectionTitle("Witnesses")
            state.witnessUrls.forEachIndexed { i, url ->
                Row(
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    modifier = Modifier.padding(bottom = 8.dp),
                ) {
                    OutlinedTextField(
                        value = url,
                        onValueChange = { vm.setWitnessUrl(i, it) },
                        label = { Text("witness ${i + 1} URL") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    IconButton(onClick = { vm.removeWitnessField(i) }) {
                        Text("✕")
                    }
                }
            }
            TextButton(onClick = vm::addWitnessField) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(Modifier.width(4.dp))
                Text("Add witness")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.witnessThreshold,
                onValueChange = vm::setWitnessThreshold,
                label = { Text("witness threshold") },
                singleLine = true,
                modifier = Modifier.width(160.dp),
            )

            SectionDivider()

            // ----- End-to-end -----
            SectionTitle("End-to-end: createIdentifier / rotateKeys")
            FlowButtons {
                Button(onClick = vm::createIdentifier) { Text("Create identifier (alice)") }
                FilledTonalButton(onClick = vm::rotateIdentifier) { Text("Rotate keys (alice)") }
                OutlinedButton(onClick = vm::showKel) { Text("Show KEL") }
            }
            Spacer(Modifier.height(8.dp))
            Text("Create status: ${state.identStatus}")
            Text("Rotate status: ${state.rotateStatus}")
            Text("Show KEL:      ${state.kelStatus}")
            state.lastAid?.let { Text("AID: $it") }

            SectionDivider()

            // ----- Rust FFI inspection -----
            SectionTitle("Rust FFI inspection")
            Button(onClick = vm::refreshRustAliases) { Text("listAliases() via Rust") }
            Spacer(Modifier.height(8.dp))
            Text("Status: ${state.rustStatus}")
            state.rustAliases.forEach { Text("• $it") }

            SectionDivider()

            // ----- Android Keystore -----
            SectionTitle("Android Keystore (label=demo)")
            FlowButtons {
                OutlinedButton(onClick = vm::createTestKey) { Text("Create key") }
                OutlinedButton(onClick = vm::signTest) { Text("Sign \"hello keri\"") }
                OutlinedButton(onClick = vm::listKeystore) { Text("List keys") }
                OutlinedButton(onClick = vm::deleteTestKey) { Text("Delete key") }
            }
            Spacer(Modifier.height(8.dp))
            Text("Status: ${state.keystoreStatus}")
            Text("Last public key: ${hex(state.lastPublicKey)}")
            Text("Last signature:  ${hex(state.lastSignature)}")
            Spacer(Modifier.height(8.dp))
            Text("Stored labels:")
            state.keystoreLabels.forEach { Text("• $it") }
            Spacer(Modifier.height(24.dp))
        }
    }

    if (showWipeConfirm) {
        AlertDialog(
            onDismissRequest = { showWipeConfirm = false },
            title = { Text("Wipe app data?") },
            text = {
                Text(
                    "Deletes the Rust KERI database and removes every key from the " +
                        "AndroidKeyStore vault. Cannot be undone.",
                )
            },
            confirmButton = {
                FilledTonalButton(onClick = {
                    showWipeConfirm = false
                    vm.wipeAll()
                }) { Text("Wipe") }
            },
            dismissButton = {
                TextButton(onClick = { showWipeConfirm = false }) { Text("Cancel") }
            },
        )
    }

    state.kelDump?.let { dump ->
        AlertDialog(
            onDismissRequest = vm::clearKelDump,
            title = { Text("KEL for alice") },
            text = {
                Box(modifier = Modifier.heightIn(max = 480.dp)) {
                    Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                        SelectionContainer {
                            Text(
                                dump,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = vm::clearKelDump) { Text("Close") }
            },
        )
    }
}

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(bottom = 8.dp),
    )
}

@Composable
private fun SectionDivider() {
    HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))
}

@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
private fun FlowButtons(content: @Composable () -> Unit) {
    androidx.compose.foundation.layout.FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) { content() }
}

