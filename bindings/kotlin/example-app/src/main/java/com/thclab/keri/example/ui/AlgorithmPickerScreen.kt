package com.thclab.keri.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.thclab.keri.uniffi.SignatureAlgo

/** Mirrors Dart's `AlgorithmPickerPage` — two cards, tap to choose. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AlgorithmPickerScreen(
    onChoose: (algo: SignatureAlgo, label: String) -> Unit,
) {
    Scaffold(topBar = { TopAppBar(title = { Text("Pick signing algorithm") }) }) { pad ->
        Column(
            modifier = Modifier
                .padding(pad)
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
        ) {
            Text(
                "Choose how KERI keys are stored and signed on this device. " +
                    "You can wipe and switch any time.",
                style = MaterialTheme.typography.bodyLarge,
            )
            Spacer(Modifier.height(32.dp))
            AlgoCard(
                title = "Software — BouncyCastle Ed25519",
                subtitle = "Seed encrypted under an AndroidKeyStore AES-GCM master " +
                    "key, biometric-gated. Seed lives in process memory briefly " +
                    "during sign() and is cached for 10s to coalesce bursts.",
                chip = "fallback",
                chipColor = Color(0xFFF57C00),
                onClick = { onChoose(SignatureAlgo.ED25519, "Ed25519 (software)") },
            )
            Spacer(Modifier.height(16.dp))
            AlgoCard(
                title = "Hardware — AndroidKeyStore P-256",
                subtitle = "NIST secp256r1, private key generated and held inside the " +
                    "TEE/StrongBox. Time-bound biometric auth (10s) enforced by " +
                    "KeyMint — no seed exists in app memory.",
                chip = "native",
                chipColor = Color(0xFF388E3C),
                onClick = { onChoose(SignatureAlgo.ECDSA_SECP256R1, "P-256 (hardware)") },
            )
        }
    }
}

@Composable
private fun AlgoCard(
    title: String,
    subtitle: String,
    chip: String,
    chipColor: Color,
    onClick: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .background(chipColor, RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 2.dp),
                ) {
                    Text(chip, color = Color.White, style = MaterialTheme.typography.labelMedium)
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(subtitle, style = MaterialTheme.typography.bodyMedium)
        }
    }
}
