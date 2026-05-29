package com.thclab.keri.example

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import com.thclab.keri.example.ui.AlgorithmPickerScreen
import com.thclab.keri.example.ui.SmokeTestScreen

@Composable
fun App(vm: KeriViewModel = viewModel()) {
    var algorithmChosen by rememberSaveable { mutableStateOf(false) }

    if (!algorithmChosen) {
        AlgorithmPickerScreen(
            onChoose = { algo, label ->
                vm.setAlgorithm(algo, label)
                algorithmChosen = true
            },
        )
    } else {
        SmokeTestScreen(
            stateFlow = vm.state,
            vm = vm,
            onBack = { algorithmChosen = false },
        )
    }
}
