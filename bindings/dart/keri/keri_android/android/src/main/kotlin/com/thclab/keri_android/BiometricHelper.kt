package com.thclab.keri_android

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

class BiometricHelper(private val activity: FragmentActivity) {

    fun authenticate(
        cipher: Cipher,
        title: String,
        subtitle: String,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val unlocked = result.cryptoObject?.cipher
                if (unlocked == null) {
                    onError("Biometric prompt returned no cipher")
                } else {
                    onSuccess(unlocked)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onError("Biometric error $errorCode: $errString")
            }

            override fun onAuthenticationFailed() {
                // Called when a biometric attempt is rejected (not yet a final error);
                // the prompt remains open. No-op.
            }
        }

        BiometricPrompt(activity, executor, callback)
            .authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}
