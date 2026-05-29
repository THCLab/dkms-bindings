package com.thclab.keri.example

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.fragment.app.FragmentActivity
import java.lang.ref.WeakReference

/**
 * Single-activity host. Compose owns the UI; the static [current] ref lets
 * the SDK's [com.thclab.keri.keystore.AndroidKeystoreKeyProvider] pull a
 * `FragmentActivity` on demand to show biometric prompts without the
 * ViewModel ever retaining one.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        currentRef = WeakReference(this)
        setContent {
            MaterialTheme {
                Surface { App() }
            }
        }
    }

    override fun onDestroy() {
        if (currentRef?.get() === this) currentRef = null
        super.onDestroy()
    }

    companion object {
        @Volatile private var currentRef: WeakReference<FragmentActivity>? = null
        val current: FragmentActivity? get() = currentRef?.get()
    }
}
