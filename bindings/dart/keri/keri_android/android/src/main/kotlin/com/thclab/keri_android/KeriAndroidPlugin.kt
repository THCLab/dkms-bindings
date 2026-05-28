package com.thclab.keri_android

import android.content.Context
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

class KeriAndroidPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    private var activity: FragmentActivity? = null
    private lateinit var provider: KeriKeyProvider

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        provider = KeriKeyProvider(appContext)
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
            ?: error("KeriAndroidPlugin requires a FragmentActivity host")
    }

    override fun onDetachedFromActivity() { activity = null }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)
    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "createKey" -> handleCreateKey(call, result)
            "openKey", "getPublicKey" -> handleGetPublicKey(call, result)
            "sign" -> handleSign(call, result)
            "deleteKey" -> handleDeleteKey(call, result)
            "listKeys" -> handleListKeys(result)
            else -> result.notImplemented()
        }
    }

    private fun handleCreateKey(call: MethodCall, result: Result) {
        val label = call.argument<String>("label")
            ?: return result.error("ARG", "Missing 'label'", null)
        val algo = call.argument<String>("algo")
            ?: return result.error("ARG", "Missing 'algo'", null)
        val act = activity ?: return result.error("STATE", "No host activity", null)
        provider.createKey(
            act, label, algo,
            onSuccess = { pub -> result.success(pub) },
            onError = { result.error("KEYSTORE", it, null) }
        )
    }

    private fun handleGetPublicKey(call: MethodCall, result: Result) {
        val label = call.argument<String>("label")
            ?: return result.error("ARG", "Missing 'label'", null)
        try {
            result.success(provider.getPublicKey(label))
        } catch (e: Exception) {
            result.error("KEYSTORE", e.message, null)
        }
    }

    private fun handleSign(call: MethodCall, result: Result) {
        val label = call.argument<String>("label")
            ?: return result.error("ARG", "Missing 'label'", null)
        val message = call.argument<ByteArray>("message")
            ?: return result.error("ARG", "Missing 'message'", null)
        val act = activity ?: return result.error("STATE", "No host activity", null)
        provider.sign(
            act, label, message,
            onSuccess = { sig -> result.success(sig) },
            onError = { result.error("KEYSTORE", it, null) }
        )
    }

    private fun handleDeleteKey(call: MethodCall, result: Result) {
        val label = call.argument<String>("label")
            ?: return result.error("ARG", "Missing 'label'", null)
        try {
            provider.deleteKey(label)
            result.success(null)
        } catch (e: Exception) {
            result.error("KEYSTORE", e.message, null)
        }
    }

    private fun handleListKeys(result: Result) {
        try {
            result.success(provider.listKeys())
        } catch (e: Exception) {
            result.error("KEYSTORE", e.message, null)
        }
    }

    private companion object {
        const val CHANNEL = "com.thclab.keri_android/keystore"
    }
}
