package com.feelbachelor.app.core.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.feelbachelor.app.core.security.CryptoUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

private const val PREF_FILE = "secure_endpoint_settings"
private const val KEY_BACKEND_URL = "backend_url"
private const val KEY_API_TOKEN = "api_token"
private const val KEY_EXPORT_ENABLED = "export_enabled"
private const val KEY_DEVICE_SALT = "device_salt"
private const val KEY_CAPTURE_ENABLED = "capture_enabled"

data class EndpointConfig(
    val backendUrl: String,
    val apiToken: String,
    val exportEnabled: Boolean,
    val captureEnabled: Boolean
) {
    fun isConfigured(): Boolean = backendUrl.isNotBlank() && apiToken.isNotBlank()
}

class SecureSettingsStore(context: Context) {
    private val prefs: SharedPreferences
    private val configState: MutableStateFlow<EndpointConfig>

    init {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        prefs = EncryptedSharedPreferences.create(
            context,
            PREF_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        if (!prefs.contains(KEY_DEVICE_SALT)) {
            prefs.edit().putString(KEY_DEVICE_SALT, CryptoUtils.randomHex()).apply()
        }

        configState = MutableStateFlow(readConfig())
    }

    fun configFlow(): StateFlow<EndpointConfig> = configState

    fun readConfig(): EndpointConfig {
        return EndpointConfig(
            backendUrl = prefs.getString(KEY_BACKEND_URL, "") ?: "",
            apiToken = prefs.getString(KEY_API_TOKEN, "") ?: "",
            exportEnabled = prefs.getBoolean(KEY_EXPORT_ENABLED, false),
            captureEnabled = prefs.getBoolean(KEY_CAPTURE_ENABLED, false)
        )
    }

    fun setBackendUrl(value: String) {
        prefs.edit().putString(KEY_BACKEND_URL, value.trim()).apply()
        configState.value = readConfig()
    }

    fun setApiToken(value: String) {
        prefs.edit().putString(KEY_API_TOKEN, value.trim()).apply()
        configState.value = readConfig()
    }

    fun setExportEnabled(value: Boolean) {
        prefs.edit().putBoolean(KEY_EXPORT_ENABLED, value).apply()
        configState.value = readConfig()
    }

    fun setCaptureEnabled(value: Boolean) {
        prefs.edit().putBoolean(KEY_CAPTURE_ENABLED, value).apply()
        configState.value = readConfig()
    }

    fun getDeviceSalt(): String {
        return prefs.getString(KEY_DEVICE_SALT, "fallback-salt") ?: "fallback-salt"
    }
}
