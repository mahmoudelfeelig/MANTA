package com.feelbachelor.app.core.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.feelbachelor.app.core.model.RemotePolicy
import com.feelbachelor.app.core.model.ThresholdProfile
import com.feelbachelor.app.core.security.CryptoUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject

private const val PREF_FILE = "secure_endpoint_settings"
private const val KEY_BACKEND_URL = "backend_url"
private const val KEY_API_TOKEN = "api_token"
private const val KEY_EXPORT_ENABLED = "export_enabled"
private const val KEY_DEVICE_SALT = "device_salt"
private const val KEY_CAPTURE_ENABLED = "capture_enabled"
private const val KEY_MEDIUM_THRESHOLD = "medium_threshold"
private const val KEY_HIGH_THRESHOLD = "high_threshold"
private const val KEY_POLICY_VERSION = "policy_version"
private const val KEY_RETENTION_DAYS = "retention_days"
private const val KEY_APP_THRESHOLD_OVERRIDES = "app_threshold_overrides"
private const val KEY_CONSENT_ACCEPTED = "consent_accepted"

data class EndpointConfig(
    val backendUrl: String,
    val apiToken: String,
    val exportEnabled: Boolean,
    val captureEnabled: Boolean,
    val mediumThreshold: Double,
    val highThreshold: Double,
    val policyVersion: Int,
    val retentionDays: Int,
    val consentAccepted: Boolean
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
        if (!prefs.contains(KEY_MEDIUM_THRESHOLD)) {
            prefs.edit().putString(KEY_MEDIUM_THRESHOLD, "0.60").apply()
        }
        if (!prefs.contains(KEY_HIGH_THRESHOLD)) {
            prefs.edit().putString(KEY_HIGH_THRESHOLD, "0.85").apply()
        }
        if (!prefs.contains(KEY_POLICY_VERSION)) {
            prefs.edit().putInt(KEY_POLICY_VERSION, 1).apply()
        }
        if (!prefs.contains(KEY_RETENTION_DAYS)) {
            prefs.edit().putInt(KEY_RETENTION_DAYS, 7).apply()
        }
        if (!prefs.contains(KEY_APP_THRESHOLD_OVERRIDES)) {
            prefs.edit().putString(KEY_APP_THRESHOLD_OVERRIDES, "{}").apply()
        }
        if (!prefs.contains(KEY_CONSENT_ACCEPTED)) {
            prefs.edit().putBoolean(KEY_CONSENT_ACCEPTED, false).apply()
        }

        configState = MutableStateFlow(readConfig())
    }

    fun configFlow(): StateFlow<EndpointConfig> = configState

    fun readConfig(): EndpointConfig {
        return EndpointConfig(
            backendUrl = prefs.getString(KEY_BACKEND_URL, "") ?: "",
            apiToken = prefs.getString(KEY_API_TOKEN, "") ?: "",
            exportEnabled = prefs.getBoolean(KEY_EXPORT_ENABLED, false),
            captureEnabled = prefs.getBoolean(KEY_CAPTURE_ENABLED, false),
            mediumThreshold = prefs.getString(KEY_MEDIUM_THRESHOLD, "0.60")?.toDoubleOrNull() ?: 0.60,
            highThreshold = prefs.getString(KEY_HIGH_THRESHOLD, "0.85")?.toDoubleOrNull() ?: 0.85,
            policyVersion = prefs.getInt(KEY_POLICY_VERSION, 1),
            retentionDays = prefs.getInt(KEY_RETENTION_DAYS, 7).coerceIn(1, 90),
            consentAccepted = prefs.getBoolean(KEY_CONSENT_ACCEPTED, false)
        )
    }

    fun setBackendUrl(value: String) {
        prefs.edit().putString(KEY_BACKEND_URL, value.trim().trimEnd('/')).apply()
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

    fun setConsentAccepted(value: Boolean) {
        prefs.edit().putBoolean(KEY_CONSENT_ACCEPTED, value).apply()
        configState.value = readConfig()
    }

    fun setBaseThresholds(profile: ThresholdProfile) {
        val normalized = profile.normalize()
        prefs.edit()
            .putString(KEY_MEDIUM_THRESHOLD, normalized.medium.toString())
            .putString(KEY_HIGH_THRESHOLD, normalized.high.toString())
            .apply()
        configState.value = readConfig()
    }

    fun getThresholdForApp(appId: String): ThresholdProfile {
        val overrides = JSONObject(prefs.getString(KEY_APP_THRESHOLD_OVERRIDES, "{}") ?: "{}")
        val value = overrides.optJSONObject(appId)
        if (value != null) {
            return ThresholdProfile(
                medium = value.optDouble("medium", readConfig().mediumThreshold),
                high = value.optDouble("high", readConfig().highThreshold)
            ).normalize()
        }

        return ThresholdProfile(
            medium = readConfig().mediumThreshold,
            high = readConfig().highThreshold
        ).normalize()
    }

    fun applyRemotePolicy(policy: RemotePolicy) {
        val normalizedThresholds = policy.defaultThresholds.normalize()
        val overrideRoot = JSONObject()
        policy.appThresholdOverrides.forEach { (appId, profile) ->
            val normalized = profile.normalize()
            overrideRoot.put(
                appId,
                JSONObject()
                    .put("medium", normalized.medium)
                    .put("high", normalized.high)
            )
        }

        prefs.edit()
            .putString(KEY_MEDIUM_THRESHOLD, normalizedThresholds.medium.toString())
            .putString(KEY_HIGH_THRESHOLD, normalizedThresholds.high.toString())
            .putInt(KEY_POLICY_VERSION, policy.policyVersion)
            .putInt(KEY_RETENTION_DAYS, policy.retentionDays.coerceIn(1, 90))
            .putBoolean(KEY_EXPORT_ENABLED, policy.exportEnabled)
            .putString(KEY_APP_THRESHOLD_OVERRIDES, overrideRoot.toString())
            .apply()

        configState.value = readConfig()
    }

    fun getPolicySyncUrl(deviceIdPseudo: String): String {
        val base = readConfig().backendUrl.trimEnd('/')
        if (base.isBlank()) {
            return ""
        }
        return "$base/api/v1/policy/device/$deviceIdPseudo"
    }

    fun getEventIngestUrl(eventType: String): String {
        val base = readConfig().backendUrl.trimEnd('/')
        if (base.isBlank()) {
            return ""
        }
        return when (eventType) {
            "mobile_flow" -> "$base/api/v1/events/mobile-flow"
            "mobile_alert" -> "$base/api/v1/events/mobile-alert"
            else -> "$base/api/v1/events/$eventType"
        }
    }

    fun getDeviceSalt(): String {
        return prefs.getString(KEY_DEVICE_SALT, "fallback-salt") ?: "fallback-salt"
    }
}
