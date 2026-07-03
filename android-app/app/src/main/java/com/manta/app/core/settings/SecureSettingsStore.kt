package com.manta.app.core.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.manta.app.core.model.RemotePolicy
import com.manta.app.core.model.ThresholdProfile
import com.manta.app.core.security.CryptoUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONObject

private const val PREF_FILE = "secure_endpoint_settings"
private const val KEY_BACKEND_URL = "backend_url"
private const val KEY_API_TOKEN = "api_token"
private const val KEY_EXPORT_ENABLED = "export_enabled"
private const val KEY_DEVICE_SALT = "device_salt"
private const val KEY_CAPTURE_ENABLED = "capture_enabled"
private const val KEY_LOW_THRESHOLD = "low_threshold"
private const val KEY_MEDIUM_THRESHOLD = "medium_threshold"
private const val KEY_HIGH_THRESHOLD = "high_threshold"
private const val KEY_POLICY_VERSION = "policy_version"
private const val KEY_RETENTION_DAYS = "retention_days"
private const val KEY_APP_THRESHOLD_OVERRIDES = "app_threshold_overrides"
private const val KEY_CONSENT_ACCEPTED = "consent_accepted"
private const val KEY_DETECTION_MODEL = "detection_model"
private const val KEY_SHADOW_MODEL = "shadow_model"
private const val KEY_FALSE_POSITIVE_BUDGET = "false_positive_budget_per_app_day"
private const val KEY_DRIFT_HIGH_THRESHOLD = "drift_high_threshold"
private const val KEY_THEME_MODE = "theme_mode"
private const val KEY_DEBUG_MODE_ENABLED = "debug_mode_enabled"
private const val KEY_TEST_MODE_ENABLED = "test_mode_enabled"
private const val KEY_PRIVACY_MODE_ENABLED = "privacy_mode_enabled"
private const val KEY_PRIVACY_MODE = "privacy_mode"
private const val KEY_FUSION_STATISTICAL_WEIGHT = "fusion_statistical_weight"
private const val KEY_FUSION_MULTIVARIATE_WEIGHT = "fusion_multivariate_weight"
private const val KEY_FUSION_SEQUENCE_WEIGHT = "fusion_sequence_weight"
private const val KEY_FUSION_LOCAL_WEIGHT = "fusion_local_weight"
private const val KEY_FUSION_LEGACY_LINEAR_WEIGHT = "fusion_linear_weight"
private const val KEY_FUSION_TFLITE_WEIGHT = "fusion_tflite_weight"
private const val KEY_FUSION_REMOTE_WEIGHT = "fusion_remote_weight"
private const val KEY_FUSION_BEACON_WEIGHT = "fusion_beacon_weight"
private const val KEY_FUSION_DRIFT_WEIGHT = "fusion_drift_weight"
private const val KEY_FUSION_REPUTATION_WEIGHT = "fusion_reputation_weight"
private const val KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT = "fusion_data_quality_penalty_weight"
private const val KEY_RESPONSE_ANOMALY_BLEND_WEIGHT = "response_anomaly_blend_weight"
private const val KEY_RESPONSE_CONTEXT_BLEND_WEIGHT = "response_context_blend_weight"
private const val KEY_LAST_EXPORT_SUCCESS_EPOCH = "last_export_success_epoch"
private const val KEY_LAST_EXPORT_ERROR = "last_export_error"
private const val KEY_LAST_EXPORT_SENT_COUNT = "last_export_sent_count"
private const val KEY_LAST_POLICY_SYNC_EPOCH = "last_policy_sync_epoch"
private const val KEY_LAST_POLICY_SYNC_STATUS = "last_policy_sync_status"
private const val KEY_LAST_POLICY_DIFF_SUMMARY = "last_policy_diff_summary"
private const val KEY_LAST_SERVER_PING_EPOCH = "last_server_ping_epoch"
private const val KEY_LAST_SERVER_PING_STATUS = "last_server_ping_status"
private const val KEY_LAST_SERVER_PING_DETAIL = "last_server_ping_detail"
private const val KEY_LAST_DEVICE_HEARTBEAT_EPOCH = "last_device_heartbeat_epoch"
private const val KEY_LAST_DEVICE_HEARTBEAT_STATUS = "last_device_heartbeat_status"
private const val KEY_LAST_DEVICE_HEARTBEAT_DETAIL = "last_device_heartbeat_detail"
private const val KEY_APP_PROFILES = "app_profiles"
private const val KEY_ABLATE_VOLUME_FEATURES = "ablate_volume_features"
private const val KEY_ABLATE_TIMING_FEATURES = "ablate_timing_features"
private const val KEY_ABLATE_DESTINATION_FEATURES = "ablate_destination_features"
private const val KEY_CUSTOM_PRIVACY_OPTIONS = "custom_privacy_options"
private const val KEY_PROTECTED_BRANDS = "protected_brands"

private fun roundWeight(value: Double): String = "%.3f".format(value)

private val DEFAULT_PROTECTED_BRANDS = listOf(
    "google",
    "microsoft",
    "apple",
    "meta",
    "paypal",
    "amazon",
    "github",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "outlook",
    "gmail",
    "dropbox",
    "icloud",
    "netflix",
    "spotify",
    "bankofamerica",
    "chase",
    "wellsfargo"
).joinToString("\n")

private val SUPPORTED_DETECTION_MODELS = setOf(
    "ensemble_fusion",
    "statistical",
    "multivariate",
    "sequence",
    "local",
    "local_sensitive",
    "local_quiet",
    "local_balanced",
    "local_privacy",
    "tflite",
    "remote_assisted"
)

private val LEGACY_DETECTION_MODEL_ALIASES = mapOf(
    "linear" to "local",
    "linear_v13_recall" to "local_sensitive",
    "linear_v14_quiet" to "local_quiet",
    "hybrid_v15" to "local_balanced"
)

enum class ThemeMode {
    SYSTEM,
    LIGHT,
    DARK
}

enum class AppProfile {
    DEFAULT,
    TRUSTED,
    HIGH_CHURN,
    BROWSER,
    SYSTEM
}

enum class PrivacyMode {
    OFF,
    LOW,
    MEDIUM,
    STRICT,
    CUSTOM
}

data class CustomPrivacyOptions(
    val includeAppId: Boolean = false,
    val includeSiteHint: Boolean = false,
    val includeIpAddresses: Boolean = false,
    val includeExactPorts: Boolean = true,
    val includeDeviceLabel: Boolean = false,
    val includeExplanations: Boolean = true,
    val includeFeatureWindow: Boolean = true
) {
    fun toJson(): String {
        return JSONObject()
            .put("include_app_id", includeAppId)
            .put("include_site_hint", includeSiteHint)
            .put("include_ip_addresses", includeIpAddresses)
            .put("include_exact_ports", includeExactPorts)
            .put("include_device_label", includeDeviceLabel)
            .put("include_explanations", includeExplanations)
            .put("include_feature_window", includeFeatureWindow)
            .toString()
    }

    companion object {
        fun fromJson(raw: String?): CustomPrivacyOptions {
            val root = runCatching { JSONObject(raw ?: "{}") }.getOrDefault(JSONObject())
            return CustomPrivacyOptions(
                includeAppId = root.optBoolean("include_app_id", false),
                includeSiteHint = root.optBoolean("include_site_hint", false),
                includeIpAddresses = root.optBoolean("include_ip_addresses", false),
                includeExactPorts = root.optBoolean("include_exact_ports", true),
                includeDeviceLabel = root.optBoolean("include_device_label", false),
                includeExplanations = root.optBoolean("include_explanations", true),
                includeFeatureWindow = root.optBoolean("include_feature_window", true)
            )
        }
    }
}

data class FusionWeights(
    val statistical: Double,
    val multivariate: Double,
    val sequence: Double,
    val local: Double,
    val tflite: Double,
    val remote: Double,
    val beacon: Double,
    val drift: Double,
    val reputation: Double,
    val dataQualityPenalty: Double,
    val responseAnomalyBlend: Double,
    val responseContextBlend: Double
) {
    fun normalize(): FusionWeights {
        val safeStat = statistical.coerceIn(0.0, 1.0)
        val safeMultivariate = multivariate.coerceIn(0.0, 1.0)
        val safeSequence = sequence.coerceIn(0.0, 1.0)
        val safeLocal = local.coerceIn(0.0, 1.0)
        val safeTflite = tflite.coerceIn(0.0, 1.0)
        val safeRemote = remote.coerceIn(0.0, 1.0)
        val total = safeStat + safeMultivariate + safeSequence + safeLocal + safeTflite + safeRemote
        val normalizedModelWeights = if (total <= 1e-6) {
            doubleArrayOf(0.28, 0.20, 0.12, 0.16, 0.12, 0.12)
        } else {
            doubleArrayOf(
                safeStat / total,
                safeMultivariate / total,
                safeSequence / total,
                safeLocal / total,
                safeTflite / total,
                safeRemote / total
            )
        }
        val safeResponseAnomaly = responseAnomalyBlend.coerceIn(0.0, 1.0)
        val safeResponseContext = responseContextBlend.coerceIn(0.0, 1.0)
        val responseTotal = safeResponseAnomaly + safeResponseContext
        val normalizedResponse = if (responseTotal <= 1e-6) {
            doubleArrayOf(0.82, 0.18)
        } else {
            doubleArrayOf(
                safeResponseAnomaly / responseTotal,
                safeResponseContext / responseTotal
            )
        }
        return FusionWeights(
            statistical = normalizedModelWeights[0],
            multivariate = normalizedModelWeights[1],
            sequence = normalizedModelWeights[2],
            local = normalizedModelWeights[3],
            tflite = normalizedModelWeights[4],
            remote = normalizedModelWeights[5],
            beacon = beacon.coerceIn(0.0, 1.0),
            drift = drift.coerceIn(0.0, 1.0),
            reputation = reputation.coerceIn(0.0, 1.0),
            dataQualityPenalty = dataQualityPenalty.coerceIn(0.0, 1.0),
            responseAnomalyBlend = normalizedResponse[0],
            responseContextBlend = normalizedResponse[1]
        )
    }
}

data class EndpointConfig(
    val backendUrl: String,
    val apiToken: String,
    val exportEnabled: Boolean,
    val captureEnabled: Boolean,
    val lowThreshold: Double,
    val mediumThreshold: Double,
    val highThreshold: Double,
    val policyVersion: Int,
    val retentionDays: Int,
    val consentAccepted: Boolean,
    val detectionModel: String,
    val shadowModel: String?,
    val falsePositiveBudgetPerAppDay: Int,
    val driftHighThreshold: Double,
    val themeMode: ThemeMode,
    val debugModeEnabled: Boolean,
    val testModeEnabled: Boolean,
    val privacyMode: PrivacyMode,
    val fusionWeights: FusionWeights,
    val lastExportSuccessEpoch: Long,
    val lastExportError: String?,
    val lastExportSentCount: Int,
    val lastPolicySyncEpoch: Long,
    val lastPolicySyncStatus: String?,
    val lastPolicyDiffSummary: String?,
    val lastServerPingEpoch: Long,
    val lastServerPingStatus: String?,
    val lastServerPingDetail: String?,
    val lastDeviceHeartbeatEpoch: Long,
    val lastDeviceHeartbeatStatus: String?,
    val lastDeviceHeartbeatDetail: String?,
    val customPrivacy: CustomPrivacyOptions,
    val ablateVolumeFeatures: Boolean,
    val ablateTimingFeatures: Boolean,
    val ablateDestinationFeatures: Boolean,
    val protectedBrandsCsv: String
) {
    fun isConfigured(): Boolean = backendUrl.isNotBlank() && apiToken.isNotBlank()
    fun isEffectiveExportEnabled(): Boolean = exportEnabled
    val privacyModeEnabled: Boolean
        get() = privacyMode != PrivacyMode.OFF
}

class SecureSettingsStore(context: Context) {
    private val appContext = context.applicationContext
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
        if (!prefs.contains(KEY_LOW_THRESHOLD)) {
            prefs.edit().putString(KEY_LOW_THRESHOLD, "0.300").apply()
        }
        if (!prefs.contains(KEY_HIGH_THRESHOLD)) {
            prefs.edit().putString(KEY_HIGH_THRESHOLD, "0.85").apply()
        }
        if (!prefs.contains(KEY_POLICY_VERSION)) {
            prefs.edit().putInt(KEY_POLICY_VERSION, 1).apply()
        }
        if (!prefs.contains(KEY_RETENTION_DAYS)) {
            prefs.edit().putInt(KEY_RETENTION_DAYS, 90).apply()
        }
        if (!prefs.contains(KEY_APP_THRESHOLD_OVERRIDES)) {
            prefs.edit().putString(KEY_APP_THRESHOLD_OVERRIDES, "{}").apply()
        }
        if (!prefs.contains(KEY_CONSENT_ACCEPTED)) {
            prefs.edit().putBoolean(KEY_CONSENT_ACCEPTED, false).apply()
        }
        if (!prefs.contains(KEY_DETECTION_MODEL)) {
            prefs.edit().putString(KEY_DETECTION_MODEL, "ensemble_fusion").apply()
        }
        if (!prefs.contains(KEY_SHADOW_MODEL)) {
            prefs.edit().putString(KEY_SHADOW_MODEL, "").apply()
        }
        if (!prefs.contains(KEY_FALSE_POSITIVE_BUDGET)) {
            prefs.edit().putInt(KEY_FALSE_POSITIVE_BUDGET, 12).apply()
        }
        if (!prefs.contains(KEY_DRIFT_HIGH_THRESHOLD)) {
            prefs.edit().putString(KEY_DRIFT_HIGH_THRESHOLD, "0.65").apply()
        }
        if (!prefs.contains(KEY_THEME_MODE)) {
            prefs.edit().putString(KEY_THEME_MODE, ThemeMode.SYSTEM.name).apply()
        }
        if (!prefs.contains(KEY_DEBUG_MODE_ENABLED)) {
            prefs.edit().putBoolean(KEY_DEBUG_MODE_ENABLED, false).apply()
        }
        if (!prefs.contains(KEY_PRIVACY_MODE_ENABLED)) {
            prefs.edit().putBoolean(KEY_PRIVACY_MODE_ENABLED, false).apply()
        }
        if (!prefs.contains(KEY_PRIVACY_MODE)) {
            val defaultMode = if (prefs.getBoolean(KEY_PRIVACY_MODE_ENABLED, false)) {
                PrivacyMode.MEDIUM.name
            } else {
                PrivacyMode.OFF.name
            }
            prefs.edit().putString(KEY_PRIVACY_MODE, defaultMode).apply()
        }
        if (!prefs.contains(KEY_FUSION_STATISTICAL_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_STATISTICAL_WEIGHT, "0.28").apply()
        }
        if (!prefs.contains(KEY_FUSION_MULTIVARIATE_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_MULTIVARIATE_WEIGHT, "0.20").apply()
        }
        if (!prefs.contains(KEY_FUSION_SEQUENCE_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_SEQUENCE_WEIGHT, "0.12").apply()
        }
        if (!prefs.contains(KEY_FUSION_LOCAL_WEIGHT) && !prefs.contains(KEY_FUSION_LEGACY_LINEAR_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_LOCAL_WEIGHT, "0.16").apply()
        }
        if (!prefs.contains(KEY_FUSION_TFLITE_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_TFLITE_WEIGHT, "0.12").apply()
        }
        if (!prefs.contains(KEY_FUSION_REMOTE_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_REMOTE_WEIGHT, "0.12").apply()
        }
        if (!prefs.contains(KEY_FUSION_BEACON_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_BEACON_WEIGHT, "0.15").apply()
        }
        if (!prefs.contains(KEY_FUSION_DRIFT_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_DRIFT_WEIGHT, "0.10").apply()
        }
        if (!prefs.contains(KEY_FUSION_REPUTATION_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_REPUTATION_WEIGHT, "0.18").apply()
        }
        if (!prefs.contains(KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT)) {
            prefs.edit().putString(KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT, "0.10").apply()
        }
        if (!prefs.contains(KEY_RESPONSE_ANOMALY_BLEND_WEIGHT)) {
            prefs.edit().putString(KEY_RESPONSE_ANOMALY_BLEND_WEIGHT, "0.82").apply()
        }
        if (!prefs.contains(KEY_RESPONSE_CONTEXT_BLEND_WEIGHT)) {
            prefs.edit().putString(KEY_RESPONSE_CONTEXT_BLEND_WEIGHT, "0.18").apply()
        }
        if (!prefs.contains(KEY_APP_PROFILES)) {
            prefs.edit().putString(KEY_APP_PROFILES, "{}").apply()
        }
        if (!prefs.contains(KEY_ABLATE_VOLUME_FEATURES)) {
            prefs.edit().putBoolean(KEY_ABLATE_VOLUME_FEATURES, false).apply()
        }
        if (!prefs.contains(KEY_ABLATE_TIMING_FEATURES)) {
            prefs.edit().putBoolean(KEY_ABLATE_TIMING_FEATURES, false).apply()
        }
        if (!prefs.contains(KEY_ABLATE_DESTINATION_FEATURES)) {
            prefs.edit().putBoolean(KEY_ABLATE_DESTINATION_FEATURES, false).apply()
        }
        if (!prefs.contains(KEY_CUSTOM_PRIVACY_OPTIONS)) {
            prefs.edit().putString(KEY_CUSTOM_PRIVACY_OPTIONS, CustomPrivacyOptions().toJson()).apply()
        }
        if (!prefs.contains(KEY_PROTECTED_BRANDS)) {
            prefs.edit().putString(KEY_PROTECTED_BRANDS, DEFAULT_PROTECTED_BRANDS).apply()
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
            lowThreshold = prefs.getString(KEY_LOW_THRESHOLD, "0.300")?.toDoubleOrNull()?.coerceIn(0.0, 1.0) ?: 0.300,
            mediumThreshold = prefs.getString(KEY_MEDIUM_THRESHOLD, "0.60")?.toDoubleOrNull() ?: 0.60,
            highThreshold = prefs.getString(KEY_HIGH_THRESHOLD, "0.85")?.toDoubleOrNull() ?: 0.85,
            policyVersion = prefs.getInt(KEY_POLICY_VERSION, 1),
            retentionDays = prefs.getInt(KEY_RETENTION_DAYS, 90).coerceIn(1, 90),
            consentAccepted = prefs.getBoolean(KEY_CONSENT_ACCEPTED, false),
            detectionModel = sanitizeDetectionModel(prefs.getString(KEY_DETECTION_MODEL, "ensemble_fusion")),
            shadowModel = sanitizeShadowModel(prefs.getString(KEY_SHADOW_MODEL, "")),
            falsePositiveBudgetPerAppDay = prefs.getInt(KEY_FALSE_POSITIVE_BUDGET, 12).coerceIn(1, 250),
            driftHighThreshold = prefs.getString(KEY_DRIFT_HIGH_THRESHOLD, "0.65")?.toDoubleOrNull()?.coerceIn(0.1, 1.0) ?: 0.65,
            themeMode = sanitizeThemeMode(prefs.getString(KEY_THEME_MODE, ThemeMode.SYSTEM.name)),
            debugModeEnabled = prefs.getBoolean(KEY_DEBUG_MODE_ENABLED, false),
            testModeEnabled = prefs.getBoolean(KEY_TEST_MODE_ENABLED, false),
            privacyMode = sanitizePrivacyMode(
                prefs.getString(KEY_PRIVACY_MODE, null),
                prefs.getBoolean(KEY_PRIVACY_MODE_ENABLED, false)
            ),
            fusionWeights = FusionWeights(
                statistical = prefs.getString(KEY_FUSION_STATISTICAL_WEIGHT, "0.28")?.toDoubleOrNull() ?: 0.28,
                multivariate = prefs.getString(KEY_FUSION_MULTIVARIATE_WEIGHT, "0.20")?.toDoubleOrNull() ?: 0.20,
                sequence = prefs.getString(KEY_FUSION_SEQUENCE_WEIGHT, "0.12")?.toDoubleOrNull() ?: 0.12,
                local = (
                    prefs.getString(KEY_FUSION_LOCAL_WEIGHT, null)
                        ?: prefs.getString(KEY_FUSION_LEGACY_LINEAR_WEIGHT, "0.16")
                    )?.toDoubleOrNull() ?: 0.16,
                tflite = prefs.getString(KEY_FUSION_TFLITE_WEIGHT, "0.12")?.toDoubleOrNull() ?: 0.12,
                remote = prefs.getString(KEY_FUSION_REMOTE_WEIGHT, "0.12")?.toDoubleOrNull() ?: 0.12,
                beacon = prefs.getString(KEY_FUSION_BEACON_WEIGHT, "0.15")?.toDoubleOrNull() ?: 0.15,
                drift = prefs.getString(KEY_FUSION_DRIFT_WEIGHT, "0.10")?.toDoubleOrNull() ?: 0.10,
                reputation = prefs.getString(KEY_FUSION_REPUTATION_WEIGHT, "0.18")?.toDoubleOrNull() ?: 0.18,
                dataQualityPenalty = prefs.getString(KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT, "0.10")?.toDoubleOrNull() ?: 0.10,
                responseAnomalyBlend = prefs.getString(KEY_RESPONSE_ANOMALY_BLEND_WEIGHT, "0.82")?.toDoubleOrNull() ?: 0.82,
                responseContextBlend = prefs.getString(KEY_RESPONSE_CONTEXT_BLEND_WEIGHT, "0.18")?.toDoubleOrNull() ?: 0.18
            ).normalize(),
            lastExportSuccessEpoch = prefs.getLong(KEY_LAST_EXPORT_SUCCESS_EPOCH, 0L),
            lastExportError = prefs.getString(KEY_LAST_EXPORT_ERROR, null),
            lastExportSentCount = prefs.getInt(KEY_LAST_EXPORT_SENT_COUNT, 0),
            lastPolicySyncEpoch = prefs.getLong(KEY_LAST_POLICY_SYNC_EPOCH, 0L),
            lastPolicySyncStatus = prefs.getString(KEY_LAST_POLICY_SYNC_STATUS, null),
            lastPolicyDiffSummary = prefs.getString(KEY_LAST_POLICY_DIFF_SUMMARY, null),
            lastServerPingEpoch = prefs.getLong(KEY_LAST_SERVER_PING_EPOCH, 0L),
            lastServerPingStatus = prefs.getString(KEY_LAST_SERVER_PING_STATUS, null),
            lastServerPingDetail = prefs.getString(KEY_LAST_SERVER_PING_DETAIL, null),
            lastDeviceHeartbeatEpoch = prefs.getLong(KEY_LAST_DEVICE_HEARTBEAT_EPOCH, 0L),
            lastDeviceHeartbeatStatus = prefs.getString(KEY_LAST_DEVICE_HEARTBEAT_STATUS, null),
            lastDeviceHeartbeatDetail = prefs.getString(KEY_LAST_DEVICE_HEARTBEAT_DETAIL, null),
            customPrivacy = CustomPrivacyOptions.fromJson(prefs.getString(KEY_CUSTOM_PRIVACY_OPTIONS, null)),
            ablateVolumeFeatures = prefs.getBoolean(KEY_ABLATE_VOLUME_FEATURES, false),
            ablateTimingFeatures = prefs.getBoolean(KEY_ABLATE_TIMING_FEATURES, false),
            ablateDestinationFeatures = prefs.getBoolean(KEY_ABLATE_DESTINATION_FEATURES, false),
            protectedBrandsCsv = prefs.getString(KEY_PROTECTED_BRANDS, DEFAULT_PROTECTED_BRANDS).orEmpty()
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

    fun setDetectionModel(value: String) {
        prefs.edit().putString(KEY_DETECTION_MODEL, sanitizeDetectionModel(value)).apply()
        configState.value = readConfig()
    }

    fun setShadowModel(value: String?) {
        prefs.edit().putString(KEY_SHADOW_MODEL, sanitizeShadowModel(value).orEmpty()).apply()
        configState.value = readConfig()
    }

    fun setFalsePositiveBudgetPerAppDay(value: Int) {
        prefs.edit().putInt(KEY_FALSE_POSITIVE_BUDGET, value.coerceIn(1, 250)).apply()
        configState.value = readConfig()
    }

    fun setDriftHighThreshold(value: Double) {
        prefs.edit().putString(KEY_DRIFT_HIGH_THRESHOLD, roundWeight(value.coerceIn(0.1, 1.0))).apply()
        configState.value = readConfig()
    }

    fun setThemeMode(value: ThemeMode) {
        prefs.edit().putString(KEY_THEME_MODE, value.name).apply()
        configState.value = readConfig()
    }

    fun setDebugModeEnabled(value: Boolean) {
        prefs.edit().putBoolean(KEY_DEBUG_MODE_ENABLED, value).apply()
        configState.value = readConfig()
    }

    fun setTestModeEnabled(value: Boolean) {
        prefs.edit().putBoolean(KEY_TEST_MODE_ENABLED, value).apply()
        configState.value = readConfig()
    }

    fun setPrivacyModeEnabled(value: Boolean) {
        prefs.edit()
            .putBoolean(KEY_PRIVACY_MODE_ENABLED, value)
            .putString(KEY_PRIVACY_MODE, if (value) PrivacyMode.MEDIUM.name else PrivacyMode.OFF.name)
            .apply()
        configState.value = readConfig()
    }

    fun setPrivacyMode(value: PrivacyMode) {
        prefs.edit()
            .putString(KEY_PRIVACY_MODE, value.name)
            .putBoolean(KEY_PRIVACY_MODE_ENABLED, value != PrivacyMode.OFF)
            .apply()
        configState.value = readConfig()
    }

    fun setCustomPrivacyOptions(value: CustomPrivacyOptions) {
        prefs.edit()
            .putString(KEY_CUSTOM_PRIVACY_OPTIONS, value.toJson())
            .apply()
        configState.value = readConfig()
    }

    fun setProtectedBrandsCsv(value: String) {
        val normalized = normalizeProtectedBrandsCsv(value)
        prefs.edit()
            .putString(KEY_PROTECTED_BRANDS, normalized)
            .apply()
        configState.value = readConfig()
    }

    fun getProtectedBrands(): List<String> {
        return readConfig().protectedBrandsCsv.lineSequence()
            .map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
            .distinct()
            .toList()
    }

    fun setFusionWeights(value: FusionWeights) {
        val normalized = value.normalize()
        prefs.edit()
            .putString(KEY_FUSION_STATISTICAL_WEIGHT, roundWeight(normalized.statistical))
            .putString(KEY_FUSION_MULTIVARIATE_WEIGHT, roundWeight(normalized.multivariate))
            .putString(KEY_FUSION_SEQUENCE_WEIGHT, roundWeight(normalized.sequence))
            .putString(KEY_FUSION_LOCAL_WEIGHT, roundWeight(normalized.local))
            .putString(KEY_FUSION_TFLITE_WEIGHT, roundWeight(normalized.tflite))
            .putString(KEY_FUSION_REMOTE_WEIGHT, roundWeight(normalized.remote))
            .putString(KEY_FUSION_BEACON_WEIGHT, roundWeight(normalized.beacon))
            .putString(KEY_FUSION_DRIFT_WEIGHT, roundWeight(normalized.drift))
            .putString(KEY_FUSION_REPUTATION_WEIGHT, roundWeight(normalized.reputation))
            .putString(KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT, roundWeight(normalized.dataQualityPenalty))
            .putString(KEY_RESPONSE_ANOMALY_BLEND_WEIGHT, roundWeight(normalized.responseAnomalyBlend))
            .putString(KEY_RESPONSE_CONTEXT_BLEND_WEIGHT, roundWeight(normalized.responseContextBlend))
            .apply()
        configState.value = readConfig()
    }

    fun setAppProfile(appId: String, profile: AppProfile) {
        val root = JSONObject(prefs.getString(KEY_APP_PROFILES, "{}") ?: "{}")
        root.put(appId, profile.name)
        prefs.edit().putString(KEY_APP_PROFILES, root.toString()).apply()
        configState.value = readConfig()
    }

    fun getAppProfile(appId: String): AppProfile {
        val root = JSONObject(prefs.getString(KEY_APP_PROFILES, "{}") ?: "{}")
        val stored = root.optString(appId, "").ifBlank { null }
        return runCatching { AppProfile.valueOf(stored ?: "") }.getOrElse {
            defaultProfileForApp(appId)
        }
    }

    fun appProfilesSnapshot(): Map<String, AppProfile> {
        val root = JSONObject(prefs.getString(KEY_APP_PROFILES, "{}") ?: "{}")
        return buildMap {
            val keys = root.keys()
            while (keys.hasNext()) {
                val appId = keys.next()
                put(appId, sanitizeAppProfile(root.optString(appId)))
            }
        }
    }

    fun setAblationFlags(volume: Boolean, timing: Boolean, destination: Boolean) {
        prefs.edit()
            .putBoolean(KEY_ABLATE_VOLUME_FEATURES, volume)
            .putBoolean(KEY_ABLATE_TIMING_FEATURES, timing)
            .putBoolean(KEY_ABLATE_DESTINATION_FEATURES, destination)
            .apply()
        configState.value = readConfig()
    }

    fun setBaseThresholds(low: Double, profile: ThresholdProfile) {
        val normalized = ThresholdProfile(low = low, medium = profile.medium, high = profile.high).normalize()
        prefs.edit()
            .putString(KEY_LOW_THRESHOLD, roundWeight(normalized.low))
            .putString(KEY_MEDIUM_THRESHOLD, roundWeight(normalized.medium))
            .putString(KEY_HIGH_THRESHOLD, roundWeight(normalized.high))
            .apply()
        configState.value = readConfig()
    }

    fun getThresholdForApp(appId: String): ThresholdProfile {
        val config = readConfig()
        val overrides = JSONObject(prefs.getString(KEY_APP_THRESHOLD_OVERRIDES, "{}") ?: "{}")
        val value = overrides.optJSONObject(appId)
        if (value != null) {
            return ThresholdProfile(
                low = value.optDouble("low", config.lowThreshold),
                medium = value.optDouble("medium", config.mediumThreshold),
                high = value.optDouble("high", config.highThreshold)
            ).normalize()
        }

        return ThresholdProfile(
            low = config.lowThreshold,
            medium = config.mediumThreshold,
            high = config.highThreshold
        ).normalize()
    }

    fun thresholdOverridesSnapshot(base: ThresholdProfile): Map<String, ThresholdProfile> {
        val root = JSONObject(prefs.getString(KEY_APP_THRESHOLD_OVERRIDES, "{}") ?: "{}")
        return buildMap {
            val keys = root.keys()
            while (keys.hasNext()) {
                val appId = keys.next()
                val value = root.optJSONObject(appId) ?: continue
                put(
                    appId,
                    ThresholdProfile(
                        low = value.optDouble("low", base.low),
                        medium = value.optDouble("medium", base.medium),
                        high = value.optDouble("high", base.high)
                    ).normalize()
                )
            }
        }
    }

    fun setThresholdOverride(appId: String, profile: ThresholdProfile) {
        val normalized = profile.normalize()
        val root = JSONObject(prefs.getString(KEY_APP_THRESHOLD_OVERRIDES, "{}") ?: "{}")
        root.put(
            appId,
            JSONObject()
                .put("low", normalized.low)
                .put("medium", normalized.medium)
                .put("high", normalized.high)
        )
        prefs.edit().putString(KEY_APP_THRESHOLD_OVERRIDES, root.toString()).apply()
        configState.value = readConfig()
    }

    fun applyRemotePolicy(policy: RemotePolicy) {
        val before = readConfig()
        val normalizedThresholds = policy.defaultThresholds.normalize()
        val overrideRoot = JSONObject()
        policy.appThresholdOverrides.forEach { (appId, profile) ->
            val normalized = profile.normalize()
            overrideRoot.put(
                appId,
                JSONObject()
                    .put("low", normalized.low)
                    .put("medium", normalized.medium)
                    .put("high", normalized.high)
            )
        }
        val profileRoot = JSONObject()
        policy.appProfileOverrides.forEach { (appId, profileName) ->
            profileRoot.put(appId, sanitizeAppProfile(profileName).name)
        }
        val fusion = FusionWeights(
            statistical = policy.fusionWeights.statistical,
            multivariate = policy.fusionWeights.multivariate,
            sequence = policy.fusionWeights.sequence,
            local = policy.fusionWeights.local,
            tflite = policy.fusionWeights.tflite,
            remote = policy.fusionWeights.remote,
            beacon = policy.fusionWeights.beacon,
            drift = policy.fusionWeights.drift,
            reputation = policy.fusionWeights.reputation,
            dataQualityPenalty = policy.fusionWeights.dataQualityPenalty,
            responseAnomalyBlend = policy.fusionWeights.responseAnomalyBlend,
            responseContextBlend = policy.fusionWeights.responseContextBlend
        ).normalize()

        prefs.edit()
            .putString(KEY_LOW_THRESHOLD, normalizedThresholds.low.toString())
            .putString(KEY_MEDIUM_THRESHOLD, normalizedThresholds.medium.toString())
            .putString(KEY_HIGH_THRESHOLD, normalizedThresholds.high.toString())
            .putInt(KEY_POLICY_VERSION, policy.policyVersion)
            .putInt(KEY_RETENTION_DAYS, policy.retentionDays.coerceIn(1, 90))
            .putBoolean(KEY_EXPORT_ENABLED, policy.exportEnabled)
            .putBoolean(KEY_CAPTURE_ENABLED, policy.captureEnabled)
            .putString(KEY_DETECTION_MODEL, sanitizeDetectionModel(policy.detectionModel))
            .putString(KEY_SHADOW_MODEL, sanitizeShadowModel(policy.shadowModel).orEmpty())
            .putInt(KEY_FALSE_POSITIVE_BUDGET, policy.falsePositiveBudgetPerAppDay.coerceIn(1, 250))
            .putString(KEY_DRIFT_HIGH_THRESHOLD, roundWeight(policy.driftHighThreshold.coerceIn(0.1, 1.0)))
            .putString(KEY_THEME_MODE, sanitizeThemeMode(policy.themeMode).name)
            .putBoolean(KEY_DEBUG_MODE_ENABLED, policy.debugModeEnabled)
            .putBoolean(KEY_TEST_MODE_ENABLED, readConfig().testModeEnabled)
            .putString(KEY_FUSION_STATISTICAL_WEIGHT, roundWeight(fusion.statistical))
            .putString(KEY_FUSION_MULTIVARIATE_WEIGHT, roundWeight(fusion.multivariate))
            .putString(KEY_FUSION_SEQUENCE_WEIGHT, roundWeight(fusion.sequence))
            .putString(KEY_FUSION_LOCAL_WEIGHT, roundWeight(fusion.local))
            .putString(KEY_FUSION_TFLITE_WEIGHT, roundWeight(fusion.tflite))
            .putString(KEY_FUSION_REMOTE_WEIGHT, roundWeight(fusion.remote))
            .putString(KEY_FUSION_BEACON_WEIGHT, roundWeight(fusion.beacon))
            .putString(KEY_FUSION_DRIFT_WEIGHT, roundWeight(fusion.drift))
            .putString(KEY_FUSION_REPUTATION_WEIGHT, roundWeight(fusion.reputation))
            .putString(KEY_FUSION_DATA_QUALITY_PENALTY_WEIGHT, roundWeight(fusion.dataQualityPenalty))
            .putString(KEY_RESPONSE_ANOMALY_BLEND_WEIGHT, roundWeight(fusion.responseAnomalyBlend))
            .putString(KEY_RESPONSE_CONTEXT_BLEND_WEIGHT, roundWeight(fusion.responseContextBlend))
            .putBoolean(KEY_ABLATE_VOLUME_FEATURES, policy.disableVolumeFeatures)
            .putBoolean(KEY_ABLATE_TIMING_FEATURES, policy.disableTimingFeatures)
            .putBoolean(KEY_ABLATE_DESTINATION_FEATURES, policy.disableDestinationFeatures)
            .putString(KEY_APP_PROFILES, profileRoot.toString())
            .putString(KEY_APP_THRESHOLD_OVERRIDES, overrideRoot.toString())
            .apply {
                policy.protectedBrandsCsv?.let { putString(KEY_PROTECTED_BRANDS, normalizeProtectedBrandsCsv(it)) }
            }
            .apply()

        configState.value = readConfig()
        recordPolicySync(
            status = "success",
            diffSummary = buildPolicyDiffSummary(before, configState.value)
        )
    }

    fun getPolicySyncUrl(deviceIdPseudo: String): String {
        val base = readConfig().backendUrl.trimEnd('/')
        if (base.isBlank()) {
            return ""
        }
        return "$base/api/v1/policy/device/$deviceIdPseudo"
    }

    fun getHealthUrl(): String {
        val base = readConfig().backendUrl.trimEnd('/')
        if (base.isBlank()) {
            return ""
        }
        return "$base/health"
    }

    fun getDeviceHeartbeatUrl(): String {
        val base = readConfig().backendUrl.trimEnd('/')
        if (base.isBlank()) {
            return ""
        }
        return "$base/api/v1/device/heartbeat"
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

    fun getPseudonymousDeviceId(): String {
        return CryptoUtils.pseudonymousDeviceId(appContext, getDeviceSalt())
    }

    fun recordExportResult(sentCount: Int, error: String?) {
        val now = System.currentTimeMillis()
        val editor = prefs.edit()
            .putInt(KEY_LAST_EXPORT_SENT_COUNT, sentCount.coerceAtLeast(0))
            .putString(KEY_LAST_EXPORT_ERROR, error?.take(512))
        if (sentCount > 0 && error == null) {
            editor.putLong(KEY_LAST_EXPORT_SUCCESS_EPOCH, now)
        }
        editor.apply()
        configState.value = readConfig()
    }

    fun recordPolicySync(status: String, diffSummary: String?) {
        prefs.edit()
            .putLong(KEY_LAST_POLICY_SYNC_EPOCH, System.currentTimeMillis())
            .putString(KEY_LAST_POLICY_SYNC_STATUS, status.take(512))
            .putString(KEY_LAST_POLICY_DIFF_SUMMARY, diffSummary?.take(2048))
            .apply()
        configState.value = readConfig()
    }

    fun recordServerPing(status: String, detail: String?) {
        prefs.edit()
            .putLong(KEY_LAST_SERVER_PING_EPOCH, System.currentTimeMillis())
            .putString(KEY_LAST_SERVER_PING_STATUS, status.take(128))
            .putString(KEY_LAST_SERVER_PING_DETAIL, detail?.take(1024))
            .apply()
        configState.value = readConfig()
    }

    fun recordDeviceHeartbeat(status: String, detail: String?) {
        prefs.edit()
            .putLong(KEY_LAST_DEVICE_HEARTBEAT_EPOCH, System.currentTimeMillis())
            .putString(KEY_LAST_DEVICE_HEARTBEAT_STATUS, status.take(128))
            .putString(KEY_LAST_DEVICE_HEARTBEAT_DETAIL, detail?.take(1024))
            .apply()
        configState.value = readConfig()
    }

    private fun sanitizeDetectionModel(value: String?): String {
        val candidate = LEGACY_DETECTION_MODEL_ALIASES[value?.trim().orEmpty()] ?: value?.trim().orEmpty()
        return if (candidate in SUPPORTED_DETECTION_MODELS) {
            candidate
        } else {
            "ensemble_fusion"
        }
    }

    private fun sanitizeShadowModel(value: String?): String? {
        val candidate = LEGACY_DETECTION_MODEL_ALIASES[value?.trim().orEmpty()] ?: value?.trim().orEmpty()
        if (candidate.isBlank()) {
            return null
        }
        return if (candidate in SUPPORTED_DETECTION_MODELS) {
            candidate
        } else {
            null
        }
    }

    private fun sanitizeThemeMode(value: String?): ThemeMode {
        return runCatching {
            ThemeMode.valueOf(value?.trim().orEmpty().ifBlank { ThemeMode.SYSTEM.name })
        }.getOrDefault(ThemeMode.SYSTEM)
    }

    private fun sanitizePrivacyMode(mode: String?, legacyEnabled: Boolean): PrivacyMode {
        val normalized = mode?.trim().orEmpty().uppercase()
        return when (normalized) {
            PrivacyMode.OFF.name -> PrivacyMode.OFF
            PrivacyMode.LOW.name,
            "RESEARCH" -> PrivacyMode.LOW
            PrivacyMode.MEDIUM.name,
            "BALANCED" -> PrivacyMode.MEDIUM
            PrivacyMode.STRICT.name -> PrivacyMode.STRICT
            PrivacyMode.CUSTOM.name -> PrivacyMode.CUSTOM
            else -> if (legacyEnabled) PrivacyMode.MEDIUM else PrivacyMode.OFF
        }
    }

    private fun sanitizeAppProfile(value: String?): AppProfile {
        return runCatching {
            AppProfile.valueOf(value?.trim().orEmpty().ifBlank { AppProfile.DEFAULT.name })
        }.getOrDefault(AppProfile.DEFAULT)
    }

    private fun buildPolicyDiffSummary(before: EndpointConfig, after: EndpointConfig): String {
        val changes = mutableListOf<String>()
        if (before.policyVersion != after.policyVersion) {
            changes += "policy ${before.policyVersion} -> ${after.policyVersion}"
        }
        if (before.lowThreshold != after.lowThreshold || before.mediumThreshold != after.mediumThreshold || before.highThreshold != after.highThreshold) {
            changes += "thresholds ${"%.2f".format(before.lowThreshold)}/${"%.2f".format(before.mediumThreshold)}/${"%.2f".format(before.highThreshold)} -> ${"%.2f".format(after.lowThreshold)}/${"%.2f".format(after.mediumThreshold)}/${"%.2f".format(after.highThreshold)}"
        }
        if (before.exportEnabled != after.exportEnabled) {
            changes += "export ${before.exportEnabled} -> ${after.exportEnabled}"
        }
        if (before.captureEnabled != after.captureEnabled) {
            changes += "capture ${before.captureEnabled} -> ${after.captureEnabled}"
        }
        if (before.retentionDays != after.retentionDays) {
            changes += "retention ${before.retentionDays}d -> ${after.retentionDays}d"
        }
        if (before.detectionModel != after.detectionModel) {
            changes += "model ${before.detectionModel} -> ${after.detectionModel}"
        }
        if (before.shadowModel != after.shadowModel) {
            changes += "shadow ${before.shadowModel ?: "off"} -> ${after.shadowModel ?: "off"}"
        }
        if (before.falsePositiveBudgetPerAppDay != after.falsePositiveBudgetPerAppDay) {
            changes += "FP budget ${before.falsePositiveBudgetPerAppDay} -> ${after.falsePositiveBudgetPerAppDay}"
        }
        if (before.driftHighThreshold != after.driftHighThreshold) {
            changes += "drift threshold ${"%.2f".format(before.driftHighThreshold)} -> ${"%.2f".format(after.driftHighThreshold)}"
        }
        if (before.themeMode != after.themeMode) {
            changes += "theme ${before.themeMode.name.lowercase()} -> ${after.themeMode.name.lowercase()}"
        }
        if (before.debugModeEnabled != after.debugModeEnabled) {
            changes += "debug ${before.debugModeEnabled} -> ${after.debugModeEnabled}"
        }
        if (before.testModeEnabled != after.testModeEnabled) {
            changes += "test mode ${before.testModeEnabled} -> ${after.testModeEnabled}"
        }
        if (before.ablateVolumeFeatures != after.ablateVolumeFeatures) {
            changes += "disable volume features ${before.ablateVolumeFeatures} -> ${after.ablateVolumeFeatures}"
        }
        if (before.ablateTimingFeatures != after.ablateTimingFeatures) {
            changes += "disable timing features ${before.ablateTimingFeatures} -> ${after.ablateTimingFeatures}"
        }
        if (before.ablateDestinationFeatures != after.ablateDestinationFeatures) {
            changes += "disable destination features ${before.ablateDestinationFeatures} -> ${after.ablateDestinationFeatures}"
        }
        if (before.fusionWeights != after.fusionWeights) {
            changes += "fusion weights updated"
        }
        if (before.protectedBrandsCsv != after.protectedBrandsCsv) {
            changes += "protected brands updated"
        }
        return if (changes.isEmpty()) {
            "Policy synced with no visible changes."
        } else {
            changes.joinToString(" | ")
        }
    }

    private fun normalizeProtectedBrandsCsv(value: String): String {
        return value.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .joinToString("\n")
            .ifBlank { DEFAULT_PROTECTED_BRANDS }
    }

    private fun defaultProfileForApp(appId: String): AppProfile {
        return when {
            appId.startsWith("com.android.") || appId.startsWith("android.") -> AppProfile.SYSTEM
            appId in setOf(
                "com.android.chrome",
                "org.mozilla.firefox",
                "org.mozilla.firefox_beta",
                "org.mozilla.fenix",
                "com.microsoft.emmx",
                "com.brave.browser",
                "com.sec.android.app.sbrowser",
                "com.duckduckgo.mobile.android"
            ) -> AppProfile.BROWSER
            else -> AppProfile.DEFAULT
        }
    }
}
