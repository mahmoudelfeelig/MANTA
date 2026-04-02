package com.manta.app.core.model

import org.json.JSONObject

object RemotePolicyParser {
    fun parse(rawJson: String): RemotePolicy {
        val root = JSONObject(rawJson)
        val policyNode = root.optJSONObject("policy") ?: root

        val thresholds = policyNode.optJSONObject("default_thresholds") ?: JSONObject()
        val defaultThresholds = ThresholdProfile(
            low = thresholds.optDouble("low", 0.3),
            medium = thresholds.optDouble("medium", 0.6),
            high = thresholds.optDouble("high", 0.85)
        ).normalize()

        val overridesObj = policyNode.optJSONObject("app_threshold_overrides") ?: JSONObject()
        val overrides = mutableMapOf<String, ThresholdProfile>()
        overridesObj.keys().forEach { appId ->
            val value = overridesObj.optJSONObject(appId) ?: return@forEach
            overrides[appId] = ThresholdProfile(
                low = value.optDouble("low", defaultThresholds.low),
                medium = value.optDouble("medium", defaultThresholds.medium),
                high = value.optDouble("high", defaultThresholds.high)
            ).normalize()
        }

        val fusionNode = policyNode.optJSONObject("fusion_weights") ?: JSONObject()
        val appProfilesNode = policyNode.optJSONObject("app_profile_overrides") ?: JSONObject()
        val appProfiles = mutableMapOf<String, String>()
        appProfilesNode.keys().forEach { appId ->
            val profile = appProfilesNode.optString(appId, "").trim()
            if (profile.isNotBlank()) {
                appProfiles[appId] = profile
            }
        }

        return RemotePolicy(
            policyVersion = policyNode.optInt("policy_version", 1),
            defaultThresholds = defaultThresholds,
            appThresholdOverrides = overrides,
            exportEnabled = policyNode.optBoolean("export_enabled", true),
            retentionDays = policyNode.optInt("retention_days", 90).coerceIn(1, 90),
            detectionModel = policyNode.optString("detection_model", "ensemble_fusion"),
            shadowModel = policyNode.optString("shadow_model", "").takeIf { it.isNotBlank() },
            falsePositiveBudgetPerAppDay = policyNode.optInt("false_positive_budget_per_app_day", 12).coerceIn(1, 250),
            driftHighThreshold = policyNode.optDouble("drift_high_threshold", 0.65).coerceIn(0.1, 1.0),
            captureEnabled = policyNode.optBoolean("capture_enabled", true),
            themeMode = policyNode.optString("theme_mode", "SYSTEM").ifBlank { "SYSTEM" },
            debugModeEnabled = policyNode.optBoolean("debug_mode_enabled", false),
            fusionWeights = RemoteFusionWeights(
                statistical = fusionNode.optDouble("statistical", 0.28),
                multivariate = fusionNode.optDouble("multivariate", 0.20),
                sequence = fusionNode.optDouble("sequence", 0.12),
                linear = fusionNode.optDouble("linear", 0.16),
                tflite = fusionNode.optDouble("tflite", 0.12),
                remote = fusionNode.optDouble("remote", 0.12),
                beacon = fusionNode.optDouble("beacon", 0.15),
                drift = fusionNode.optDouble("drift", 0.10),
                reputation = fusionNode.optDouble("reputation", 0.18),
                dataQualityPenalty = fusionNode.optDouble("data_quality_penalty", 0.10),
                responseAnomalyBlend = fusionNode.optDouble("response_anomaly", 0.82),
                responseContextBlend = fusionNode.optDouble("response_context", 0.18)
            ),
            disableVolumeFeatures = policyNode.optBoolean("disable_volume_features", false),
            disableTimingFeatures = policyNode.optBoolean("disable_timing_features", false),
            disableDestinationFeatures = policyNode.optBoolean("disable_destination_features", false),
            appProfileOverrides = appProfiles,
            protectedBrandsCsv = policyNode.optString("protected_brands_csv", "").takeIf { it.isNotBlank() }
        )
    }
}
