package com.feelbachelor.app.core.model

import org.json.JSONObject

object RemotePolicyParser {
    fun parse(rawJson: String): RemotePolicy {
        val root = JSONObject(rawJson)
        val policyNode = root.optJSONObject("policy") ?: root

        val thresholds = policyNode.optJSONObject("default_thresholds") ?: JSONObject()
        val defaultThresholds = ThresholdProfile(
            medium = thresholds.optDouble("medium", 0.6),
            high = thresholds.optDouble("high", 0.85)
        ).normalize()

        val overridesObj = policyNode.optJSONObject("app_threshold_overrides") ?: JSONObject()
        val overrides = mutableMapOf<String, ThresholdProfile>()
        overridesObj.keys().forEach { appId ->
            val value = overridesObj.optJSONObject(appId) ?: return@forEach
            overrides[appId] = ThresholdProfile(
                medium = value.optDouble("medium", defaultThresholds.medium),
                high = value.optDouble("high", defaultThresholds.high)
            ).normalize()
        }

        return RemotePolicy(
            policyVersion = policyNode.optInt("policy_version", 1),
            defaultThresholds = defaultThresholds,
            appThresholdOverrides = overrides,
            exportEnabled = policyNode.optBoolean("export_enabled", true),
            retentionDays = policyNode.optInt("retention_days", 7).coerceIn(1, 90),
            detectionModel = policyNode.optString("detection_model", "ensemble_fusion"),
            shadowModel = policyNode.optString("shadow_model", "").takeIf { it.isNotBlank() },
            falsePositiveBudgetPerAppDay = policyNode.optInt("false_positive_budget_per_app_day", 12).coerceIn(1, 250),
            driftHighThreshold = policyNode.optDouble("drift_high_threshold", 0.65).coerceIn(0.1, 1.0)
        )
    }
}
