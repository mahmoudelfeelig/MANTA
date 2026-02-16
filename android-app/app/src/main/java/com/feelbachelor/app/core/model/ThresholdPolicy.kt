package com.feelbachelor.app.core.model

data class ThresholdProfile(
    val medium: Double,
    val high: Double
) {
    fun normalize(): ThresholdProfile {
        val mediumBound = medium.coerceIn(0.0, 1.0)
        val highBound = high.coerceIn(mediumBound, 1.0)
        return ThresholdProfile(mediumBound, highBound)
    }
}

data class RemotePolicy(
    val policyVersion: Int,
    val defaultThresholds: ThresholdProfile,
    val appThresholdOverrides: Map<String, ThresholdProfile>,
    val exportEnabled: Boolean,
    val retentionDays: Int
)
