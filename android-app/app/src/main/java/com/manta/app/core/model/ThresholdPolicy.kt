package com.manta.app.core.model

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

data class RemoteFusionWeights(
    val statistical: Double = 0.28,
    val multivariate: Double = 0.20,
    val sequence: Double = 0.12,
    val linear: Double = 0.16,
    val tflite: Double = 0.12,
    val remote: Double = 0.12,
    val beacon: Double = 0.15,
    val drift: Double = 0.10,
    val reputation: Double = 0.18,
    val dataQualityPenalty: Double = 0.10,
    val responseAnomalyBlend: Double = 0.82,
    val responseContextBlend: Double = 0.18
)

data class RemotePolicy(
    val policyVersion: Int,
    val defaultThresholds: ThresholdProfile,
    val appThresholdOverrides: Map<String, ThresholdProfile>,
    val exportEnabled: Boolean,
    val retentionDays: Int,
    val detectionModel: String = "ensemble_fusion",
    val shadowModel: String? = null,
    val falsePositiveBudgetPerAppDay: Int = 12,
    val driftHighThreshold: Double = 0.65,
    val captureEnabled: Boolean = true,
    val themeMode: String = "SYSTEM",
    val debugModeEnabled: Boolean = false,
    val fusionWeights: RemoteFusionWeights = RemoteFusionWeights(),
    val disableVolumeFeatures: Boolean = false,
    val disableTimingFeatures: Boolean = false,
    val disableDestinationFeatures: Boolean = false,
    val appProfileOverrides: Map<String, String> = emptyMap()
)
