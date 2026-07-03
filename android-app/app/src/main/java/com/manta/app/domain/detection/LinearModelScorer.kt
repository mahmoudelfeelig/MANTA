package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min

data class LinearModelSpec(
    val featureOrder: List<String>,
    val means: List<Double>,
    val scales: List<Double>,
    val weights: List<Double>,
    val bias: Double,
    val recommendedThreshold: Double,
    val appFamilyThresholds: Map<String, Double> = emptyMap(),
    val appIdThresholds: Map<String, Double> = emptyMap(),
    val inputTransform: String? = null
) {
    fun isValid(): Boolean {
        return featureOrder.isNotEmpty() &&
            featureOrder.size == means.size &&
            means.size == scales.size &&
            scales.size == weights.size
    }
}

class LinearModelScorer(
    private val spec: LinearModelSpec,
    private val sourceLabel: String = "linear-model"
) : AnomalyScorer {

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        if (!spec.isValid()) {
            return AnomalyScoreResult(
                score = 0.0,
                topFeatures = listOf("invalid_model"),
                featureContributions = emptyMap(),
                source = "$sourceLabel-invalid",
                confidence = 0.0,
                uncertainty = 1.0
            )
        }

        val featureValues = featureMap(window)
        var linear = spec.bias
        val contributions = linkedMapOf<String, Double>()
        spec.featureOrder.forEachIndexed { index, name ->
            val raw = featureValues[name] ?: 0.0
            val scale = spec.scales[index].let { if (it == 0.0) 1.0 else it }
            val normalized = (raw - spec.means[index]) / scale
            val weighted = spec.weights[index] * normalized
            contributions[name] = abs(weighted)
            linear += weighted
        }

        val rawScore = 1.0 / (1.0 + exp(-linear))
        val effectiveThreshold = thresholdForApp(window.appId)
        val score = calibrateScore(rawScore, effectiveThreshold)
        val topFeatures = contributions.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }
        val thresholdDistance = abs(score - spec.recommendedThreshold).coerceIn(0.0, 1.0)
        val confidence = (0.45 + 0.55 * thresholdDistance).coerceIn(0.0, 1.0)

        return AnomalyScoreResult(
            score = min(1.0, max(0.0, score)),
            topFeatures = topFeatures,
            featureContributions = contributions,
            source = sourceLabel,
            confidence = confidence,
            uncertainty = (1.0 - confidence).coerceIn(0.0, 1.0),
            diagnostics = mapOf(
                "threshold_distance" to thresholdDistance,
                "recommended_threshold" to spec.recommendedThreshold,
                "effective_threshold" to effectiveThreshold,
                "raw_score" to rawScore
            )
        )
    }

    private fun featureMap(window: FeatureWindow): Map<String, Double> {
        return FeatureInputTransforms.apply(spec.inputTransform, window.portableFeatureMap())
    }

    private fun thresholdForApp(appId: String): Double {
        spec.appIdThresholds[appId]?.let { return it }
        val family = deriveAppFamily(appId)
        return spec.appFamilyThresholds[family] ?: spec.recommendedThreshold
    }

    private fun calibrateScore(rawScore: Double, effectiveThreshold: Double): Double {
        return (rawScore * (spec.recommendedThreshold / effectiveThreshold.coerceIn(0.05, 1.0))).coerceIn(0.0, 1.0)
    }

    private fun deriveAppFamily(appId: String): String {
        val normalized = appId.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')
        return when {
            normalized.startsWith("service_") -> "service"
            normalized.startsWith("uid_") -> "system"
            listOf("chrome", "firefox", "browser", "opera", "edge", "safari", "duckduckgo", "brave").any { it in normalized } -> "browser"
            listOf("analytics", "telemetry", "doubleclick", "googleads", "scorecardresearch", "tracking").any { it in normalized } -> "telemetry"
            listOf("vpn", "ssh", "rdp", "teamviewer", "anydesk", "openvpn", "ipsec", "l2tp").any { it in normalized } -> "remote_access"
            listOf("gmail", "outlook", "telegram", "whatsapp", "fbmessenger", "facebook", "instagram", "snapchat", "twitter", "tiktok", "spotify", "netflix", "youtube").any { it in normalized } -> "consumer_app"
            listOf("android", "systemui", "gms", "play_services", "packageinstaller").any { it in normalized } -> "system"
            listOf("background", "daemon", "worker", "sensor", "watersensor", "temp_humidity").any { it in normalized } -> "background"
            listOf("spy", "rat", "mal", "phish", "attack", "anomaly", "bot").any { it in normalized } -> "malware"
            else -> "other_app"
        }
    }
}
