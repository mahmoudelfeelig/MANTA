package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow
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
    val recommendedThreshold: Double
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

        val score = 1.0 / (1.0 + exp(-linear))
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
                "recommended_threshold" to spec.recommendedThreshold
            )
        )
    }

    private fun featureMap(window: FeatureWindow): Map<String, Double> {
        return mapOf(
            "flow_count" to window.flowCount.toDouble(),
            "bytes_out" to window.totalBytesOut.toDouble(),
            "bytes_in" to window.totalBytesIn.toDouble(),
            "mean_packet_size" to window.meanPacketSize,
            "outbound_ratio" to window.outboundRatio,
            "burstiness" to window.burstiness,
            "novelty" to window.noveltyScore,
            "conn_freq_delta" to window.connectionFrequencyDelta
        )
    }
}
