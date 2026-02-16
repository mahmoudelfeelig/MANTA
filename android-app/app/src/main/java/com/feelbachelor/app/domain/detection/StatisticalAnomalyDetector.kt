package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

private data class RunningStat(
    var count: Int = 0,
    var mean: Double = 0.0,
    var m2: Double = 0.0
) {
    fun update(value: Double) {
        count += 1
        val delta = value - mean
        mean += delta / count
        val delta2 = value - mean
        m2 += delta * delta2
    }

    fun stdDev(): Double = if (count > 1) sqrt(m2 / (count - 1)) else 1.0
}

class StatisticalAnomalyDetector : AnomalyScorer {
    private val stats = mutableMapOf<String, MutableMap<String, RunningStat>>()

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val appStats = stats.getOrPut(window.appId) { mutableMapOf() }

        val features = mapOf(
            "flow_count" to window.flowCount.toDouble(),
            "bytes_out" to window.totalBytesOut.toDouble(),
            "bytes_in" to window.totalBytesIn.toDouble(),
            "mean_packet_size" to window.meanPacketSize,
            "outbound_ratio" to window.outboundRatio,
            "burstiness" to window.burstiness,
            "novelty" to window.noveltyScore,
            "conn_freq_delta" to window.connectionFrequencyDelta
        )

        val zScores = features.mapValues { (name, value) ->
            val stat = appStats.getOrPut(name) { RunningStat() }
            val std = stat.stdDev().coerceAtLeast(0.001)
            val z = abs((value - stat.mean) / std)
            stat.update(value)
            z
        }

        val raw = zScores.values.average().takeIf { !it.isNaN() } ?: 0.0
        val bounded = min(1.0, max(0.0, raw / 6.0))
        val topFeatures = zScores.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }

        return AnomalyScoreResult(
            score = bounded,
            topFeatures = topFeatures,
            source = "statistical"
        )
    }
}
