package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.sqrt

data class DriftResult(
    val score: Double,
    val topFeatures: List<String>,
    val featureScores: Map<String, Double>,
    val mature: Boolean
)

private data class DriftStat(
    var count: Int = 0,
    var mean: Double = 0.0,
    var m2: Double = 0.0
) {
    fun observe(value: Double) {
        count += 1
        val delta = value - mean
        mean += delta / count
        val delta2 = value - mean
        m2 += delta * delta2
    }

    fun stdDev(): Double {
        if (count < 2) {
            return 1.0
        }
        return sqrt((m2 / (count - 1)).coerceAtLeast(1e-9))
    }
}

class ConceptDriftMonitor(
    private val minMatureSamples: Int = 25,
    private val normalizer: Double = 5.0
) {
    private val state = mutableMapOf<String, MutableMap<String, DriftStat>>()

    @Synchronized
    fun evaluate(window: FeatureWindow): DriftResult {
        val appState = state.getOrPut(window.appId) { mutableMapOf() }
        val features = featureMap(window)
        val featureScores = linkedMapOf<String, Double>()
        var matureCount = 0

        features.forEach { (name, value) ->
            val stat = appState.getOrPut(name) { DriftStat() }
            if (stat.count >= minMatureSamples) {
                matureCount += 1
            }
            val z = abs((value - stat.mean) / stat.stdDev())
            featureScores[name] = z
            stat.observe(value)
        }

        val matureRatio = matureCount.toDouble() / features.size.toDouble()
        val raw = featureScores.values.average().takeIf { !it.isNaN() } ?: 0.0
        val score = (raw / normalizer).coerceIn(0.0, 1.0) * matureRatio.coerceIn(0.0, 1.0)
        val top = featureScores.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }

        return DriftResult(
            score = score.coerceIn(0.0, 1.0),
            topFeatures = top,
            featureScores = featureScores,
            mature = matureRatio >= 0.5
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
            "novelty_score" to window.noveltyScore,
            "connection_frequency_delta" to window.connectionFrequencyDelta,
            "bytes_per_flow" to window.bytesPerFlow,
            "destination_diversity" to window.destinationDiversity,
            "activity_ratio" to window.activityRatio,
            "byte_rate" to window.byteRate,
            "packet_rate" to window.packetRate,
            "mean_duration_ms" to window.meanDurationMillis,
            "duration_jitter" to window.durationJitter,
            "port_diversity" to window.portDiversity,
            "protocol_diversity" to window.protocolDiversity,
            "packet_imbalance" to window.packetImbalance,
            "hour_of_day" to window.hourOfDay.toDouble(),
            "is_weekend" to if (window.isWeekend) 1.0 else 0.0
        )
    }
}
