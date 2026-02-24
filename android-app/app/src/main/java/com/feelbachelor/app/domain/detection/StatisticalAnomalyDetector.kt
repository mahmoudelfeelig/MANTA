package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

private const val MIN_WINDOWS_FOR_STABLE_SCORING = 15
private const val MIN_FEATURE_SAMPLES = 12
private const val MIN_STD_DEV = 0.05
private const val ZSCORE_NORMALIZER = 6.5

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
    private val contextStats = mutableMapOf<String, MutableMap<String, RunningStat>>()
    private val appWindowCounts = mutableMapOf<String, Int>()

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val appStats = stats.getOrPut(window.appId) { mutableMapOf() }
        val contextKey = "${window.appId}|h${window.hourOfDay}|w${if (window.isWeekend) 1 else 0}"
        val ctxStats = contextStats.getOrPut(contextKey) { mutableMapOf() }
        val appWindowCount = (appWindowCounts[window.appId] ?: 0) + 1
        appWindowCounts[window.appId] = appWindowCount

        val features = mapOf(
            "flow_count" to window.flowCount.toDouble(),
            "bytes_out" to window.totalBytesOut.toDouble(),
            "bytes_in" to window.totalBytesIn.toDouble(),
            "mean_packet_size" to window.meanPacketSize,
            "outbound_ratio" to window.outboundRatio,
            "burstiness" to window.burstiness,
            "novelty" to window.noveltyScore,
            "conn_freq_delta" to window.connectionFrequencyDelta,
            "periodic_beacon" to window.periodicBeaconScore
        )

        var matureFeatureCount = 0
        val zScores = features.mapValues { (name, value) ->
            val global = appStats.getOrPut(name) { RunningStat() }
            val context = ctxStats.getOrPut(name) { RunningStat() }
            if (global.count >= MIN_FEATURE_SAMPLES) {
                matureFeatureCount += 1
            }
            val globalStd = global.stdDev().coerceAtLeast(MIN_STD_DEV)
            val globalZ = abs((value - global.mean) / globalStd)
            val contextStd = context.stdDev().coerceAtLeast(MIN_STD_DEV)
            val contextZ = abs((value - context.mean) / contextStd)

            global.update(value)
            context.update(value)

            val contextWeight = if (context.count >= (MIN_FEATURE_SAMPLES / 2)) 0.35 else 0.0
            ((1.0 - contextWeight) * globalZ) + (contextWeight * contextZ)
        }

        val raw = zScores.values.average().takeIf { !it.isNaN() } ?: 0.0
        val normalized = min(1.0, max(0.0, raw / ZSCORE_NORMALIZER))
        val warmupFactor = min(1.0, appWindowCount.toDouble() / MIN_WINDOWS_FOR_STABLE_SCORING.toDouble())
        val maturityRatio = matureFeatureCount.toDouble() / features.size.toDouble()
        val maturityFactor = (0.35 + (0.65 * maturityRatio)).coerceIn(0.35, 1.0)
        val bounded = (normalized * warmupFactor * maturityFactor).coerceIn(0.0, 1.0)
        val uncertainty = (1.0 - ((warmupFactor + maturityFactor) / 2.0)).coerceIn(0.0, 1.0)
        val confidence = (1.0 - uncertainty).coerceIn(0.0, 1.0)
        val topFeatures = zScores.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }

        return AnomalyScoreResult(
            score = bounded,
            topFeatures = topFeatures,
            featureContributions = zScores,
            source = "statistical",
            confidence = confidence,
            uncertainty = uncertainty,
            diagnostics = mapOf(
                "warmup_factor" to warmupFactor,
                "maturity_ratio" to maturityRatio,
                "data_quality_score" to window.dataQualityScore
            )
        )
    }
}
