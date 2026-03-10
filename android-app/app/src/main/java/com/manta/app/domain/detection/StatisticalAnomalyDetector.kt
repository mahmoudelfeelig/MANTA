package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sqrt

private const val MIN_WINDOWS_FOR_STABLE_SCORING = 15
private const val MIN_FEATURE_SAMPLES = 12
private const val MIN_STD_DEV = 0.05
private const val ZSCORE_NORMALIZER = 6.5
private const val SHORT_TERM_ALPHA = 0.35
private const val MEDIUM_TERM_ALPHA = 0.12
private const val LONG_TERM_ALPHA = 0.04

private val FEATURE_WEIGHTS = mapOf(
    "flow_count" to 0.70,
    "bytes_out" to 0.60,
    "bytes_in" to 0.60,
    "mean_packet_size" to 0.65,
    "outbound_ratio" to 0.45,
    "burstiness" to 0.22,
    "novelty" to 1.10,
    "conn_freq_delta" to 0.22,
    "periodic_beacon" to 1.15,
    "bytes_per_flow" to 0.60,
    "destination_diversity" to 0.80,
    "activity_ratio" to 0.45,
    "byte_rate" to 0.58,
    "packet_rate" to 0.48,
    "mean_duration_ms" to 0.34,
    "duration_jitter" to 0.42,
    "port_diversity" to 0.58,
    "protocol_diversity" to 0.32,
    "packet_imbalance" to 0.28,
    "small_flow_ratio" to 0.24,
    "high_port_ratio" to 0.18
)

private data class RunningStat(
    var count: Int = 0,
    var mean: Double = 0.0,
    var variance: Double = MIN_STD_DEV * MIN_STD_DEV
) {
    fun update(value: Double, alpha: Double) {
        if (count == 0) {
            count = 1
            mean = value
            variance = MIN_STD_DEV * MIN_STD_DEV
            return
        }
        count += 1
        val boundedAlpha = alpha.coerceIn(0.01, 0.95)
        val delta = value - mean
        mean += boundedAlpha * delta
        variance = ((1.0 - boundedAlpha) * variance) + (boundedAlpha * delta * delta)
    }

    fun stdDev(): Double = sqrt(variance.coerceAtLeast(MIN_STD_DEV * MIN_STD_DEV))
}

private data class MultiScaleStats(
    val shortTerm: RunningStat = RunningStat(),
    val mediumTerm: RunningStat = RunningStat(),
    val longTerm: RunningStat = RunningStat(),
) {
    fun update(value: Double, aggressive: Boolean = false) {
        shortTerm.update(value, alpha = if (aggressive) 0.55 else SHORT_TERM_ALPHA)
        mediumTerm.update(value, alpha = if (aggressive) 0.28 else MEDIUM_TERM_ALPHA)
        longTerm.update(value, alpha = if (aggressive) 0.10 else LONG_TERM_ALPHA)
    }
}

private data class FeedbackProfile(
    var benignCount: Int = 0,
    var dangerousCount: Int = 0,
    val benignExemplar: MutableMap<String, RunningStat> = mutableMapOf(),
    val dangerousExemplar: MutableMap<String, RunningStat> = mutableMapOf(),
)

class StatisticalAnomalyDetector : AnomalyScorer {
    private val stats = mutableMapOf<String, MutableMap<String, MultiScaleStats>>()
    private val contextStats = mutableMapOf<String, MutableMap<String, MultiScaleStats>>()
    private val appWindowCounts = mutableMapOf<String, Int>()
    private val feedbackProfiles = mutableMapOf<String, FeedbackProfile>()

    @Synchronized
    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val appStats = stats.getOrPut(window.appId) { mutableMapOf() }
        val contextKey = "${window.appId}|h${window.hourOfDay}|w${if (window.isWeekend) 1 else 0}"
        val ctxStats = contextStats.getOrPut(contextKey) { mutableMapOf() }
        val feedback = feedbackProfiles.getOrPut(window.appId) { FeedbackProfile() }
        val appWindowCount = (appWindowCounts[window.appId] ?: 0) + 1
        appWindowCounts[window.appId] = appWindowCount
        val shouldUpdateBaseline = !(
            window.noveltyScore >= 0.75 ||
                window.periodicBeaconScore >= 0.65 ||
                (window.destinationDiversity >= 0.9 && window.connectionFrequencyDelta >= 1.0)
            )

        val features = featureMap(window)

        var matureFeatureCount = 0
        val zScores = features.mapValues { (name, value) ->
            val global = appStats.getOrPut(name) { MultiScaleStats() }
            val context = ctxStats.getOrPut(name) { MultiScaleStats() }
            if (global.longTerm.count >= MIN_FEATURE_SAMPLES) {
                matureFeatureCount += 1
            }
            val globalZ = multiscaleZ(value = value, stats = global)
            val contextZ = multiscaleZ(value = value, stats = context)

            if (shouldUpdateBaseline) {
                global.update(value)
                context.update(value)
            }

            val contextWeight = if (context.mediumTerm.count >= (MIN_FEATURE_SAMPLES / 2)) 0.35 else 0.0
            ((1.0 - contextWeight) * globalZ) + (contextWeight * contextZ)
        }

        val weightedValues = zScores.map { (feature, score) ->
            score * (FEATURE_WEIGHTS[feature] ?: 1.0)
        }
        val weightedNormalizer = zScores.keys.sumOf { FEATURE_WEIGHTS[it] ?: 1.0 }.coerceAtLeast(1e-9)
        val raw = (weightedValues.sum() / weightedNormalizer).takeIf { !it.isNaN() } ?: 0.0
        val normalized = min(1.0, max(0.0, raw / ZSCORE_NORMALIZER))
        val warmupFactor = min(1.0, appWindowCount.toDouble() / MIN_WINDOWS_FOR_STABLE_SCORING.toDouble())
        val maturityRatio = matureFeatureCount.toDouble() / features.size.toDouble()
        val maturityFactor = (0.35 + (0.65 * maturityRatio)).coerceIn(0.35, 1.0)
        val corroboration = listOf(
            zScores["novelty"] ?: 0.0,
            zScores["periodic_beacon"] ?: 0.0,
            zScores["destination_diversity"] ?: 0.0,
            zScores["port_diversity"] ?: 0.0
        ).average()
        val burstOnlyPattern =
            (
                (zScores["burstiness"] ?: 0.0) > 1.3 ||
                    (zScores["conn_freq_delta"] ?: 0.0) > 1.3 ||
                    (zScores["byte_rate"] ?: 0.0) > 1.3 ||
                    (zScores["packet_rate"] ?: 0.0) > 1.3
                ) &&
                corroboration < 0.55
        val burstPenalty = if (burstOnlyPattern) 0.58 else 1.0
        val startupSpikePattern =
            appWindowCount <= 6 &&
                ((zScores["flow_count"] ?: 0.0) > 1.4 || (zScores["conn_freq_delta"] ?: 0.0) > 1.5) &&
                (zScores["novelty"] ?: 0.0) < 0.75 &&
                (zScores["periodic_beacon"] ?: 0.0) < 0.90
        val startupPenalty = if (startupSpikePattern) 0.52 else 1.0
        val interactivePenalty =
            if (
                (zScores["activity_ratio"] ?: 0.0) > 0.8 &&
                (zScores["novelty"] ?: 0.0) < 0.65 &&
                (zScores["destination_diversity"] ?: 0.0) < 0.85
            ) {
                0.76
            } else {
                1.0
            }
        val benignSimilarityPenalty = exemplarSimilarityPenalty(features, feedback.benignExemplar)
        val dangerousSimilarityBoost = exemplarSimilarityBoost(features, feedback.dangerousExemplar)
        val bounded = (
            (normalized * warmupFactor * maturityFactor * burstPenalty * startupPenalty * interactivePenalty * benignSimilarityPenalty) +
                dangerousSimilarityBoost
            ).coerceIn(0.0, 1.0)
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
                "data_quality_score" to window.dataQualityScore,
                "adaptation_frozen" to if (shouldUpdateBaseline) 0.0 else 1.0,
                "startup_penalty" to startupPenalty,
                "interactive_penalty" to interactivePenalty,
                "feedback_benign_count" to feedback.benignCount.toDouble(),
                "feedback_dangerous_count" to feedback.dangerousCount.toDouble(),
                "feedback_benign_penalty" to benignSimilarityPenalty,
                "feedback_dangerous_boost" to dangerousSimilarityBoost
            )
        )
    }

    @Synchronized
    fun recordFeedback(window: FeatureWindow, dangerous: Boolean) {
        val features = featureMap(window)
        val appStats = stats.getOrPut(window.appId) { mutableMapOf() }
        val contextKey = "${window.appId}|h${window.hourOfDay}|w${if (window.isWeekend) 1 else 0}"
        val ctxStats = contextStats.getOrPut(contextKey) { mutableMapOf() }
        val feedback = feedbackProfiles.getOrPut(window.appId) { FeedbackProfile() }
        features.forEach { (name, value) ->
            if (!dangerous) {
                appStats.getOrPut(name) { MultiScaleStats() }.update(value, aggressive = true)
                ctxStats.getOrPut(name) { MultiScaleStats() }.update(value, aggressive = true)
                feedback.benignExemplar.getOrPut(name) { RunningStat() }.update(value, alpha = 0.35)
            } else {
                feedback.dangerousExemplar.getOrPut(name) { RunningStat() }.update(value, alpha = 0.25)
            }
        }
        if (dangerous) {
            feedback.dangerousCount += 1
        } else {
            feedback.benignCount += 1
        }
    }

    private fun multiscaleZ(value: Double, stats: MultiScaleStats): Double {
        val shortWeight = if (stats.shortTerm.count >= 4) 0.45 else 0.0
        val mediumWeight = if (stats.mediumTerm.count >= 8) 0.35 else 0.0
        val longWeight = if (stats.longTerm.count >= MIN_FEATURE_SAMPLES) 0.20 else 0.0
        val totalWeight = (shortWeight + mediumWeight + longWeight).coerceAtLeast(1e-9)
        val shortZ = abs((value - stats.shortTerm.mean) / stats.shortTerm.stdDev().coerceAtLeast(MIN_STD_DEV))
        val mediumZ = abs((value - stats.mediumTerm.mean) / stats.mediumTerm.stdDev().coerceAtLeast(MIN_STD_DEV))
        val longZ = abs((value - stats.longTerm.mean) / stats.longTerm.stdDev().coerceAtLeast(MIN_STD_DEV))
        return ((shortWeight * shortZ) + (mediumWeight * mediumZ) + (longWeight * longZ)) / totalWeight
    }

    private fun exemplarSimilarityPenalty(
        features: Map<String, Double>,
        exemplar: Map<String, RunningStat>
    ): Double {
        if (exemplar.isEmpty()) {
            return 1.0
        }
        val meanDistance = features.entries.mapNotNull { (name, value) ->
            val stat = exemplar[name] ?: return@mapNotNull null
            abs(value - stat.mean) / stat.stdDev().coerceAtLeast(MIN_STD_DEV)
        }.average()
        if (meanDistance.isNaN()) {
            return 1.0
        }
        return (1.0 - (0.18 * (1.0 / (1.0 + meanDistance)))).coerceIn(0.78, 1.0)
    }

    private fun exemplarSimilarityBoost(
        features: Map<String, Double>,
        exemplar: Map<String, RunningStat>
    ): Double {
        if (exemplar.isEmpty()) {
            return 0.0
        }
        val meanDistance = features.entries.mapNotNull { (name, value) ->
            val stat = exemplar[name] ?: return@mapNotNull null
            abs(value - stat.mean) / stat.stdDev().coerceAtLeast(MIN_STD_DEV)
        }.average()
        if (meanDistance.isNaN()) {
            return 0.0
        }
        return (0.12 * (1.0 / (1.0 + meanDistance))).coerceIn(0.0, 0.12)
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
            "conn_freq_delta" to window.connectionFrequencyDelta,
            "periodic_beacon" to window.periodicBeaconScore,
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
            "small_flow_ratio" to window.smallFlowRatio,
            "high_port_ratio" to window.highPortRatio
        )
    }
}
