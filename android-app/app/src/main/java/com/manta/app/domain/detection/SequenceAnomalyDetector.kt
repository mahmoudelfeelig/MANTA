package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.abs

private data class SequenceTransitionStats(
    var totalTransitions: Int = 0,
    val transitionCounts: MutableMap<String, MutableMap<String, Int>> = mutableMapOf(),
    var lastState: String? = null,
    var lastNovelty: Double = 0.0,
    var lastDiversity: Double = 0.0,
    var lastByteRate: Double = 0.0,
    var lastPacketRate: Double = 0.0,
    var lastPeriodicity: Double = 0.0,
)

class SequenceAnomalyDetector(
    private val minTransitions: Int = 8,
    private val adaptationRate: Double = 0.12,
) : AnomalyScorer {
    private val perAppState = mutableMapOf<String, SequenceTransitionStats>()

    @Synchronized
    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val state = perAppState.getOrPut(window.appId) { SequenceTransitionStats() }
        val currentState = bucketState(window)
        val previousState = state.lastState

        val rarityScore = transitionRarity(state, previousState, currentState)
        val temporalShift = temporalShiftScore(window, state)
        val periodicityBreak = (window.periodicBeaconScore - state.lastPeriodicity).coerceAtLeast(0.0)
        val noveltyBreak = (window.noveltyScore - state.lastNovelty).coerceAtLeast(0.0)
        val score = (
            (0.52 * rarityScore) +
                (0.28 * temporalShift) +
                (0.12 * periodicityBreak) +
                (0.08 * noveltyBreak)
            ).coerceIn(0.0, 1.0)
        val confidence = (state.totalTransitions.toDouble() / (minTransitions.toDouble() * 1.5))
            .coerceIn(0.20, 0.96)
        val contributions = linkedMapOf(
            "sequence_transition_rarity" to rarityScore,
            "sequence_temporal_shift" to temporalShift,
            "sequence_periodicity_break" to periodicityBreak,
            "sequence_novelty_break" to noveltyBreak,
        )

        if (score < 0.90 || window.noveltyScore < 0.95) {
            updateState(state, previousState, currentState, window)
        }

        return AnomalyScoreResult(
            score = score,
            topFeatures = contributions.entries.sortedByDescending { it.value }.take(4).map { it.key },
            featureContributions = contributions,
            source = "sequence",
            confidence = confidence,
            uncertainty = (1.0 - confidence).coerceIn(0.0, 1.0),
            diagnostics = mapOf(
                "sequence_total_transitions" to state.totalTransitions.toDouble(),
                "sequence_adaptation_rate" to adaptationRate,
            ),
            anomalyScore = score,
            contextScore = 0.0,
            responseScore = score,
        )
    }

    private fun transitionRarity(
        state: SequenceTransitionStats,
        previousState: String?,
        currentState: String,
    ): Double {
        if (previousState == null || state.totalTransitions < minTransitions) {
            return 0.0
        }
        val outgoing = state.transitionCounts[previousState].orEmpty()
        val totalOutgoing = outgoing.values.sum().coerceAtLeast(1)
        val observed = outgoing[currentState] ?: 0
        val smoothedProbability = (observed + 1.0) / (totalOutgoing + outgoing.size + 1.0)
        return (1.0 - smoothedProbability).coerceIn(0.0, 1.0)
    }

    private fun temporalShiftScore(window: FeatureWindow, state: SequenceTransitionStats): Double {
        if (state.totalTransitions < 2) {
            return 0.0
        }
        val diversityShift = abs(window.destinationDiversity - state.lastDiversity)
        val noveltyShift = abs(window.noveltyScore - state.lastNovelty)
        val byteRateShift = normalizedShift(window.byteRate, state.lastByteRate)
        val packetRateShift = normalizedShift(window.packetRate, state.lastPacketRate)
        return (
            (0.34 * diversityShift) +
                (0.28 * noveltyShift) +
                (0.22 * byteRateShift) +
                (0.16 * packetRateShift)
            ).coerceIn(0.0, 1.0)
    }

    private fun normalizedShift(current: Double, previous: Double): Double {
        val baseline = maxOf(abs(previous), 1.0)
        return (abs(current - previous) / baseline).coerceIn(0.0, 1.0)
    }

    private fun bucketState(window: FeatureWindow): String {
        val noveltyBucket = when {
            window.noveltyScore >= 0.85 -> "exploratory"
            window.noveltyScore >= 0.45 -> "mixed"
            else -> "stable"
        }
        val trafficBucket = when {
            window.byteRate >= 40_000.0 || window.flowCount >= 24 -> "burst"
            window.byteRate >= 8_000.0 || window.flowCount >= 8 -> "active"
            else -> "quiet"
        }
        val destinationBucket = when {
            window.destinationDiversity >= 0.80 -> "spread"
            window.destinationDiversity >= 0.35 -> "varied"
            else -> "focused"
        }
        val transportBucket = when {
            window.protocolDiversity >= 0.60 || window.portDiversity >= 0.60 -> "mixed"
            window.highPortRatio >= 0.75 -> "high_port"
            else -> "narrow"
        }
        return "$noveltyBucket|$trafficBucket|$destinationBucket|$transportBucket"
    }

    private fun updateState(
        state: SequenceTransitionStats,
        previousState: String?,
        currentState: String,
        window: FeatureWindow,
    ) {
        if (previousState != null) {
            val outgoing = state.transitionCounts.getOrPut(previousState) { mutableMapOf() }
            outgoing[currentState] = (outgoing[currentState] ?: 0) + 1
            state.totalTransitions += 1
            if (adaptationRate > 0.0 && state.totalTransitions > 128) {
                decayCounts(state)
            }
        }
        state.lastState = currentState
        state.lastNovelty = window.noveltyScore
        state.lastDiversity = window.destinationDiversity
        state.lastByteRate = window.byteRate
        state.lastPacketRate = window.packetRate
        state.lastPeriodicity = window.periodicBeaconScore
    }

    private fun decayCounts(state: SequenceTransitionStats) {
        state.transitionCounts.forEach { (_, outgoing) ->
            val keys = outgoing.keys.toList()
            keys.forEach { target ->
                val decayed = (outgoing[target] ?: 0) * (1.0 - adaptationRate)
                if (decayed < 1.0) {
                    outgoing.remove(target)
                } else {
                    outgoing[target] = decayed.toInt()
                }
            }
        }
        state.totalTransitions = state.transitionCounts.values.sumOf { outgoing -> outgoing.values.sum() }
    }
}
