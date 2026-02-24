package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow
import kotlin.math.abs

class AnomalyEngine(
    private val statisticalDetector: StatisticalAnomalyDetector,
    private val linearScorer: ExportedModelAnomalyScorer,
    private val tfliteScorer: TfliteAnomalyScorer
) {
    companion object {
        const val MODE_ENSEMBLE = "ensemble_fusion"
        const val MODE_STATISTICAL = "statistical"
        const val MODE_LINEAR = "linear"
        const val MODE_TFLITE = "tflite"

        val SUPPORTED_MODES: Set<String> = setOf(
            MODE_ENSEMBLE,
            MODE_STATISTICAL,
            MODE_LINEAR,
            MODE_TFLITE
        )
    }

    private data class DetectorCandidate(
        val result: AnomalyScoreResult,
        val weight: Double
    )

    private data class AppFusionState(
        var emaScore: Double = 0.0,
        var initialized: Boolean = false
    )

    private val appFusionStates = mutableMapOf<String, AppFusionState>()

    fun score(window: FeatureWindow, configuredMode: String = MODE_ENSEMBLE): AnomalyScoreResult {
        return when (configuredMode) {
            MODE_STATISTICAL -> scoreStatistical(window)
            MODE_LINEAR -> scoreLinear(window)
            MODE_TFLITE -> scoreTflite(window)
            MODE_ENSEMBLE -> scoreEnsemble(window)
            else -> scoreEnsemble(window)
        }
    }

    private fun scoreStatistical(window: FeatureWindow): AnomalyScoreResult {
        val result = statisticalDetector.score(window)
        return result.copy(source = MODE_STATISTICAL)
    }

    private fun scoreLinear(window: FeatureWindow): AnomalyScoreResult {
        val result = if (linearScorer.isModelAvailable()) {
            linearScorer.score(window)
        } else {
            statisticalDetector.score(window)
        }
        return result.copy(source = MODE_LINEAR)
    }

    private fun scoreTflite(window: FeatureWindow): AnomalyScoreResult {
        val result = when {
            tfliteScorer.isModelAvailable() -> tfliteScorer.score(window)
            linearScorer.isModelAvailable() -> linearScorer.score(window)
            else -> statisticalDetector.score(window)
        }
        return result.copy(source = MODE_TFLITE)
    }

    private fun scoreEnsemble(window: FeatureWindow): AnomalyScoreResult {
        val candidates = mutableListOf<DetectorCandidate>()
        candidates += DetectorCandidate(
            result = statisticalDetector.score(window),
            weight = 0.20
        )

        if (linearScorer.isModelAvailable()) {
            candidates += DetectorCandidate(
                result = linearScorer.score(window),
                weight = 0.45
            )
        }
        if (tfliteScorer.isModelAvailable()) {
            candidates += DetectorCandidate(
                result = tfliteScorer.score(window),
                weight = 0.35
            )
        }

        if (candidates.isEmpty()) {
            return statisticalDetector.score(window)
        }

        val fusedScore = fuseScores(window.appId, candidates)
        val mergedContributions = mergeFeatureContributions(candidates)
        val totalWeight = candidates.sumOf { it.weight }.coerceAtLeast(1e-9)
        val weightedConfidence = candidates.sumOf { it.result.confidence * it.weight } / totalWeight
        val scoreSpread = candidates.map { it.result.score }.let { values ->
            if (values.isEmpty()) 0.0 else (values.maxOrNull()!! - values.minOrNull()!!)
        }
        val uncertainty = ((1.0 - weightedConfidence) * 0.7 + scoreSpread * 0.3).coerceIn(0.0, 1.0)
        val confidence = (1.0 - uncertainty).coerceIn(0.0, 1.0)
        val topFeatures = mergedContributions.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }

        return AnomalyScoreResult(
            score = fusedScore,
            topFeatures = topFeatures,
            featureContributions = mergedContributions,
            source = MODE_ENSEMBLE,
            confidence = confidence,
            uncertainty = uncertainty,
            diagnostics = mapOf(
                "candidate_count" to candidates.size.toDouble(),
                "score_spread" to scoreSpread,
                "weighted_confidence" to weightedConfidence
            )
        )
    }

    private fun fuseScores(appId: String, candidates: List<DetectorCandidate>): Double {
        val totalWeight = candidates.sumOf { it.weight }.coerceAtLeast(1e-9)
        val weightedAverage = candidates.sumOf { it.result.score * it.weight } / totalWeight

        val sortedScores = candidates.map { it.result.score }.sorted()
        val median = if (sortedScores.size % 2 == 0) {
            val mid = sortedScores.size / 2
            (sortedScores[mid - 1] + sortedScores[mid]) / 2.0
        } else {
            sortedScores[sortedScores.size / 2]
        }

        val spread = (sortedScores.lastOrNull() ?: 0.0) - (sortedScores.firstOrNull() ?: 0.0)
        val disagreementPenalty = 0.20 * spread.coerceIn(0.0, 1.0)

        val instantFused = (0.70 * weightedAverage) + (0.30 * median) - disagreementPenalty
        return smoothScore(appId = appId, instantScore = instantFused.coerceIn(0.0, 1.0))
    }

    @Synchronized
    private fun smoothScore(appId: String, instantScore: Double): Double {
        val state = appFusionStates.getOrPut(appId) { AppFusionState() }
        if (!state.initialized) {
            state.initialized = true
            state.emaScore = instantScore
            return instantScore
        }

        val alpha = 0.35
        state.emaScore = (alpha * instantScore) + ((1.0 - alpha) * state.emaScore)
        return ((0.45 * instantScore) + (0.55 * state.emaScore)).coerceIn(0.0, 1.0)
    }

    private fun mergeFeatureContributions(candidates: List<DetectorCandidate>): Map<String, Double> {
        val totalWeight = candidates.sumOf { it.weight }.coerceAtLeast(1e-9)
        val merged = linkedMapOf<String, Double>()
        candidates.forEach { candidate ->
            val normalizedWeight = candidate.weight / totalWeight
            candidate.result.featureContributions.forEach { (feature, contribution) ->
                val weightedContribution = abs(contribution) * normalizedWeight
                merged[feature] = (merged[feature] ?: 0.0) + weightedContribution
            }
        }
        return merged
    }
}
