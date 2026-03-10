package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.TriageStatus
import com.manta.app.core.settings.FusionWeights
import kotlin.math.abs

class AnomalyEngine(
    private val statisticalDetector: StatisticalAnomalyDetector,
    private val multivariateDetector: MultivariateAnomalyDetector,
    private val sequenceDetector: SequenceAnomalyDetector,
    private val linearScorer: ExportedModelAnomalyScorer,
    private val tfliteScorer: TfliteAnomalyScorer,
    private val remoteScorer: RemoteAssistedAnomalyScorer
) {
    companion object {
        const val MODE_ENSEMBLE = "ensemble_fusion"
        const val MODE_STATISTICAL = "statistical"
        const val MODE_MULTIVARIATE = "multivariate"
        const val MODE_SEQUENCE = "sequence"
        const val MODE_LINEAR = "linear"
        const val MODE_TFLITE = "tflite"
        const val MODE_REMOTE = "remote_assisted"

        val SUPPORTED_MODES: Set<String> = setOf(
            MODE_ENSEMBLE,
            MODE_STATISTICAL,
            MODE_MULTIVARIATE,
            MODE_SEQUENCE,
            MODE_LINEAR,
            MODE_TFLITE,
            MODE_REMOTE
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

    fun score(
        window: FeatureWindow,
        configuredMode: String = MODE_ENSEMBLE,
        fusionWeights: FusionWeights = FusionWeights(
            statistical = 0.28,
            multivariate = 0.20,
            sequence = 0.12,
            linear = 0.16,
            tflite = 0.12,
            remote = 0.12,
            beacon = 0.15,
            drift = 0.10,
            reputation = 0.18,
            dataQualityPenalty = 0.10,
            responseAnomalyBlend = 0.82,
            responseContextBlend = 0.18
        )
    ): AnomalyScoreResult {
        return when (configuredMode) {
            MODE_STATISTICAL -> scoreStatistical(window)
            MODE_MULTIVARIATE -> scoreMultivariate(window)
            MODE_SEQUENCE -> scoreSequence(window)
            MODE_LINEAR -> scoreLinear(window)
            MODE_TFLITE -> scoreTflite(window)
            MODE_REMOTE -> scoreRemote(window, fusionWeights.normalize())
            MODE_ENSEMBLE -> scoreEnsemble(window, fusionWeights.normalize())
            else -> scoreEnsemble(window, fusionWeights.normalize())
        }
    }

    private fun scoreStatistical(window: FeatureWindow): AnomalyScoreResult {
        val result = statisticalDetector.score(window)
        return result.copy(source = MODE_STATISTICAL)
    }

    private fun scoreMultivariate(window: FeatureWindow): AnomalyScoreResult {
        val result = multivariateDetector.score(window)
        return result.copy(source = MODE_MULTIVARIATE)
    }

    private fun scoreSequence(window: FeatureWindow): AnomalyScoreResult {
        val result = sequenceDetector.score(window)
        return result.copy(source = MODE_SEQUENCE)
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

    private fun scoreRemote(window: FeatureWindow, fusionWeights: FusionWeights): AnomalyScoreResult {
        val result = remoteScorer.score(window)
        return if (result.source == "remote_assisted_unavailable") {
            scoreEnsemble(window, fusionWeights).copy(source = "${MODE_REMOTE}_fallback")
        } else {
            result.copy(source = MODE_REMOTE)
        }
    }

    private fun scoreEnsemble(window: FeatureWindow, fusionWeights: FusionWeights): AnomalyScoreResult {
        val candidates = mutableListOf<DetectorCandidate>()
        candidates += DetectorCandidate(
            result = statisticalDetector.score(window).copy(source = MODE_STATISTICAL),
            weight = fusionWeights.statistical
        )
        candidates += DetectorCandidate(
            result = multivariateDetector.score(window).copy(source = MODE_MULTIVARIATE),
            weight = fusionWeights.multivariate
        )
        candidates += DetectorCandidate(
            result = sequenceDetector.score(window).copy(source = MODE_SEQUENCE),
            weight = fusionWeights.sequence
        )

        if (linearScorer.isModelAvailable()) {
            candidates += DetectorCandidate(
                result = linearScorer.score(window),
                weight = fusionWeights.linear
            )
        }
        if (tfliteScorer.isModelAvailable()) {
            candidates += DetectorCandidate(
                result = tfliteScorer.score(window),
                weight = fusionWeights.tflite
            )
        }
        val remoteResult = remoteScorer.score(window)
        if (remoteResult.source != "remote_assisted_unavailable") {
            candidates += DetectorCandidate(
                result = remoteResult,
                weight = fusionWeights.remote
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
            ),
            anomalyScore = fusedScore,
            contextScore = 0.0,
            responseScore = fusedScore
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

    fun recordFeedback(window: FeatureWindow, status: TriageStatus) {
        when (status) {
            TriageStatus.FALSE_POSITIVE -> statisticalDetector.recordFeedback(window = window, dangerous = false)
            TriageStatus.RESOLVED -> statisticalDetector.recordFeedback(window = window, dangerous = true)
            TriageStatus.OPEN,
            TriageStatus.INVESTIGATING -> Unit
        }
    }
}
