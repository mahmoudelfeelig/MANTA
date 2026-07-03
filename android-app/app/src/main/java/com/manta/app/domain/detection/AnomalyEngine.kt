package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.TriageStatus
import com.manta.app.core.settings.FusionWeights
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

class AnomalyEngine(
    private val statisticalDetector: StatisticalAnomalyDetector,
    private val multivariateDetector: MultivariateAnomalyDetector,
    private val sequenceDetector: SequenceAnomalyDetector,
    private val localScorer: ExportedModelAnomalyScorer,
    private val tfliteScorer: TfliteAnomalyScorer,
    private val remoteScorer: RemoteAssistedAnomalyScorer,
    private val sensitiveLocalScorer: ExportedModelAnomalyScorer = localScorer,
    private val quietLocalScorer: ExportedModelAnomalyScorer = localScorer,
    private val privacyLocalScorer: ExportedModelAnomalyScorer = localScorer
) {
    companion object {
        const val MODE_ENSEMBLE = "ensemble_fusion"
        const val MODE_STATISTICAL = "statistical"
        const val MODE_MULTIVARIATE = "multivariate"
        const val MODE_SEQUENCE = "sequence"
        const val MODE_LOCAL = "local"
        const val MODE_LOCAL_SENSITIVE = "local_sensitive"
        const val MODE_LOCAL_QUIET = "local_quiet"
        const val MODE_LOCAL_BALANCED = "local_balanced"
        const val MODE_LOCAL_PRIVACY = "local_privacy"
        const val MODE_TFLITE = "tflite"
        const val MODE_REMOTE = "remote_assisted"

        const val LEGACY_MODE_LINEAR = "linear"
        const val LEGACY_MODE_LINEAR_V13 = "linear_v13_recall"
        const val LEGACY_MODE_LINEAR_V14 = "linear_v14_quiet"
        const val LEGACY_MODE_HYBRID_V15 = "hybrid_v15"

        val SUPPORTED_MODES: Set<String> = setOf(
            MODE_ENSEMBLE,
            MODE_STATISTICAL,
            MODE_MULTIVARIATE,
            MODE_SEQUENCE,
            MODE_LOCAL,
            MODE_LOCAL_SENSITIVE,
            MODE_LOCAL_QUIET,
            MODE_LOCAL_BALANCED,
            MODE_LOCAL_PRIVACY,
            MODE_TFLITE,
            MODE_REMOTE
        )

        val LEGACY_MODE_ALIASES: Map<String, String> = mapOf(
            LEGACY_MODE_LINEAR to MODE_LOCAL,
            LEGACY_MODE_LINEAR_V13 to MODE_LOCAL_SENSITIVE,
            LEGACY_MODE_LINEAR_V14 to MODE_LOCAL_QUIET,
            LEGACY_MODE_HYBRID_V15 to MODE_LOCAL_BALANCED
        )

        fun canonicalMode(mode: String?): String {
            val normalized = mode.orEmpty().trim()
            return LEGACY_MODE_ALIASES[normalized] ?: normalized
        }
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
            local = 0.16,
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
        return when (canonicalMode(configuredMode)) {
            MODE_STATISTICAL -> scoreStatistical(window)
            MODE_MULTIVARIATE -> scoreMultivariate(window)
            MODE_SEQUENCE -> scoreSequence(window)
            MODE_LOCAL -> scoreLocal(window)
            MODE_LOCAL_SENSITIVE -> scoreSensitiveLocal(window)
            MODE_LOCAL_QUIET -> scoreQuietLocal(window)
            MODE_LOCAL_BALANCED -> scoreBalancedLocal(window)
            MODE_LOCAL_PRIVACY -> scorePrivacyLocal(window)
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

    private fun scoreLocal(window: FeatureWindow): AnomalyScoreResult {
        val result = if (localScorer.isModelAvailable()) {
            localScorer.score(window)
        } else {
            statisticalDetector.score(window)
        }
        return result.copy(source = MODE_LOCAL)
    }

    private fun scoreSensitiveLocal(window: FeatureWindow): AnomalyScoreResult {
        val result = if (sensitiveLocalScorer.isModelAvailable()) {
            sensitiveLocalScorer.score(window)
        } else {
            scoreLocal(window)
        }
        return result.copy(source = MODE_LOCAL_SENSITIVE)
    }

    private fun scoreQuietLocal(window: FeatureWindow): AnomalyScoreResult {
        val result = if (quietLocalScorer.isModelAvailable()) {
            quietLocalScorer.score(window)
        } else {
            scoreLocal(window)
        }
        return result.copy(source = MODE_LOCAL_QUIET)
    }

    private fun scoreBalancedLocal(window: FeatureWindow): AnomalyScoreResult {
        val recallResult = if (sensitiveLocalScorer.isModelAvailable()) {
            sensitiveLocalScorer.score(window)
        } else {
            scoreLocal(window)
        }
        val quietResult = if (quietLocalScorer.isModelAvailable()) {
            quietLocalScorer.score(window)
        } else {
            scoreLocal(window)
        }
        val family = deriveAppFamily(window.appId)
        val hybridScore = when (family) {
            "malware", "remote_access" -> max(recallResult.score, quietResult.score)
            "service", "system", "other_app" -> min(
                (0.25 * recallResult.score) + (0.75 * quietResult.score),
                quietResult.score + 0.12
            )
            else -> (0.45 * recallResult.score) + (0.55 * quietResult.score)
        }.coerceIn(0.0, 1.0)
        val mergedContributions = mergeFeatureContributions(
            listOf(
                DetectorCandidate(recallResult, 0.45),
                DetectorCandidate(quietResult, 0.55)
            )
        )
        val confidence = max(recallResult.confidence, quietResult.confidence)
        val uncertainty = (0.65 * min(recallResult.uncertainty, quietResult.uncertainty) +
            0.35 * abs(recallResult.score - quietResult.score)).coerceIn(0.0, 1.0)
        return AnomalyScoreResult(
            score = hybridScore,
            topFeatures = mergedContributions.entries
                .sortedByDescending { it.value }
                .take(3)
                .map { it.key }
                .ifEmpty { recallResult.topFeatures + quietResult.topFeatures }
                .distinct()
                .take(3),
            featureContributions = mergedContributions,
            source = MODE_LOCAL_BALANCED,
            confidence = confidence.coerceIn(0.0, 1.0),
            uncertainty = uncertainty,
            diagnostics = mapOf(
                "v13_recall_score" to recallResult.score,
                "v14_quiet_score" to quietResult.score,
                "hybrid_family_weight" to when (family) {
                    "malware", "remote_access" -> 1.0
                    "service", "system", "other_app" -> 0.25
                    else -> 0.45
                }
            ),
            anomalyScore = hybridScore,
            responseScore = hybridScore
        )
    }

    private fun scorePrivacyLocal(window: FeatureWindow): AnomalyScoreResult {
        val result = if (privacyLocalScorer.isModelAvailable()) {
            privacyLocalScorer.score(window)
        } else {
            scoreLocal(window)
        }
        return result.copy(source = MODE_LOCAL_PRIVACY)
    }

    private fun scoreTflite(window: FeatureWindow): AnomalyScoreResult {
        val result = when {
            tfliteScorer.isModelAvailable() -> tfliteScorer.score(window)
            localScorer.isModelAvailable() -> localScorer.score(window)
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

        if (localScorer.isModelAvailable()) {
            candidates += DetectorCandidate(
                result = localScorer.score(window),
                weight = fusionWeights.local
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

    fun recordFeedback(window: FeatureWindow, status: TriageStatus) {
        when (status) {
            TriageStatus.FALSE_POSITIVE -> statisticalDetector.recordFeedback(window = window, dangerous = false)
            TriageStatus.RESOLVED -> statisticalDetector.recordFeedback(window = window, dangerous = true)
            TriageStatus.OPEN,
            TriageStatus.INVESTIGATING -> Unit
        }
    }
}
