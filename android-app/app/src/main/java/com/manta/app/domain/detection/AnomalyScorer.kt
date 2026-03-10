package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow

data class AnomalyScoreResult(
    val score: Double,
    val topFeatures: List<String>,
    val featureContributions: Map<String, Double>,
    val source: String,
    val confidence: Double = 0.5,
    val uncertainty: Double = 0.5,
    val diagnostics: Map<String, Double> = emptyMap(),
    val anomalyScore: Double = score,
    val contextScore: Double = 0.0,
    val responseScore: Double = score
)

interface AnomalyScorer {
    fun score(window: FeatureWindow): AnomalyScoreResult
}
