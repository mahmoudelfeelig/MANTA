package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow

data class AnomalyScoreResult(
    val score: Double,
    val topFeatures: List<String>,
    val featureContributions: Map<String, Double>,
    val source: String
)

interface AnomalyScorer {
    fun score(window: FeatureWindow): AnomalyScoreResult
}
