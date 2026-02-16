package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow

data class AnomalyScoreResult(
    val score: Double,
    val topFeatures: List<String>,
    val source: String
)

interface AnomalyScorer {
    fun score(window: FeatureWindow): AnomalyScoreResult
}
