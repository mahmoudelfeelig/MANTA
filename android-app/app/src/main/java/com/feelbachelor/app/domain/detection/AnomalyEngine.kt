package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow

class AnomalyEngine(
    private val statisticalDetector: StatisticalAnomalyDetector,
    private val tfliteScorer: TfliteAnomalyScorer
) {
    fun score(window: FeatureWindow): AnomalyScoreResult {
        val statistical = statisticalDetector.score(window)
        if (!tfliteScorer.isModelAvailable()) {
            return statistical
        }

        val tflite = tfliteScorer.score(window)
        return if (tflite.score >= statistical.score) {
            tflite
        } else {
            statistical
        }
    }
}
