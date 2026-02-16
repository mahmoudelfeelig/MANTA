package com.feelbachelor.app.di

import android.content.Context
import com.feelbachelor.app.core.net.OkHttpEventClient
import com.feelbachelor.app.core.settings.SecureSettingsStore
import com.feelbachelor.app.data.FlowRepository
import com.feelbachelor.app.domain.detection.AnomalyEngine
import com.feelbachelor.app.domain.detection.StatisticalAnomalyDetector
import com.feelbachelor.app.domain.detection.TfliteAnomalyScorer
import com.feelbachelor.app.domain.flow.FeatureWindowBuilder

class AppContainer(context: Context) {
    val settingsStore = SecureSettingsStore(context)
    val eventClient = OkHttpEventClient(settingsStore)

    private val statisticalDetector = StatisticalAnomalyDetector()
    private val tfliteScorer = TfliteAnomalyScorer(context)
    private val anomalyEngine = AnomalyEngine(statisticalDetector, tfliteScorer)
    private val featureWindowBuilder = FeatureWindowBuilder()

    val repository = FlowRepository(
        context = context,
        settingsStore = settingsStore,
        featureWindowBuilder = featureWindowBuilder,
        anomalyEngine = anomalyEngine
    )
}
