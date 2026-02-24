package com.feelbachelor.app.di

import android.content.Context
import com.feelbachelor.app.core.net.OkHttpEventClient
import com.feelbachelor.app.core.settings.SecureSettingsStore
import com.feelbachelor.app.data.FlowRepository
import com.feelbachelor.app.domain.detection.AnomalyEngine
import com.feelbachelor.app.domain.detection.ConceptDriftMonitor
import com.feelbachelor.app.domain.detection.DataQualityMonitor
import com.feelbachelor.app.domain.detection.ExportedModelAnomalyScorer
import com.feelbachelor.app.domain.detection.FalsePositiveBudgetManager
import com.feelbachelor.app.domain.detection.PeriodicBeaconDetector
import com.feelbachelor.app.domain.detection.RuntimeGuardrailManager
import com.feelbachelor.app.domain.detection.SeverityStabilityGate
import com.feelbachelor.app.domain.detection.StatisticalAnomalyDetector
import com.feelbachelor.app.domain.detection.TfliteAnomalyScorer
import com.feelbachelor.app.domain.flow.FeatureWindowBuilder

class AppContainer(context: Context) {
    val settingsStore = SecureSettingsStore(context)
    val eventClient = OkHttpEventClient(settingsStore)

    private val statisticalDetector = StatisticalAnomalyDetector()
    private val exportedModelScorer = ExportedModelAnomalyScorer(context)
    private val tfliteScorer = TfliteAnomalyScorer(context)
    private val anomalyEngine = AnomalyEngine(statisticalDetector, exportedModelScorer, tfliteScorer)
    private val severityStabilityGate = SeverityStabilityGate(requiredConsecutiveHigh = 3)
    private val conceptDriftMonitor = ConceptDriftMonitor()
    private val periodicBeaconDetector = PeriodicBeaconDetector()
    private val dataQualityMonitor = DataQualityMonitor()
    private val falsePositiveBudgetManager = FalsePositiveBudgetManager()
    private val runtimeGuardrailManager = RuntimeGuardrailManager()
    private val featureWindowBuilder = FeatureWindowBuilder()

    val repository = FlowRepository(
        context = context,
        settingsStore = settingsStore,
        featureWindowBuilder = featureWindowBuilder,
        anomalyEngine = anomalyEngine,
        severityStabilityGate = severityStabilityGate,
        conceptDriftMonitor = conceptDriftMonitor,
        periodicBeaconDetector = periodicBeaconDetector,
        dataQualityMonitor = dataQualityMonitor,
        falsePositiveBudgetManager = falsePositiveBudgetManager,
        runtimeGuardrailManager = runtimeGuardrailManager
    )
}
