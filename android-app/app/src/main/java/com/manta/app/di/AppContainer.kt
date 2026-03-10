package com.manta.app.di

import android.content.Context
import com.manta.app.core.net.OkHttpEventClient
import com.manta.app.core.settings.SecureSettingsStore
import com.manta.app.data.FlowRepository
import com.manta.app.domain.detection.AnomalyEngine
import com.manta.app.domain.detection.ConceptDriftMonitor
import com.manta.app.domain.detection.DataQualityMonitor
import com.manta.app.domain.detection.ExportedModelAnomalyScorer
import com.manta.app.domain.detection.FalsePositiveBudgetManager
import com.manta.app.domain.detection.MultivariateAnomalyDetector
import com.manta.app.domain.detection.PeriodicBeaconDetector
import com.manta.app.domain.detection.RuntimeGuardrailManager
import com.manta.app.domain.detection.RemoteAssistedAnomalyScorer
import com.manta.app.domain.detection.SequenceAnomalyDetector
import com.manta.app.domain.detection.SeverityStabilityGate
import com.manta.app.domain.detection.StatisticalAnomalyDetector
import com.manta.app.domain.detection.TfliteAnomalyScorer
import com.manta.app.domain.flow.FeatureWindowBuilder

class AppContainer(context: Context) {
    val settingsStore = SecureSettingsStore(context)
    val eventClient = OkHttpEventClient(settingsStore)

    private val statisticalDetector = StatisticalAnomalyDetector()
    private val multivariateDetector = MultivariateAnomalyDetector()
    private val sequenceDetector = SequenceAnomalyDetector()
    private val exportedModelScorer = ExportedModelAnomalyScorer(context)
    private val tfliteScorer = TfliteAnomalyScorer(context)
    private val remoteScorer = RemoteAssistedAnomalyScorer(settingsStore)
    private val anomalyEngine = AnomalyEngine(
        statisticalDetector,
        multivariateDetector,
        sequenceDetector,
        exportedModelScorer,
        tfliteScorer,
        remoteScorer
    )
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
