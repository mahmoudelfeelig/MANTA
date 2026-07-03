package com.manta.app.di

import android.content.Context
import com.manta.app.core.model.PacketPipelineHealth
import com.manta.app.core.model.RuntimeHealth
import com.manta.app.core.net.OkHttpEventClient
import com.manta.app.core.settings.SecureSettingsStore
import com.manta.app.data.FlowRepository
import com.manta.app.domain.detection.AnomalyEngine
import com.manta.app.domain.detection.AlertEvidencePolicy
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
import com.manta.app.domain.intelligence.DestinationInsightEngine
import com.manta.app.service.PacketPipelineStats

class AppContainer(context: Context) {
    companion object {
        const val ANALYSIS_SHARD_COUNT = 4
    }

    val settingsStore = SecureSettingsStore(context)
    val eventClient = OkHttpEventClient(settingsStore)
    val packetPipelineStats = PacketPipelineStats(shardCount = ANALYSIS_SHARD_COUNT)

    private val statisticalDetector = StatisticalAnomalyDetector()
    private val multivariateDetector = MultivariateAnomalyDetector()
    private val sequenceDetector = SequenceAnomalyDetector()
    private val exportedModelScorer = ExportedModelAnomalyScorer(context)
    private val sensitiveLocalScorer = ExportedModelAnomalyScorer(context, "models/anomaly-v13-recall.json")
    private val quietLocalScorer = ExportedModelAnomalyScorer(context, "models/anomaly-v14-quiet.json")
    private val privacyLocalScorer = ExportedModelAnomalyScorer(context, "models/anomaly-privacy-local.json")
    private val tfliteScorer = TfliteAnomalyScorer(context)
    private val remoteScorer = RemoteAssistedAnomalyScorer(settingsStore)
    private val anomalyEngine = AnomalyEngine(
        statisticalDetector,
        multivariateDetector,
        sequenceDetector,
        exportedModelScorer,
        tfliteScorer,
        remoteScorer,
        sensitiveLocalScorer,
        quietLocalScorer,
        privacyLocalScorer
    )
    private val severityStabilityGate = SeverityStabilityGate(requiredConsecutiveHigh = 3)
    private val alertEvidencePolicy = AlertEvidencePolicy()
    private val conceptDriftMonitor = ConceptDriftMonitor()
    private val periodicBeaconDetector = PeriodicBeaconDetector()
    private val dataQualityMonitor = DataQualityMonitor()
    private val falsePositiveBudgetManager = FalsePositiveBudgetManager()
    private val runtimeGuardrailManager = RuntimeGuardrailManager()
    private val featureWindowBuilder = FeatureWindowBuilder()
    private val destinationInsightEngine = DestinationInsightEngine()

    val repository = FlowRepository(
        context = context,
        settingsStore = settingsStore,
        featureWindowBuilder = featureWindowBuilder,
        anomalyEngine = anomalyEngine,
        severityStabilityGate = severityStabilityGate,
        alertEvidencePolicy = alertEvidencePolicy,
        conceptDriftMonitor = conceptDriftMonitor,
        periodicBeaconDetector = periodicBeaconDetector,
        dataQualityMonitor = dataQualityMonitor,
        falsePositiveBudgetManager = falsePositiveBudgetManager,
        runtimeGuardrailManager = runtimeGuardrailManager,
        destinationInsightEngine = destinationInsightEngine,
        packetPipelineStats = packetPipelineStats
    )

    fun runtimeHealth(): RuntimeHealth {
        val config = settingsStore.readConfig()
        val snapshot = packetPipelineStats.snapshot()
        return RuntimeHealth(
            localModelAvailable = exportedModelScorer.isModelAvailable() ||
                sensitiveLocalScorer.isModelAvailable() ||
                quietLocalScorer.isModelAvailable() ||
                privacyLocalScorer.isModelAvailable(),
            tfliteAvailable = tfliteScorer.isModelAvailable(),
            remoteConfigured = config.isConfigured(),
            activeDetectionModel = config.detectionModel,
            shadowModel = config.shadowModel,
            packetPipeline = PacketPipelineHealth(
                packetsRead = snapshot.packetsRead,
                activeFlows = snapshot.activeFlows,
                parserFailure = snapshot.parserFailure,
                forwardQueueDropped = snapshot.forwardQueueDropped,
                analysisIngressDropped = snapshot.analysisIngressDropped,
                analysisShardDropped = snapshot.analysisShardDropped,
                readToParseAvgMs = snapshot.readToParseAvgMs,
                parseToShardAvgMs = snapshot.parseToShardAvgMs,
                shardToFlushAvgMs = snapshot.shardToFlushAvgMs,
                flushToPersistAvgMs = snapshot.flushToPersistAvgMs
            )
        )
    }
}
