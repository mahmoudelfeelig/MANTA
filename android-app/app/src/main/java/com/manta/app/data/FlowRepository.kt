package com.manta.app.data

import android.content.Context
import android.os.Build
import android.util.Log
import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.AnomalyAlert
import com.manta.app.core.model.DestinationInsight
import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.FlowProtocol
import com.manta.app.core.model.FlowRecord
import com.manta.app.core.model.ProtocolEvidence
import com.manta.app.core.model.TriageStatus
import com.manta.app.core.model.ThresholdProfile
import com.manta.app.core.net.NetworkEventClient
import com.manta.app.core.security.CryptoUtils
import com.manta.app.core.settings.AppProfile
import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.SecureSettingsStore
import com.manta.app.data.db.AnomalyScoreEntity
import com.manta.app.data.db.AppDatabase
import com.manta.app.data.db.ExportQueueEntity
import com.manta.app.data.db.FeatureWindowEntity
import com.manta.app.data.db.RawFlowEntity
import com.manta.app.domain.detection.AnomalyEngine
import com.manta.app.domain.detection.ConceptDriftMonitor
import com.manta.app.domain.detection.DataQualityMonitor
import com.manta.app.domain.detection.ExplanationFormatter
import com.manta.app.domain.detection.FalsePositiveBudgetManager
import com.manta.app.domain.detection.PeriodicBeaconDetector
import com.manta.app.domain.detection.RuntimeGuardrailManager
import com.manta.app.domain.detection.SeverityStabilityGate
import com.manta.app.domain.detection.ThresholdResolver
import com.manta.app.domain.flow.FeatureWindowBuilder
import com.manta.app.domain.intelligence.DestinationInsightEngine
import com.manta.app.service.PacketPipelineStats
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.math.min
import kotlin.system.measureNanoTime

private const val WINDOW_MILLIS = 60_000L
private const val ALERT_CORRELATION_WINDOW_MILLIS = 10 * 60_000L
private const val FEEDBACK_ADJUST_STEP_FP = 0.02
private const val FEEDBACK_ADJUST_STEP_TRUE_POSITIVE = 0.01
private const val TAG = "FlowRepository"
private const val RECENT_FLOW_WINDOW_LIMIT = 240
private const val PENDING_EXPORT_COUNT_CACHE_TTL_MILLIS = 2_000L
private const val SETTINGS_LOOKUP_CACHE_TTL_MILLIS = 5_000L

private val BROWSER_PACKAGES = setOf(
    "com.android.chrome",
    "org.mozilla.firefox",
    "org.mozilla.firefox_beta",
    "org.mozilla.fenix",
    "com.microsoft.emmx",
    "com.brave.browser",
    "com.opera.browser",
    "com.opera.mini.native",
    "com.sec.android.app.sbrowser",
    "com.duckduckgo.mobile.android",
    "com.vivaldi.browser",
    "com.kiwibrowser.browser"
)

class FlowRepository(
    context: Context,
    private val settingsStore: SecureSettingsStore,
    private val featureWindowBuilder: FeatureWindowBuilder,
    private val anomalyEngine: AnomalyEngine,
    private val severityStabilityGate: SeverityStabilityGate,
    private val conceptDriftMonitor: ConceptDriftMonitor,
    private val periodicBeaconDetector: PeriodicBeaconDetector,
    private val dataQualityMonitor: DataQualityMonitor,
    private val falsePositiveBudgetManager: FalsePositiveBudgetManager,
    private val runtimeGuardrailManager: RuntimeGuardrailManager,
    private val destinationInsightEngine: DestinationInsightEngine,
    private val packetPipelineStats: PacketPipelineStats
) {
    private val appContext = context.applicationContext
    private val db = AppDatabase.getInstance(context)
    private val dao = db.flowDao()
    private val siteHintCache = mutableMapOf<String, String?>()
    private val dnsAnswerCache = mutableMapOf<String, String>()
    private val pendingExportCountLock = Any()
    private var pendingExportCountCachedAtMillis = 0L
    private var pendingExportCountCachedValue = 0
    private val protectedBrandsLock = Any()
    private var protectedBrandsCachedCsv = ""
    private var protectedBrandsCachedValue: List<String> = emptyList()
    private val appProfileCache = linkedMapOf<String, Pair<Long, AppProfile>>()

    suspend fun persistFlow(flow: FlowRecord): AnomalyAlert? = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        val resolvedSiteHint = resolveSiteHint(flow = flow, privacyModeEnabled = config.privacyModeEnabled)
        val destinationInsight = destinationInsightEngine.analyze(
            flow,
            resolvedSiteHint,
            protectedBrandsFor(config.protectedBrandsCsv)
        )
        val enrichedFlow = flow.copy(
            siteHint = resolvedSiteHint ?: flow.siteHint,
            destinationInsight = destinationInsight
        )
        recordDnsResolution(enrichedFlow)

        dao.insertRawFlow(
            RawFlowEntity(
                id = enrichedFlow.id,
                timestampStartMillis = enrichedFlow.timestampStartMillis,
                timestampEndMillis = enrichedFlow.timestampEndMillis,
                appId = enrichedFlow.appId,
                ipVersion = enrichedFlow.ipVersion,
                protocol = enrichedFlow.protocol.name,
                srcIp = enrichedFlow.srcIp,
                srcPort = enrichedFlow.srcPort,
                dstIp = enrichedFlow.dstIp,
                dstPort = enrichedFlow.dstPort,
                bytesOut = enrichedFlow.bytesOut,
                bytesIn = enrichedFlow.bytesIn,
                packetsOut = enrichedFlow.packetsOut,
                packetsIn = enrichedFlow.packetsIn,
                durationMillis = enrichedFlow.durationMillis,
                destinationHash = enrichedFlow.destinationHash,
                destinationNovelty = enrichedFlow.destinationNovelty,
                siteHint = enrichedFlow.siteHint,
                ttlGap = enrichedFlow.ttlGap,
                ttlMetricsPresent = enrichedFlow.ttlMetricsPresent,
                synRateTotal = enrichedFlow.synRateTotal,
                rstRateTotal = enrichedFlow.rstRateTotal,
                ackRateTotal = enrichedFlow.ackRateTotal,
                finRateTotal = enrichedFlow.finRateTotal,
                pshRateTotal = enrichedFlow.pshRateTotal,
                fragmentRateTotal = enrichedFlow.fragmentRateTotal,
                tcpWindowMean = enrichedFlow.tcpWindowMean,
                ackDelayMean = enrichedFlow.ackDelayMean,
                interPacketGapMean = enrichedFlow.interPacketGapMean,
                payloadMean = enrichedFlow.payloadMean,
                loadMean = enrichedFlow.loadMean,
                transportMetricsPresent = enrichedFlow.transportMetricsPresent,
                protocolEvidenceJson = enrichedFlow.protocolEvidence.toJsonString(),
                destinationInsightJson = enrichedFlow.destinationInsight.toJsonString()
            )
        )

        val quality = dataQualityMonitor.evaluate(enrichedFlow)
        val pendingExportQueue = cachedPendingExportCount()
        val guardrail = runtimeGuardrailManager.decide(
            context = appContext,
            pendingExportQueue = pendingExportQueue
        )
        val beaconScore = periodicBeaconDetector.observe(enrichedFlow)

        val windowStart = enrichedFlow.timestampEndMillis - WINDOW_MILLIS
        val recent = dao.getRecentFlowsByApp(enrichedFlow.appId, windowStart, RECENT_FLOW_WINDOW_LIMIT).map { entity ->
            FlowRecord(
                id = entity.id,
                timestampStartMillis = entity.timestampStartMillis,
                timestampEndMillis = entity.timestampEndMillis,
                appId = entity.appId,
                ipVersion = entity.ipVersion,
                protocol = FlowProtocol.valueOf(entity.protocol),
                srcIp = entity.srcIp,
                srcPort = entity.srcPort,
                dstIp = entity.dstIp,
                dstPort = entity.dstPort,
                bytesOut = entity.bytesOut,
                bytesIn = entity.bytesIn,
                packetsOut = entity.packetsOut,
                packetsIn = entity.packetsIn,
                durationMillis = entity.durationMillis,
                destinationHash = entity.destinationHash,
                destinationNovelty = entity.destinationNovelty,
                siteHint = entity.siteHint,
                ttlGap = entity.ttlGap,
                ttlMetricsPresent = entity.ttlMetricsPresent,
                synRateTotal = entity.synRateTotal,
                rstRateTotal = entity.rstRateTotal,
                ackRateTotal = entity.ackRateTotal,
                finRateTotal = entity.finRateTotal,
                pshRateTotal = entity.pshRateTotal,
                fragmentRateTotal = entity.fragmentRateTotal,
                tcpWindowMean = entity.tcpWindowMean,
                ackDelayMean = entity.ackDelayMean,
                interPacketGapMean = entity.interPacketGapMean,
                payloadMean = entity.payloadMean,
                loadMean = entity.loadMean,
                transportMetricsPresent = entity.transportMetricsPresent,
                protocolEvidence = ProtocolEvidence.fromJsonString(entity.protocolEvidenceJson),
                destinationInsight = DestinationInsight.fromJsonString(entity.destinationInsightJson)
            )
        }

        val siteHint = enrichedFlow.siteHint
        enqueueFlowForExport(flow = enrichedFlow, siteHint = siteHint)
        val activeModel = config.detectionModel
        val shadowModel = config.shadowModel
        val appProfile = effectiveAppProfile(
            base = cachedAppProfile(enrichedFlow.appId),
            flow = enrichedFlow,
            siteHint = siteHint
        )
        val builtWindow = featureWindowBuilder.build(
            appId = enrichedFlow.appId,
            flows = recent,
            windowStartMillis = windowStart,
            windowEndMillis = enrichedFlow.timestampEndMillis,
            siteHint = siteHint,
            periodicBeaconScore = beaconScore,
            dataQualityScore = quality.score,
            sampledByGuardrail = guardrail.sampled,
            processingCostMillis = 0.0
        )
        val scoringWindow = applyAblations(window = builtWindow, config = config)
        var anomaly = anomalyEngine.score(
            window = scoringWindow,
            configuredMode = activeModel,
            fusionWeights = config.fusionWeights
        )
        var shadowScore: Double? = null
        var driftScore = 0.0
        var reputationScore = 0.0
        val dataQualityWarnings = quality.warnings
        var processingCostMillis: Double
        var dangerSummary: String? = null

        val processingNanos = measureNanoTime {
            if (!guardrail.processDetection) {
                anomaly = anomalyEngine.score(
                    window = scoringWindow,
                    configuredMode = AnomalyEngine.MODE_STATISTICAL,
                    fusionWeights = config.fusionWeights
                )
                anomaly = anomaly.copy(
                    score = anomaly.score * 0.35,
                    anomalyScore = anomaly.score * 0.35,
                    responseScore = anomaly.score * 0.35,
                    source = "${activeModel}-sampled",
                    diagnostics = anomaly.diagnostics + mapOf(
                        "sample_factor" to guardrail.sampleFactor.toDouble()
                    )
                )
            } else {
                anomaly = anomalyEngine.score(
                    window = scoringWindow,
                    configuredMode = activeModel,
                    fusionWeights = config.fusionWeights
                )
                if (!shadowModel.isNullOrBlank() && shadowModel != activeModel) {
                    shadowScore = anomalyEngine.score(
                        window = scoringWindow,
                        configuredMode = shadowModel,
                        fusionWeights = config.fusionWeights
                    ).score
                }
            }
            val drift = conceptDriftMonitor.evaluate(scoringWindow)
            driftScore = drift.score
            dangerSummary = buildDangerSummary(flow = enrichedFlow, siteHint = siteHint)
            reputationScore = dangerScore(flow = enrichedFlow, siteHint = siteHint)
            val driftPostScore = if (driftScore >= config.driftHighThreshold) {
                driftScore
            } else {
                (driftScore * 0.35).coerceIn(0.0, 1.0)
            }

            val anomalyChannelScore = (
                anomaly.anomalyScore +
                    (config.fusionWeights.beacon * beaconScore) +
                    (config.fusionWeights.drift * driftPostScore) -
                    (config.fusionWeights.dataQualityPenalty * (1.0 - quality.score))
                ).coerceIn(0.0, 1.0)
            val contextChannelScore = (config.fusionWeights.reputation * reputationScore).coerceIn(0.0, 1.0)
            val adjustedScore = (
                (config.fusionWeights.responseAnomalyBlend * anomalyChannelScore) +
                    (config.fusionWeights.responseContextBlend * contextChannelScore)
                ).coerceIn(0.0, 1.0)
            val mergedContributions = anomaly.featureContributions.toMutableMap()
            if (beaconScore >= 0.4) {
                mergedContributions["periodic_beacon"] = beaconScore
            }
            if (driftPostScore >= 0.2) {
                mergedContributions["concept_drift"] = driftPostScore
            }
            if (reputationScore > 0.0) {
                mergedContributions["reputation_risk"] = reputationScore
            }
            if (quality.score < 1.0) {
                mergedContributions["data_quality_penalty"] = 1.0 - quality.score
            }
            val mergedTop = mergedContributions.entries
                .sortedByDescending { it.value }
                .take(4)
                .map { it.key }

            anomaly = anomaly.copy(
                score = adjustedScore,
                topFeatures = mergedTop,
                featureContributions = mergedContributions,
                confidence = (anomaly.confidence * quality.score).coerceIn(0.0, 1.0),
                uncertainty = (1.0 - (anomaly.confidence * quality.score)).coerceIn(0.0, 1.0),
                anomalyScore = anomalyChannelScore,
                contextScore = contextChannelScore,
                responseScore = adjustedScore,
                diagnostics = anomaly.diagnostics + mapOf(
                    "base_detector_score" to anomaly.anomalyScore,
                    "anomaly_channel_score" to anomalyChannelScore,
                    "context_channel_score" to contextChannelScore,
                    "response_score" to adjustedScore,
                    "periodic_beacon_score" to beaconScore,
                    "drift_score" to driftScore,
                    "drift_post_score" to driftPostScore,
                    "drift_threshold" to config.driftHighThreshold,
                    "reputation_score" to reputationScore,
                    "data_quality_score" to quality.score
                )
            )
        }
        processingCostMillis = processingNanos / 1_000_000.0
        runtimeGuardrailManager.recordProcessingCost(processingCostMillis)
        val window = builtWindow.copy(processingCostMillis = processingCostMillis)
        saveFeatureWindow(window)
        val thresholdProfile = adjustedThresholdProfile(
            base = settingsStore.getThresholdForApp(enrichedFlow.appId),
            profile = appProfile,
            testModeEnabled = config.testModeEnabled
        )
        val proposedSeverity = ThresholdResolver.resolveSeverity(anomaly.score, thresholdProfile)
        val stabilizedSeverity = severityStabilityGate.adjust(flow.appId, proposedSeverity)
        val falsePositives = dao.countFalsePositivesForAppSince(
            appId = enrichedFlow.appId,
            sinceMillis = enrichedFlow.timestampEndMillis - 24L * 60L * 60L * 1000L
        )
        val budgetDecision = falsePositiveBudgetManager.apply(
            proposed = stabilizedSeverity,
            falsePositivesInWindow = falsePositives,
            budgetPerAppDay = config.falsePositiveBudgetPerAppDay
        )
        var severity = budgetDecision.severity
        var suppressionReason = budgetDecision.suppressionReason ?: guardrail.reason
        if (anomaly.confidence < 0.48 && severity != AlertSeverity.LOW) {
            severity = when (severity) {
                AlertSeverity.HIGH -> AlertSeverity.MEDIUM
                AlertSeverity.MEDIUM -> AlertSeverity.LOW
                AlertSeverity.LOW -> AlertSeverity.LOW
            }
            suppressionReason = appendSuppressionReason(suppressionReason, "low_confidence:${"%.2f".format(anomaly.confidence)}")
        }
        if (shouldSuppressForProfile(
                profile = appProfile,
                alert = anomaly,
                siteHint = siteHint,
                dangerSummary = dangerSummary,
                flow = enrichedFlow
            )
        ) {
            severity = AlertSeverity.LOW
            suppressionReason = appendSuppressionReason(suppressionReason, "profile_suppression:${appProfile.name.lowercase()}")
        }
        val dangerFloor = minimumSeverityForDanger(
            flow = enrichedFlow,
            siteHint = siteHint,
            reputationScore = reputationScore
        )
        val minimumPersistScore = when {
            config.testModeEnabled && activeModel != AnomalyEngine.MODE_ENSEMBLE -> thresholdProfile.low * 0.20
            config.debugModeEnabled && activeModel != AnomalyEngine.MODE_ENSEMBLE -> thresholdProfile.low * 0.35
            activeModel != AnomalyEngine.MODE_ENSEMBLE -> thresholdProfile.low * 0.55
            config.testModeEnabled -> thresholdProfile.low * 0.65
            else -> thresholdProfile.low
        }
        if (anomaly.responseScore < minimumPersistScore && dangerFloor == null) {
            return@withContext null
        }
        dangerFloor?.let { floor ->
            severity = maxSeverity(severity, floor)
        }
        val explanation = (dangerSummary?.let { "Potential risk: $it. " } ?: "") + ExplanationFormatter.summarize(
            topFeatures = anomaly.topFeatures,
            contributions = anomaly.featureContributions
        ) + enrichedFlow.destinationInsight.mitreTechniques.takeIf { it.isNotEmpty() }?.let {
            " MITRE: ${it.joinToString(",")}."
        }.orEmpty() + if (suppressionReason != null) " Suppression: $suppressionReason." else ""

        val correlationKey = computeCorrelationKey(
            appId = enrichedFlow.appId,
            sourceModel = anomaly.source,
            topFeatures = anomaly.topFeatures
        )
        val correlated = dao.findCorrelatedAlert(
            appId = enrichedFlow.appId,
            correlationKey = correlationKey,
            sinceMillis = enrichedFlow.timestampEndMillis - ALERT_CORRELATION_WINDOW_MILLIS
        )

        val alert = if (correlated != null) {
            val mergedSeverity = maxSeverity(
                AlertSeverity.valueOf(correlated.severity),
                severity
            )
            val updatedCount = (correlated.occurrenceCount + 1).coerceAtLeast(2)
            dao.updateCorrelatedAlert(
                alertId = correlated.id,
                score = maxOf(correlated.score, anomaly.responseScore),
                severity = mergedSeverity.name,
                topFeaturesCsv = anomaly.topFeatures.joinToString(","),
                featureContributionsJson = serializeFeatureContributions(anomaly.featureContributions),
                explanation = explanation,
                sourceModel = anomaly.source,
                triageStatus = correlated.triageStatus,
                triageNote = correlated.triageNote,
                triageUpdatedAtMillis = flow.timestampEndMillis,
                confidence = anomaly.confidence,
                uncertainty = anomaly.uncertainty,
                anomalyScore = maxOf(correlated.anomalyScore, anomaly.anomalyScore),
                contextScore = maxOf(correlated.contextScore, anomaly.contextScore),
                responseScore = maxOf(correlated.responseScore, anomaly.responseScore),
                driftScore = maxOf(correlated.driftScore, driftScore),
                occurrenceCount = updatedCount,
                lastSeenMillis = flow.timestampEndMillis,
                shadowModel = shadowModel,
                shadowScore = shadowScore,
                suppressionReason = suppressionReason,
                dataQualityWarningsCsv = dataQualityWarnings.joinToString(","),
                beaconScore = maxOf(correlated.beaconScore, beaconScore),
                destinationIp = enrichedFlow.dstIp,
                destinationPort = enrichedFlow.dstPort,
                destinationHash = enrichedFlow.destinationHash,
                siteHint = siteHint,
                mitreTechniquesCsv = enrichedFlow.destinationInsight.mitreTechniques.joinToString(","),
                destinationIdentity = enrichedFlow.destinationInsight.registrableDomain ?: enrichedFlow.destinationInsight.normalizedHost,
                lookalikeScore = enrichedFlow.destinationInsight.lookalikeScore
            )
            mapEntityToAlert(
                dao.getScoreById(correlated.id) ?: correlated.copy(
                    score = maxOf(correlated.score, anomaly.responseScore),
                    severity = mergedSeverity.name,
                    topFeaturesCsv = anomaly.topFeatures.joinToString(","),
                    featureContributionsJson = serializeFeatureContributions(anomaly.featureContributions),
                    explanation = explanation,
                    sourceModel = anomaly.source,
                    triageUpdatedAtMillis = flow.timestampEndMillis,
                    confidence = anomaly.confidence,
                    uncertainty = anomaly.uncertainty,
                    anomalyScore = maxOf(correlated.anomalyScore, anomaly.anomalyScore),
                    contextScore = maxOf(correlated.contextScore, anomaly.contextScore),
                    responseScore = maxOf(correlated.responseScore, anomaly.responseScore),
                    driftScore = maxOf(correlated.driftScore, driftScore),
                    occurrenceCount = updatedCount,
                    lastSeenMillis = flow.timestampEndMillis,
                    shadowModel = shadowModel,
                    shadowScore = shadowScore,
                    suppressionReason = suppressionReason,
                    dataQualityWarningsCsv = dataQualityWarnings.joinToString(","),
                    beaconScore = maxOf(correlated.beaconScore, beaconScore),
                    destinationIp = enrichedFlow.dstIp,
                    destinationPort = enrichedFlow.dstPort,
                    destinationHash = enrichedFlow.destinationHash,
                    siteHint = siteHint,
                    mitreTechniquesCsv = enrichedFlow.destinationInsight.mitreTechniques.joinToString(","),
                    destinationIdentity = enrichedFlow.destinationInsight.registrableDomain ?: enrichedFlow.destinationInsight.normalizedHost,
                    lookalikeScore = enrichedFlow.destinationInsight.lookalikeScore
                )
            )
        } else {
            val newAlert = AnomalyAlert(
                id = UUID.randomUUID().toString(),
                featureWindowId = window.id,
                appId = enrichedFlow.appId,
                anomalyScore = anomaly.responseScore,
                severity = severity,
                topFeatures = anomaly.topFeatures,
                featureContributions = anomaly.featureContributions,
                explanation = explanation,
                sourceModel = anomaly.source,
                triageStatus = TriageStatus.OPEN,
                triageNote = "",
                createdAtMillis = enrichedFlow.timestampEndMillis,
                triageUpdatedAtMillis = enrichedFlow.timestampEndMillis,
                confidence = anomaly.confidence,
                uncertainty = anomaly.uncertainty,
                baseAnomalyScore = anomaly.anomalyScore,
                contextScore = anomaly.contextScore,
                responseScore = anomaly.responseScore,
                driftScore = driftScore,
                occurrenceCount = 1,
                firstSeenMillis = enrichedFlow.timestampEndMillis,
                lastSeenMillis = enrichedFlow.timestampEndMillis,
                correlationKey = correlationKey,
                shadowModel = shadowModel,
                shadowScore = shadowScore,
                suppressionReason = suppressionReason,
                dataQualityWarnings = dataQualityWarnings,
                beaconScore = beaconScore,
                destinationIp = enrichedFlow.dstIp,
                destinationPort = enrichedFlow.dstPort,
                destinationHash = enrichedFlow.destinationHash,
                siteHint = siteHint,
                mitreTechniques = enrichedFlow.destinationInsight.mitreTechniques,
                destinationIdentity = enrichedFlow.destinationInsight.registrableDomain ?: enrichedFlow.destinationInsight.normalizedHost,
                lookalikeScore = enrichedFlow.destinationInsight.lookalikeScore
            )

            dao.insertAnomalyScore(
                AnomalyScoreEntity(
                    id = newAlert.id,
                    featureWindowId = newAlert.featureWindowId,
                    appId = newAlert.appId,
                    score = newAlert.anomalyScore,
                    severity = newAlert.severity.name,
                    topFeaturesCsv = newAlert.topFeatures.joinToString(","),
                    featureContributionsJson = serializeFeatureContributions(newAlert.featureContributions),
                    explanation = newAlert.explanation,
                    sourceModel = newAlert.sourceModel,
                    triageStatus = newAlert.triageStatus.name,
                    triageNote = newAlert.triageNote,
                    createdAtMillis = newAlert.createdAtMillis,
                    triageUpdatedAtMillis = newAlert.triageUpdatedAtMillis,
                    confidence = newAlert.confidence,
                    uncertainty = newAlert.uncertainty,
                    anomalyScore = newAlert.baseAnomalyScore,
                    contextScore = newAlert.contextScore,
                    responseScore = newAlert.responseScore,
                    driftScore = newAlert.driftScore,
                    occurrenceCount = newAlert.occurrenceCount,
                    firstSeenMillis = newAlert.firstSeenMillis,
                    lastSeenMillis = newAlert.lastSeenMillis,
                    correlationKey = newAlert.correlationKey,
                    shadowModel = newAlert.shadowModel,
                    shadowScore = newAlert.shadowScore,
                    suppressionReason = newAlert.suppressionReason,
                    dataQualityWarningsCsv = newAlert.dataQualityWarnings.joinToString(","),
                    beaconScore = newAlert.beaconScore,
                    destinationIp = newAlert.destinationIp,
                    destinationPort = newAlert.destinationPort,
                    destinationHash = newAlert.destinationHash,
                    siteHint = newAlert.siteHint,
                    mitreTechniquesCsv = newAlert.mitreTechniques.joinToString(","),
                    destinationIdentity = newAlert.destinationIdentity,
                    lookalikeScore = newAlert.lookalikeScore
                )
            )
            newAlert
        }

        enqueueAlertForExport(alert = alert, window = scoringWindow, siteHint = siteHint)

        return@withContext alert
    }

    suspend fun latestAlerts(limit: Int = 20): List<AnomalyAlert> = withContext(Dispatchers.IO) {
        dao.getLatestScores(limit).map { mapEntityToAlert(it) }
    }

    suspend fun alertCount(): Int = withContext(Dispatchers.IO) {
        dao.countScores()
    }

    suspend fun alertsByTriage(status: TriageStatus, limit: Int = 50): List<AnomalyAlert> = withContext(Dispatchers.IO) {
        dao.getScoresByTriage(status.name, limit).map { mapEntityToAlert(it) }
    }

    private suspend fun cachedPendingExportCount(): Int {
        val now = System.currentTimeMillis()
        synchronized(pendingExportCountLock) {
            if (now - pendingExportCountCachedAtMillis <= PENDING_EXPORT_COUNT_CACHE_TTL_MILLIS) {
                return pendingExportCountCachedValue
            }
        }
        val fresh = dao.countPendingExports()
        synchronized(pendingExportCountLock) {
            pendingExportCountCachedAtMillis = now
            pendingExportCountCachedValue = fresh
        }
        return fresh
    }

    private fun protectedBrandsFor(csv: String): List<String> {
        synchronized(protectedBrandsLock) {
            if (csv == protectedBrandsCachedCsv) {
                return protectedBrandsCachedValue
            }
            val parsed = csv.lineSequence()
                .map { it.trim().lowercase() }
                .filter { it.isNotBlank() }
                .distinct()
                .toList()
            protectedBrandsCachedCsv = csv
            protectedBrandsCachedValue = parsed
            return parsed
        }
    }

    private fun cachedAppProfile(appId: String): AppProfile {
        val now = System.currentTimeMillis()
        synchronized(appProfileCache) {
            appProfileCache[appId]?.let { (cachedAt, profile) ->
                if (now - cachedAt <= SETTINGS_LOOKUP_CACHE_TTL_MILLIS) {
                    return profile
                }
            }
        }
        val fresh = settingsStore.getAppProfile(appId)
        synchronized(appProfileCache) {
            appProfileCache[appId] = now to fresh
            while (appProfileCache.size > 512) {
                val eldest = appProfileCache.entries.firstOrNull()?.key ?: break
                appProfileCache.remove(eldest)
            }
        }
        return fresh
    }

    suspend fun updateAlertTriage(alertId: String, status: TriageStatus, note: String) = withContext(Dispatchers.IO) {
        dao.updateAlertTriage(
            alertId = alertId,
            triageStatus = status.name,
            triageNote = note,
            updatedAtMillis = System.currentTimeMillis()
        )

        val updatedEntity = dao.getScoreById(alertId)
        if (updatedEntity != null) {
            applyAnalystFeedbackThresholdAdjustment(appId = updatedEntity.appId, status = status)
            dao.getFeatureWindowById(updatedEntity.featureWindowId)?.let { windowEntity ->
                anomalyEngine.recordFeedback(
                    window = mapFeatureWindowEntity(windowEntity),
                    status = status
                )
            }
        }
        val config = settingsStore.readConfig()
        if (updatedEntity != null && config.isEffectiveExportEnabled()) {
            val exportedAppId = exportAppId(updatedEntity.appId, config.privacyMode, config.customPrivacy)
            val payload = JSONObject()
                .put("event_type", "mobile_alert")
                .put("event_version", "1.0")
                .put("device_id_pseudo", pseudonymousDeviceId())
                .put("device_label", currentDeviceLabel().takeIf { config.privacyMode != PrivacyMode.CUSTOM || config.customPrivacy.includeDeviceLabel })
                .put("alert_id", updatedEntity.id)
                .put("app_id", exportedAppId)
                .put("anomaly_score", updatedEntity.score)
                .put("base_anomaly_score", updatedEntity.anomalyScore)
                .put("context_score", updatedEntity.contextScore)
                .put("response_score", updatedEntity.score)
                .put("severity", updatedEntity.severity)
                .put(
                    "top_features",
                    if (config.privacyMode == PrivacyMode.CUSTOM && !config.customPrivacy.includeExplanations) JSONArray()
                    else JSONArray(updatedEntity.topFeaturesCsv.split(',').filter { it.isNotBlank() })
                )
                .put(
                    "explanation",
                    if (config.privacyMode == PrivacyMode.CUSTOM && !config.customPrivacy.includeExplanations) ""
                    else updatedEntity.explanation
                )
                .put("source_model", updatedEntity.sourceModel)
                .put("confidence", updatedEntity.confidence)
                .put("uncertainty", updatedEntity.uncertainty)
                .put("drift_score", updatedEntity.driftScore)
                .put("occurrence_count", updatedEntity.occurrenceCount)
                .put("first_seen", updatedEntity.firstSeenMillis)
                .put("last_seen", updatedEntity.lastSeenMillis)
                .put("correlation_key", updatedEntity.correlationKey)
                .put("shadow_model", updatedEntity.shadowModel)
                .put("shadow_score", updatedEntity.shadowScore)
                .put("suppression_reason", updatedEntity.suppressionReason)
                .put("data_quality_warnings", JSONArray(updatedEntity.dataQualityWarningsCsv.split(',').filter { it.isNotBlank() }))
                .put("beacon_score", updatedEntity.beaconScore)
                .put("triage_status", status.name)
                .put("triage_note", note)
                .put("site_hint", exportSiteHint(updatedEntity.siteHint, config.privacyMode, config.customPrivacy))
                .put("timestamp", updatedEntity.createdAtMillis)
                .toString()

            dao.enqueueExport(
                ExportQueueEntity(
                    eventType = "mobile_alert",
                    payload = payload,
                    createdAtMillis = System.currentTimeMillis(),
                    lastAttemptMillis = 0,
                    nextAttemptMillis = System.currentTimeMillis(),
                    attempts = 0,
                    exported = false
                )
            )
        }
    }

    suspend fun removeAlert(alertId: String) = withContext(Dispatchers.IO) {
        dao.deleteAlertById(alertId)
    }

    suspend fun clearAllAlerts() = withContext(Dispatchers.IO) {
        dao.purgeScores()
    }

    suspend fun backfillRecentExports(maxFlows: Int = 300, maxAlerts: Int = 200): Int = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (!config.isEffectiveExportEnabled()) {
            return@withContext 0
        }

        val sinceMillis = config.lastExportSuccessEpoch.coerceAtLeast(0L)
        var queued = 0

        dao.getLatestFlows(maxFlows)
            .asReversed()
            .forEach { entity ->
                if (sinceMillis > 0L && entity.timestampEndMillis <= sinceMillis) {
                    return@forEach
                }
                enqueueFlowForExport(flow = mapRawFlowEntity(entity), siteHint = entity.siteHint)
                queued += 1
            }

        dao.getLatestScores(maxAlerts)
            .asReversed()
            .forEach { entity ->
                if (sinceMillis > 0L && entity.createdAtMillis <= sinceMillis) {
                    return@forEach
                }
                val windowEntity = dao.getFeatureWindowById(entity.featureWindowId) ?: return@forEach
                enqueueAlertForExport(
                    alert = mapEntityToAlert(entity),
                    window = mapFeatureWindowEntity(windowEntity),
                    siteHint = entity.siteHint
                )
                queued += 1
            }

        queued
    }

    suspend fun processExportQueue(client: NetworkEventClient, batchSize: Int = 50): Int = withContext(Dispatchers.IO) {
        if (!settingsStore.readConfig().isEffectiveExportEnabled()) {
            settingsStore.recordExportResult(sentCount = 0, error = null)
            return@withContext 0
        }
        val now = System.currentTimeMillis()
        val pending = dao.getPendingExports(now, batchSize)
        if (pending.isEmpty()) {
            settingsStore.recordExportResult(sentCount = 0, error = null)
            return@withContext 0
        }

        var sent = 0
        var lastError: String? = null
        pending.forEach { entry ->
            val result = client.sendEvent(eventType = entry.eventType, payload = entry.payload)
            if (result.isSuccess) {
                dao.markExported(entry.queueId, now)
                sent += 1
            } else {
                lastError = result.exceptionOrNull()?.message
                if (lastError?.contains("status 422") == true) {
                    // Validation failures are permanent for the queued payload; retrying only blocks newer events.
                    dao.markExported(entry.queueId, now)
                } else {
                    val nextAttempts = entry.attempts + 1
                    val backoffMillis = min(60_000L, 2_000L * (1 shl entry.attempts.coerceAtMost(5)))
                    dao.rescheduleExport(
                        queueId = entry.queueId,
                        attempts = nextAttempts,
                        attemptMillis = now,
                        nextAttemptMillis = now + backoffMillis
                    )
                }
            }
        }
        settingsStore.recordExportResult(sentCount = sent, error = lastError)
        sent
    }

    suspend fun refreshBackendConnection(client: NetworkEventClient): Result<String> = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (config.backendUrl.isBlank()) {
            settingsStore.recordServerPing(status = "offline", detail = "Backend URL missing")
            settingsStore.recordDeviceHeartbeat(status = "offline", detail = "Backend URL missing")
            return@withContext Result.failure(IllegalStateException("Backend URL is not configured"))
        }

        val serverResult = client.pingBackend()
        if (serverResult.isFailure) {
            val error = serverResult.exceptionOrNull()?.message ?: "Server unreachable"
            settingsStore.recordServerPing(status = "offline", detail = error)
            settingsStore.recordDeviceHeartbeat(status = "offline", detail = "Server unreachable")
            return@withContext Result.failure(IllegalStateException(error))
        }

        settingsStore.recordServerPing(
            status = "online",
            detail = serverResult.getOrNull()?.take(240)?.takeIf { it.isNotBlank() } ?: "Server reachable"
        )
        if (!config.isConfigured()) {
            settingsStore.recordDeviceHeartbeat(
                status = "not_configured",
                detail = "API token missing, so device presence was not refreshed"
            )
            return@withContext Result.success("Server reachable. Add an API token to refresh device presence.")
        }

        val heartbeatResult = client.sendDeviceHeartbeat(
            deviceIdPseudo = pseudonymousDeviceId(),
            deviceLabel = currentDeviceLabel(),
        )
        if (heartbeatResult.isFailure) {
            val error = heartbeatResult.exceptionOrNull()?.message ?: "Device heartbeat failed"
            settingsStore.recordDeviceHeartbeat(status = "offline", detail = error)
            return@withContext Result.success("Server reachable, but device presence refresh failed: $error")
        }

        settingsStore.recordDeviceHeartbeat(
            status = "online",
            detail = heartbeatResult.getOrNull()?.take(240)?.takeIf { it.isNotBlank() } ?: "Device presence refreshed"
        )
        Result.success("Server reachable and device presence refreshed.")
    }

    suspend fun syncRemotePolicy(client: NetworkEventClient): Result<Unit> = withContext(Dispatchers.IO) {
        val result = client.fetchRemotePolicy(pseudonymousDeviceId())
        if (result.isFailure) {
            return@withContext Result.failure(result.exceptionOrNull() ?: IllegalStateException("Unknown policy sync error"))
        }

        val policy = result.getOrThrow()
        settingsStore.applyRemotePolicy(policy)
        refreshBackendConnection(client)
        Result.success(Unit)
    }

    suspend fun runRetentionCleanup(retentionDays: Int = settingsStore.readConfig().retentionDays): Int = withContext(Dispatchers.IO) {
        val cutoff = System.currentTimeMillis() - retentionDays * 24L * 60L * 60L * 1000L
        val deletedFlows = dao.deleteOldFlows(cutoff)
        val deletedWindows = dao.deleteOldFeatureWindows(cutoff)
        val deletedScores = dao.deleteOldScores(cutoff)
        val deletedExported = dao.deleteOldExported(cutoff)
        deletedFlows + deletedWindows + deletedScores + deletedExported
    }

    suspend fun purgeAllLocalData() = withContext(Dispatchers.IO) {
        dao.purgeRawFlows()
        dao.purgeFeatureWindows()
        dao.purgeScores()
        dao.purgeExportQueue()
    }

    suspend fun clearPendingExports() = withContext(Dispatchers.IO) {
        dao.purgeExportQueue()
    }

    suspend fun exportLatestFlowsCsv(maxRows: Int = 20_000): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val safeLimit = maxRows.coerceIn(1, 100_000)
            val flows = dao.getLatestFlows(safeLimit).asReversed()
            val exportRoot = File(appContext.getExternalFilesDir(null), "exports")
            if (!exportRoot.exists()) {
                exportRoot.mkdirs()
            }

            val outputFile = File(exportRoot, "flows-${System.currentTimeMillis()}.csv")
            val config = settingsStore.readConfig()
            val customPrivacy = config.customPrivacy
            val salt = settingsStore.getDeviceSalt()

            outputFile.bufferedWriter(Charsets.UTF_8).use { writer ->
                writer.appendLine(
                    "timestamp_start_ms,timestamp_end_ms,app_id,protocol,src_ip,src_port," +
                        "dst_ip,dst_port,destination_key,site_hint,bytes_out,bytes_in,packets_out,packets_in,duration_ms,is_new_destination_for_app," +
                        "dns_query_name,dns_query_type,dns_response_code,dns_answer_value,tls_sni,tls_alpn,tls_version,tls_ja3_like,tls_leaf_subject,tls_leaf_issuer,tls_leaf_san," +
                        "http_method,http_host,http_path,quic_version,quic_detected,http3_detected,registrable_domain,brand_match,lookalike_score,threat_tags,mitre_techniques"
                )

                flows.forEach { flow ->
                    val protocolEvidence = ProtocolEvidence.fromJsonString(flow.protocolEvidenceJson)
                    val destinationInsight = DestinationInsight.fromJsonString(flow.destinationInsightJson)
                    val exportedAppId = exportAppId(flow.appId, config.privacyMode, customPrivacy)
                    val exportedSrcIp = exportFlowIp(flow.srcIp, config.privacyMode, customPrivacy, salt)
                    val exportedDstIp = exportFlowIp(flow.dstIp, config.privacyMode, customPrivacy, salt)
                    val exportedSiteHint = exportSiteHint(flow.siteHint, config.privacyMode, customPrivacy) ?: ""
                    val exportedSrcPort = exportFlowPort(flow.srcPort, config.privacyMode, customPrivacy)
                    val exportedDstPort = exportFlowPort(flow.dstPort, config.privacyMode, customPrivacy)
                    val exportedDestinationKey = exportDestinationKey(flow, config.privacyMode, customPrivacy, salt)

                    writer.appendLine(
                        listOf(
                            flow.timestampStartMillis,
                            flow.timestampEndMillis,
                            exportedAppId,
                            flow.protocol,
                            exportedSrcIp,
                            exportedSrcPort,
                            exportedDstIp,
                            exportedDstPort,
                            exportedDestinationKey,
                            exportedSiteHint,
                            flow.bytesOut,
                            flow.bytesIn,
                            flow.packetsOut,
                            flow.packetsIn,
                            flow.durationMillis,
                            flow.destinationNovelty,
                            protocolEvidence.dnsQueryName,
                            protocolEvidence.dnsQueryType,
                            protocolEvidence.dnsResponseCode,
                            protocolEvidence.dnsAnswerValue,
                            protocolEvidence.tlsSni,
                            protocolEvidence.tlsAlpn,
                            protocolEvidence.tlsVersion,
                            protocolEvidence.tlsJa3Like,
                            protocolEvidence.tlsLeafSubject,
                            protocolEvidence.tlsLeafIssuer,
                            protocolEvidence.tlsLeafSan,
                            protocolEvidence.httpMethod,
                            protocolEvidence.httpHost,
                            protocolEvidence.httpPath,
                            protocolEvidence.quicVersion,
                            protocolEvidence.quicDetected,
                            protocolEvidence.http3Detected,
                            destinationInsight.registrableDomain,
                            destinationInsight.brandMatch,
                            destinationInsight.lookalikeScore,
                            destinationInsight.threatTags.joinToString("|"),
                            destinationInsight.mitreTechniques.joinToString("|")
                        ).joinToString(",") { csvCell(it) }
                    )
                }
            }

            outputFile.absolutePath
        }
    }

    suspend fun exportLatestAlertsJson(maxRows: Int = 25_000): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val safeLimit = maxRows.coerceIn(1, 50_000)
            val alerts = dao.getLatestScores(safeLimit).asReversed()
            val exportRoot = File(appContext.getExternalFilesDir(null), "exports")
            if (!exportRoot.exists()) {
                exportRoot.mkdirs()
            }

            val outputFile = File(exportRoot, "alerts-${System.currentTimeMillis()}.json")
            val config = settingsStore.readConfig()
            val alertsPayload = JSONObject()
                .put("generated_at", System.currentTimeMillis())
                .put("privacy_mode", config.privacyMode.name.lowercase())
                .put(
                    "alerts",
                    JSONArray(
                        alerts.map { entity ->
                            JSONObject()
                                .put("id", entity.id)
                                .put("app_id", exportAppId(entity.appId, config.privacyMode, config.customPrivacy))
                                .put("score", entity.score)
                                .put("severity", entity.severity)
                                .put("source_model", entity.sourceModel)
                                .put("confidence", entity.confidence)
                                .put("uncertainty", entity.uncertainty)
                                .put("drift_score", entity.driftScore)
                                .put("occurrence_count", entity.occurrenceCount)
                                .put("first_seen", entity.firstSeenMillis)
                                .put("last_seen", entity.lastSeenMillis)
                                .put("correlation_key", entity.correlationKey)
                                .put("triage_status", entity.triageStatus)
                                .put("triage_note", entity.triageNote)
                                .put("explanation", entity.explanation)
                                .put("top_features", JSONArray(entity.topFeaturesCsv.split(',').filter { it.isNotBlank() }))
                                .put("feature_contributions", JSONObject(deserializeFeatureContributions(entity.featureContributionsJson)))
                                .put("site_hint", exportSiteHint(entity.siteHint, config.privacyMode, config.customPrivacy))
                                .put("mitre_techniques", JSONArray(entity.mitreTechniquesCsv.split(',').filter { it.isNotBlank() }))
                                .put("destination_identity", entity.destinationIdentity)
                                .put("lookalike_score", entity.lookalikeScore)
                        }
                    )
                )
            outputFile.writeText(alertsPayload.toString(2), Charsets.UTF_8)
            outputFile.absolutePath
        }
    }

    suspend fun exportForensicsBundle(maxRows: Int = 20_000): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val exportRoot = File(appContext.getExternalFilesDir(null), "exports")
            if (!exportRoot.exists()) {
                exportRoot.mkdirs()
            }
            val timestamp = System.currentTimeMillis()
            val bundleDir = File(exportRoot, "forensics-$timestamp")
            if (!bundleDir.exists()) {
                bundleDir.mkdirs()
            }

            val flowCsvPath = exportLatestFlowsCsv(maxRows).getOrThrow()
            val flowCsv = File(flowCsvPath)
            val flowCopy = File(bundleDir, "flows.csv")
            flowCsv.copyTo(flowCopy, overwrite = true)

            val alertsFile = File(bundleDir, "alerts.json")
            val privacyMode = settingsStore.readConfig().privacyMode
            val salt = settingsStore.getDeviceSalt()
            val alertsPayload = JSONObject()
                .put("generated_at", timestamp)
                .put(
                    "alerts",
                    JSONArray(
                        dao.getLatestScores(25_000).map { entity ->
                            JSONObject()
                                .put("id", entity.id)
                                .put("app_id", exportAppId(entity.appId, privacyMode, settingsStore.readConfig().customPrivacy))
                                .put("score", entity.score)
                                .put("severity", entity.severity)
                                .put("source_model", entity.sourceModel)
                                .put("confidence", entity.confidence)
                                .put("uncertainty", entity.uncertainty)
                                .put("drift_score", entity.driftScore)
                                .put("occurrence_count", entity.occurrenceCount)
                                .put("first_seen", entity.firstSeenMillis)
                                .put("last_seen", entity.lastSeenMillis)
                                .put("correlation_key", entity.correlationKey)
                                .put("triage_status", entity.triageStatus)
                                .put("triage_note", entity.triageNote)
                                .put("explanation", entity.explanation)
                                .put("top_features", JSONArray(entity.topFeaturesCsv.split(',').filter { it.isNotBlank() }))
                                .put("feature_contributions", JSONObject(deserializeFeatureContributions(entity.featureContributionsJson)))
                                .put("site_hint", exportSiteHint(entity.siteHint, privacyMode, settingsStore.readConfig().customPrivacy))
                                .put("mitre_techniques", JSONArray(entity.mitreTechniquesCsv.split(',').filter { it.isNotBlank() }))
                                .put("destination_identity", entity.destinationIdentity)
                                .put("lookalike_score", entity.lookalikeScore)
                        }
                    )
                )
            alertsFile.writeText(alertsPayload.toString(2), Charsets.UTF_8)

            val policyFile = File(bundleDir, "policy.json")
            val config = settingsStore.readConfig()
            val policyPayload = JSONObject()
                .put("backend_url", if (config.privacyMode == PrivacyMode.STRICT) "" else config.backendUrl)
                .put("export_enabled", config.exportEnabled)
                .put("privacy_mode", config.privacyMode.name.lowercase())
                .put("privacy_mode_enabled", config.privacyModeEnabled)
                .put("debug_mode_enabled", config.debugModeEnabled)
                .put("detection_model", config.detectionModel)
                .put("shadow_model", config.shadowModel)
                .put("policy_version", config.policyVersion)
                .put("retention_days", config.retentionDays)
                .put("default_thresholds", JSONObject().put("low", config.lowThreshold).put("medium", config.mediumThreshold).put("high", config.highThreshold))
                .put("false_positive_budget_per_app_day", config.falsePositiveBudgetPerAppDay)
                .put("drift_high_threshold", config.driftHighThreshold)
                .put("fusion_weights", JSONObject()
                    .put("statistical", config.fusionWeights.statistical)
                    .put("multivariate", config.fusionWeights.multivariate)
                    .put("sequence", config.fusionWeights.sequence)
                    .put("linear", config.fusionWeights.linear)
                    .put("tflite", config.fusionWeights.tflite)
                    .put("remote", config.fusionWeights.remote)
                    .put("beacon", config.fusionWeights.beacon)
                    .put("drift", config.fusionWeights.drift)
                    .put("reputation", config.fusionWeights.reputation)
                    .put("data_quality_penalty", config.fusionWeights.dataQualityPenalty)
                    .put("response_anomaly", config.fusionWeights.responseAnomalyBlend)
                    .put("response_context", config.fusionWeights.responseContextBlend)
                )
            policyFile.writeText(policyPayload.toString(2), Charsets.UTF_8)

            val diagnosticsFile = File(bundleDir, "diagnostics.json")
            val diagPayload = JSONObject()
                .put("generated_at", timestamp)
                .put("data_quality_counters", JSONObject(dataQualityMonitor.snapshotCounters()))
                .put("guardrail", JSONObject(runtimeGuardrailManager.diagnostics()))
                .put("packet_pipeline", JSONObject(packetPipelineStats.snapshot().toMap()))
            diagnosticsFile.writeText(diagPayload.toString(2), Charsets.UTF_8)

            val connectivityFile = File(bundleDir, "connectivity.json")
            val connectivityPayload = JSONObject()
                .put("generated_at", timestamp)
                .put("last_export_success_epoch", config.lastExportSuccessEpoch)
                .put("last_export_error", config.lastExportError)
                .put("last_export_sent_count", config.lastExportSentCount)
                .put("last_policy_sync_epoch", config.lastPolicySyncEpoch)
                .put("last_policy_sync_status", config.lastPolicySyncStatus)
                .put("last_policy_diff_summary", config.lastPolicyDiffSummary)
                .put("last_server_ping_epoch", config.lastServerPingEpoch)
                .put("last_server_ping_status", config.lastServerPingStatus)
                .put("last_server_ping_detail", config.lastServerPingDetail)
                .put("last_device_heartbeat_epoch", config.lastDeviceHeartbeatEpoch)
                .put("last_device_heartbeat_status", config.lastDeviceHeartbeatStatus)
                .put("last_device_heartbeat_detail", config.lastDeviceHeartbeatDetail)
                .put("privacy_mode", config.privacyMode.name.lowercase())
                .put("privacy_mode_enabled", config.privacyModeEnabled)
                .put("debug_mode_enabled", config.debugModeEnabled)
            connectivityFile.writeText(connectivityPayload.toString(2), Charsets.UTF_8)

            val previewFile = File(bundleDir, "export-preview.json")
            val previewPayload = JSONObject()
                .put("generated_at", timestamp)
                .put("privacy_mode", config.privacyMode.name.lowercase())
                .put("privacy_mode_enabled", config.privacyModeEnabled)
                .put("flow_sample", buildFlowExportPreview(config))
                .put("alert_sample", buildAlertExportPreview(config))
            previewFile.writeText(previewPayload.toString(2), Charsets.UTF_8)

            val manifestFile = File(bundleDir, "manifest.json")
            val manifest = JSONObject()
                .put("generated_at", timestamp)
                .put("bundle_version", "1.0")
                .put("device_id_pseudo", pseudonymousDeviceId())
                .put("contents", listOf("flows.csv", "alerts.json", "policy.json", "diagnostics.json", "connectivity.json", "export-preview.json"))
            manifestFile.writeText(manifest.toString(2), Charsets.UTF_8)

            val zipFile = File(exportRoot, "forensics-$timestamp.zip")
            ZipOutputStream(FileOutputStream(zipFile)).use { zip ->
                bundleDir.listFiles().orEmpty().forEach { file ->
                    zip.putNextEntry(ZipEntry(file.name))
                    file.inputStream().use { input -> input.copyTo(zip) }
                    zip.closeEntry()
                }
            }

            bundleDir.listFiles().orEmpty().forEach { it.delete() }
            bundleDir.delete()
            zipFile.absolutePath
        }
    }

    private fun computeCorrelationKey(appId: String, sourceModel: String, topFeatures: List<String>): String {
        val normalized = topFeatures.map { it.trim().lowercase() }.sorted().take(3).joinToString("|")
        return CryptoUtils.sha256("$appId|$sourceModel|$normalized")
    }

    private fun maxSeverity(left: AlertSeverity, right: AlertSeverity): AlertSeverity {
        val rank = mapOf(AlertSeverity.LOW to 1, AlertSeverity.MEDIUM to 2, AlertSeverity.HIGH to 3)
        return if ((rank[left] ?: 0) >= (rank[right] ?: 0)) left else right
    }

    private fun applyAnalystFeedbackThresholdAdjustment(appId: String, status: TriageStatus) {
        val current = settingsStore.getThresholdForApp(appId)
        val next = when (status) {
            TriageStatus.FALSE_POSITIVE -> ThresholdProfile(
                low = (current.low + FEEDBACK_ADJUST_STEP_FP).coerceAtMost(0.90),
                medium = (current.medium + FEEDBACK_ADJUST_STEP_FP).coerceAtMost(0.95),
                high = (current.high + FEEDBACK_ADJUST_STEP_FP).coerceAtMost(0.99)
            ).normalize()

            TriageStatus.RESOLVED -> ThresholdProfile(
                low = (current.low - FEEDBACK_ADJUST_STEP_TRUE_POSITIVE).coerceAtLeast(0.02),
                medium = (current.medium - FEEDBACK_ADJUST_STEP_TRUE_POSITIVE).coerceAtLeast(0.05),
                high = (current.high - FEEDBACK_ADJUST_STEP_TRUE_POSITIVE).coerceAtLeast(0.15)
            ).normalize()

            TriageStatus.INVESTIGATING,
            TriageStatus.OPEN -> current
        }
        if (next != current) {
            settingsStore.setThresholdOverride(appId = appId, profile = next)
        }
    }

    private suspend fun saveFeatureWindow(window: FeatureWindow) {
        dao.insertFeatureWindow(
            FeatureWindowEntity(
                id = window.id,
                appId = window.appId,
                windowStartMillis = window.windowStartMillis,
                windowEndMillis = window.windowEndMillis,
                flowCount = window.flowCount,
                totalBytesOut = window.totalBytesOut,
                totalBytesIn = window.totalBytesIn,
                meanPacketSize = window.meanPacketSize,
                outboundRatio = window.outboundRatio,
                burstiness = window.burstiness,
                noveltyScore = window.noveltyScore,
                connectionFrequencyDelta = window.connectionFrequencyDelta,
                bytesPerFlow = window.bytesPerFlow,
                destinationDiversity = window.destinationDiversity,
                activityRatio = window.activityRatio,
                byteRate = window.byteRate,
                packetRate = window.packetRate,
                meanDurationMillis = window.meanDurationMillis,
                durationJitter = window.durationJitter,
                portDiversity = window.portDiversity,
                protocolDiversity = window.protocolDiversity,
                packetImbalance = window.packetImbalance,
                smallFlowRatio = window.smallFlowRatio,
                highPortRatio = window.highPortRatio,
                periodicBeaconScore = window.periodicBeaconScore,
                hourOfDay = window.hourOfDay,
                dayOfWeek = window.dayOfWeek,
                isWeekend = window.isWeekend,
                dataQualityScore = window.dataQualityScore,
                ttlGap = window.ttlGap,
                ttlMetricsPresent = window.ttlMetricsPresent,
                synRateTotal = window.synRateTotal,
                rstRateTotal = window.rstRateTotal,
                ackRateTotal = window.ackRateTotal,
                finRateTotal = window.finRateTotal,
                pshRateTotal = window.pshRateTotal,
                fragmentRateTotal = window.fragmentRateTotal,
                tcpWindowMean = window.tcpWindowMean,
                ackDelayMean = window.ackDelayMean,
                interPacketGapMean = window.interPacketGapMean,
                payloadMean = window.payloadMean,
                loadMean = window.loadMean,
                transportMetricsPresent = window.transportMetricsPresent,
                sampledByGuardrail = window.sampledByGuardrail,
                processingCostMillis = window.processingCostMillis
            )
        )
    }

    private fun mapFeatureWindowEntity(entity: FeatureWindowEntity): FeatureWindow {
        return FeatureWindow(
            id = entity.id,
            appId = entity.appId,
            windowStartMillis = entity.windowStartMillis,
            windowEndMillis = entity.windowEndMillis,
            flowCount = entity.flowCount,
            totalBytesOut = entity.totalBytesOut,
            totalBytesIn = entity.totalBytesIn,
            meanPacketSize = entity.meanPacketSize,
            outboundRatio = entity.outboundRatio,
            burstiness = entity.burstiness,
            noveltyScore = entity.noveltyScore,
            connectionFrequencyDelta = entity.connectionFrequencyDelta,
            bytesPerFlow = entity.bytesPerFlow,
            destinationDiversity = entity.destinationDiversity,
            activityRatio = entity.activityRatio,
            byteRate = entity.byteRate,
            packetRate = entity.packetRate,
            meanDurationMillis = entity.meanDurationMillis,
            durationJitter = entity.durationJitter,
            portDiversity = entity.portDiversity,
            protocolDiversity = entity.protocolDiversity,
            packetImbalance = entity.packetImbalance,
            smallFlowRatio = entity.smallFlowRatio,
            highPortRatio = entity.highPortRatio,
            periodicBeaconScore = entity.periodicBeaconScore,
            hourOfDay = entity.hourOfDay,
            dayOfWeek = entity.dayOfWeek,
            isWeekend = entity.isWeekend,
            dataQualityScore = entity.dataQualityScore,
            ttlGap = entity.ttlGap,
            ttlMetricsPresent = entity.ttlMetricsPresent,
            synRateTotal = entity.synRateTotal,
            rstRateTotal = entity.rstRateTotal,
            ackRateTotal = entity.ackRateTotal,
            finRateTotal = entity.finRateTotal,
            pshRateTotal = entity.pshRateTotal,
            fragmentRateTotal = entity.fragmentRateTotal,
            tcpWindowMean = entity.tcpWindowMean,
            ackDelayMean = entity.ackDelayMean,
            interPacketGapMean = entity.interPacketGapMean,
            payloadMean = entity.payloadMean,
            loadMean = entity.loadMean,
            transportMetricsPresent = entity.transportMetricsPresent,
            sampledByGuardrail = entity.sampledByGuardrail,
            processingCostMillis = entity.processingCostMillis
        )
    }

    private suspend fun enqueueFlowForExport(flow: FlowRecord, siteHint: String?) {
        val config = settingsStore.readConfig()
        if (!config.isEffectiveExportEnabled()) {
            return
        }
        val payload = flow.toJson(
            deviceIdPseudo = pseudonymousDeviceId(),
            anomalyScore = null,
            explainTopFeatures = emptyList(),
            siteHint = exportSiteHint(siteHint, config.privacyMode, config.customPrivacy),
            deviceLabel = currentDeviceLabel(),
            privacyMode = config.privacyMode,
            deviceSalt = settingsStore.getDeviceSalt(),
            customPrivacy = config.customPrivacy
        )
        dao.enqueueExport(
            ExportQueueEntity(
                eventType = "mobile_flow",
                payload = payload,
                createdAtMillis = System.currentTimeMillis(),
                lastAttemptMillis = 0,
                nextAttemptMillis = System.currentTimeMillis(),
                attempts = 0,
                exported = false
            )
        )
    }

    private suspend fun enqueueAlertForExport(alert: AnomalyAlert, window: FeatureWindow, siteHint: String?) {
        val config = settingsStore.readConfig()
        if (!config.isEffectiveExportEnabled()) {
            return
        }
        val exportedAppId = exportAppId(alert.appId, config.privacyMode, config.customPrivacy)
        val customPrivacy = config.customPrivacy

        val payload = JSONObject()
            .put("event_type", "mobile_alert")
            .put("event_version", "1.0")
            .put("device_id_pseudo", pseudonymousDeviceId())
            .put("device_label", currentDeviceLabel().takeIf { config.privacyMode != PrivacyMode.CUSTOM || customPrivacy.includeDeviceLabel })
            .put("alert_id", alert.id)
            .put("app_id", exportedAppId)
            .put("anomaly_score", alert.anomalyScore)
            .put("base_anomaly_score", alert.baseAnomalyScore)
            .put("context_score", alert.contextScore)
            .put("response_score", alert.responseScore)
            .put("severity", alert.severity.name)
            .put(
                "top_features",
                if (config.privacyMode == PrivacyMode.CUSTOM && !customPrivacy.includeExplanations) JSONArray()
                else JSONArray(alert.topFeatures)
            )
            .put(
                "feature_contributions",
                if (config.privacyMode == PrivacyMode.CUSTOM && !customPrivacy.includeExplanations) JSONObject()
                else JSONObject(serializeFeatureContributions(alert.featureContributions))
            )
            .put(
                "explanation",
                if (config.privacyMode == PrivacyMode.CUSTOM && !customPrivacy.includeExplanations) ""
                else alert.explanation
            )
            .put("source_model", alert.sourceModel)
            .put("site_hint", exportSiteHint(siteHint, config.privacyMode, customPrivacy))
            .put("destination_identity", alert.destinationIdentity)
            .put("lookalike_score", alert.lookalikeScore)
            .put("mitre_techniques", JSONArray(alert.mitreTechniques))
            .put(
                "window_features",
                if (config.privacyMode == PrivacyMode.CUSTOM && !customPrivacy.includeFeatureWindow) {
                    JSONObject()
                } else {
                    JSONObject()
                        .put("flow_count", window.flowCount)
                        .put("bytes_out", window.totalBytesOut)
                        .put("bytes_in", window.totalBytesIn)
                        .put("mean_packet_size", window.meanPacketSize)
                        .put("outbound_ratio", window.outboundRatio)
                        .put("burstiness", window.burstiness)
                        .put("novelty_score", window.noveltyScore)
                        .put("connection_frequency_delta", window.connectionFrequencyDelta)
                        .put("bytes_per_flow", window.bytesPerFlow)
                        .put("destination_diversity", window.destinationDiversity)
                        .put("activity_ratio", window.activityRatio)
                        .put("periodic_beacon_score", window.periodicBeaconScore)
                        .put("byte_rate", window.byteRate)
                        .put("packet_rate", window.packetRate)
                        .put("mean_duration_ms", window.meanDurationMillis)
                        .put("duration_jitter", window.durationJitter)
                        .put("port_diversity", window.portDiversity)
                        .put("protocol_diversity", window.protocolDiversity)
                        .put("packet_imbalance", window.packetImbalance)
                        .put("small_flow_ratio", window.smallFlowRatio)
                        .put("high_port_ratio", window.highPortRatio)
                        .put("hour_of_day", window.hourOfDay)
                        .put("is_weekend", window.isWeekend)
                        .put("data_quality_score", window.dataQualityScore)
                        .put("ttl_gap", window.ttlGap)
                        .put("ttl_metrics_present", window.ttlMetricsPresent)
                        .put("syn_rate_total", window.synRateTotal)
                        .put("rst_rate_total", window.rstRateTotal)
                        .put("ack_rate_total", window.ackRateTotal)
                        .put("fin_rate_total", window.finRateTotal)
                        .put("psh_rate_total", window.pshRateTotal)
                        .put("fragment_rate_total", window.fragmentRateTotal)
                        .put("tcp_window_mean", window.tcpWindowMean)
                        .put("ack_delay_mean", window.ackDelayMean)
                        .put("inter_packet_gap_mean", window.interPacketGapMean)
                        .put("payload_mean", window.payloadMean)
                        .put("load_mean", window.loadMean)
                        .put("transport_metrics_present", window.transportMetricsPresent)
                }
            )
            .put("confidence", alert.confidence)
            .put("uncertainty", alert.uncertainty)
            .put("drift_score", alert.driftScore)
            .put("occurrence_count", alert.occurrenceCount)
            .put("first_seen", alert.firstSeenMillis)
            .put("last_seen", alert.lastSeenMillis)
            .put("correlation_key", alert.correlationKey)
            .put("shadow_model", alert.shadowModel)
            .put("shadow_score", alert.shadowScore)
            .put("suppression_reason", alert.suppressionReason)
            .put("data_quality_warnings", JSONArray(alert.dataQualityWarnings))
            .put("beacon_score", alert.beaconScore)
            .put("triage_status", alert.triageStatus.name)
            .put("triage_note", alert.triageNote)
            .put("timestamp", alert.createdAtMillis)
            .toString()

        dao.enqueueExport(
            ExportQueueEntity(
                eventType = "mobile_alert",
                payload = payload,
                createdAtMillis = System.currentTimeMillis(),
                lastAttemptMillis = 0,
                nextAttemptMillis = System.currentTimeMillis(),
                attempts = 0,
                exported = false
            )
        )
    }

    private fun pseudonymousDeviceId(): String {
        return settingsStore.getPseudonymousDeviceId()
    }

    private fun mapRawFlowEntity(entity: RawFlowEntity): FlowRecord {
        return FlowRecord(
            id = entity.id,
            timestampStartMillis = entity.timestampStartMillis,
            timestampEndMillis = entity.timestampEndMillis,
            appId = entity.appId,
            ipVersion = entity.ipVersion,
            protocol = FlowProtocol.valueOf(entity.protocol),
            srcIp = entity.srcIp,
            srcPort = entity.srcPort,
            dstIp = entity.dstIp,
            dstPort = entity.dstPort,
            bytesOut = entity.bytesOut,
            bytesIn = entity.bytesIn,
            packetsOut = entity.packetsOut,
            packetsIn = entity.packetsIn,
            durationMillis = entity.durationMillis,
            destinationHash = entity.destinationHash,
            destinationNovelty = entity.destinationNovelty,
            siteHint = entity.siteHint,
            ttlGap = entity.ttlGap,
            ttlMetricsPresent = entity.ttlMetricsPresent,
            synRateTotal = entity.synRateTotal,
            rstRateTotal = entity.rstRateTotal,
            ackRateTotal = entity.ackRateTotal,
            finRateTotal = entity.finRateTotal,
            pshRateTotal = entity.pshRateTotal,
            fragmentRateTotal = entity.fragmentRateTotal,
            tcpWindowMean = entity.tcpWindowMean,
            ackDelayMean = entity.ackDelayMean,
            interPacketGapMean = entity.interPacketGapMean,
            payloadMean = entity.payloadMean,
            loadMean = entity.loadMean,
            transportMetricsPresent = entity.transportMetricsPresent,
            protocolEvidence = ProtocolEvidence.fromJsonString(entity.protocolEvidenceJson),
            destinationInsight = DestinationInsight.fromJsonString(entity.destinationInsightJson)
        )
    }

    private fun currentDeviceLabel(): String {
        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        val model = Build.MODEL?.trim().orEmpty()
        val deviceCode = Build.DEVICE?.trim().orEmpty()
        return listOf(manufacturer, model)
            .filter { it.isNotBlank() }
            .distinct()
            .joinToString(" ")
            .let { base ->
                when {
                    base.isBlank() && deviceCode.isNotBlank() -> deviceCode
                    deviceCode.isNotBlank() && !base.contains(deviceCode, ignoreCase = true) -> "$base ($deviceCode)"
                    else -> base
                }
            }
            .ifBlank { "Android device" }
    }

    private fun serializeFeatureContributions(value: Map<String, Double>): String {
        val json = JSONObject()
        value.toSortedMap().forEach { (feature, score) ->
            json.put(feature, score)
        }
        return json.toString()
    }

    private fun deserializeFeatureContributions(raw: String?): Map<String, Double> {
        val root = runCatching { JSONObject(raw ?: "{}") }.getOrDefault(JSONObject())
        val contributions = linkedMapOf<String, Double>()
        root.keys().forEach { key ->
            contributions[key] = root.optDouble(key, 0.0)
        }
        return contributions
    }

    private fun mapEntityToAlert(entity: AnomalyScoreEntity): AnomalyAlert {
        return AnomalyAlert(
            id = entity.id,
            featureWindowId = entity.featureWindowId,
            appId = entity.appId,
            anomalyScore = entity.score,
            severity = AlertSeverity.valueOf(entity.severity),
            topFeatures = entity.topFeaturesCsv.split(',').filter { it.isNotBlank() },
            featureContributions = deserializeFeatureContributions(entity.featureContributionsJson),
            explanation = entity.explanation,
            sourceModel = entity.sourceModel,
            triageStatus = TriageStatus.valueOf(entity.triageStatus),
            triageNote = entity.triageNote,
            createdAtMillis = entity.createdAtMillis,
            triageUpdatedAtMillis = entity.triageUpdatedAtMillis,
            confidence = entity.confidence,
            uncertainty = entity.uncertainty,
            baseAnomalyScore = entity.anomalyScore,
            contextScore = entity.contextScore,
            responseScore = entity.responseScore,
            driftScore = entity.driftScore,
            occurrenceCount = entity.occurrenceCount,
            firstSeenMillis = entity.firstSeenMillis,
            lastSeenMillis = entity.lastSeenMillis,
            correlationKey = entity.correlationKey,
            shadowModel = entity.shadowModel,
            shadowScore = entity.shadowScore,
            suppressionReason = entity.suppressionReason,
            dataQualityWarnings = entity.dataQualityWarningsCsv.split(',').filter { it.isNotBlank() },
            beaconScore = entity.beaconScore,
            destinationIp = entity.destinationIp,
            destinationPort = entity.destinationPort,
            destinationHash = entity.destinationHash,
            siteHint = entity.siteHint,
            mitreTechniques = entity.mitreTechniquesCsv.split(',').filter { it.isNotBlank() },
            destinationIdentity = entity.destinationIdentity,
            lookalikeScore = entity.lookalikeScore
        )
    }

    private fun resolveSiteHint(flow: FlowRecord, privacyModeEnabled: Boolean): String? {
        if (!flow.siteHint.isNullOrBlank()) {
            return flow.siteHint
        }
        if (!flow.protocolEvidence.preferredHost().isNullOrBlank()) {
            return flow.protocolEvidence.preferredHost()
        }
        synchronized(dnsAnswerCache) {
            dnsAnswerCache[flow.dstIp]?.let { return it }
        }
        if (privacyModeEnabled || !isBrowserLikeFlow(flow, siteHint = null)) {
            return null
        }
        if (isPrivateDestination(flow.dstIp)) {
            return null
        }

        return synchronized(siteHintCache) {
            if (siteHintCache.containsKey(flow.dstIp)) {
                siteHintCache[flow.dstIp]
            } else {
                val resolved = runCatching {
                    val canonical = InetAddress.getByName(flow.dstIp).canonicalHostName.orEmpty()
                    canonical
                        .takeIf { it.isNotBlank() && it != flow.dstIp }
                        ?.removePrefix("www.")
                }.getOrNull()
                siteHintCache[flow.dstIp] = resolved
                resolved
            }
        }
    }

    private fun recordDnsResolution(flow: FlowRecord) {
        val queryName = flow.protocolEvidence.dnsQueryName?.takeIf { it.isNotBlank() } ?: return
        val answer = flow.protocolEvidence.dnsAnswerValue?.takeIf { it.isNotBlank() } ?: return
        if (!answer.matches(Regex("""\d{1,3}(\.\d{1,3}){3}""")) && !answer.contains(':')) {
            return
        }
        synchronized(dnsAnswerCache) {
            dnsAnswerCache[answer] = queryName
            while (dnsAnswerCache.size > 2048) {
                val eldest = dnsAnswerCache.entries.firstOrNull()?.key ?: break
                dnsAnswerCache.remove(eldest)
            }
        }
    }

    private fun isBrowserApp(appId: String): Boolean {
        return appId in BROWSER_PACKAGES
    }

    private fun isPrivateDestination(ip: String): Boolean {
        return ip.startsWith("10.") ||
            ip.startsWith("127.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("172.16.") ||
            ip.startsWith("172.17.") ||
            ip.startsWith("172.18.") ||
            ip.startsWith("172.19.") ||
            ip.startsWith("172.20.") ||
            ip.startsWith("172.21.") ||
            ip.startsWith("172.22.") ||
            ip.startsWith("172.23.") ||
            ip.startsWith("172.24.") ||
            ip.startsWith("172.25.") ||
            ip.startsWith("172.26.") ||
            ip.startsWith("172.27.") ||
            ip.startsWith("172.28.") ||
            ip.startsWith("172.29.") ||
            ip.startsWith("172.30.") ||
            ip.startsWith("172.31.") ||
            ip.startsWith("fd") ||
            ip.startsWith("fe80")
    }

    private fun buildDangerSummary(flow: FlowRecord, siteHint: String?): String? {
        val reasons = linkedSetOf<String>()
        val insight = flow.destinationInsight
        if (flow.dstPort == 80 && isBrowserLikeFlow(flow, siteHint)) {
            reasons += "insecure plaintext web destination"
        }

        val host = siteHint?.lowercase().orEmpty()
        if (host.isNotBlank()) {
            when {
                host.contains("expired.badssl.com") -> reasons += "expired TLS certificate test host"
                host.contains("self-signed.badssl.com") -> reasons += "self-signed TLS certificate test host"
                host.contains("wrong.host.badssl.com") -> reasons += "TLS hostname mismatch test host"
                host.contains("revoked.badssl.com") -> reasons += "revoked TLS certificate test host"
                host.contains("pinning-test.badssl.com") -> reasons += "certificate pinning test host"
                host.contains("mixed.badssl.com") -> reasons += "mixed-content TLS test host"
                host.contains("http.badssl.com") -> reasons += "plaintext HTTP security test host"
                host.endsWith(".badssl.com") || host == "badssl.com" -> reasons += "TLS security test host"
                host.contains("neverssl.com") -> reasons += "browser plaintext web test host"
            }
            if (host.contains("xn--") ||
                host.endsWith(".zip") ||
                host.endsWith(".mov") ||
                host.endsWith(".top") ||
                host.endsWith(".xyz") ||
                host.endsWith(".click") ||
                host.endsWith(".gq") ||
                host.endsWith(".work") ||
                host.contains("login-") ||
                host.contains("verify-") ||
                host.contains("secure-") ||
                host.contains("update-") ||
                host.contains("password-") ||
                host.contains("billing-") ||
                host.contains("signin-")
            ) {
                reasons += "possible phishing-style domain"
            }
            if (host.contains("doubleclick") ||
                host.contains("googlesyndication") ||
                host.contains("googleadservices") ||
                host.contains("ads.") ||
                host.contains("tracking") ||
                host.contains("telemetry")
            ) {
                reasons += "tracking or telemetry destination"
            }
            if (host.contains("malware") || host.contains("phish") || host.contains("scam")) {
                reasons += "matches a locally suspicious keyword list"
            }
            if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) {
                reasons += "host appears as a direct IP literal"
            }
        }
        if (insight.lookalikeScore >= 0.55 && !insight.brandMatch.isNullOrBlank()) {
            reasons += "lookalike domain similar to ${insight.brandMatch}"
        }
        if (insight.punycodePresent) {
            reasons += "punycode domain"
        }
        if (insight.suspiciousTld) {
            reasons += "suspicious top-level domain"
        }
        insight.threatTags.forEach { reasons += it.replace('_', ' ') }
        if (!flow.protocolEvidence.tlsLeafSubject.isNullOrBlank()) {
            reasons += "tls certificate observed"
        }
        if (flow.protocolEvidence.http3Detected) {
            reasons += "quic/http3 destination"
        }

        if (flow.dstPort !in setOf(53, 80, 123, 443, 853) && flow.dstPort > 0) {
            reasons += "unusual destination port ${flow.dstPort}"
        }

        return reasons.takeIf { it.isNotEmpty() }?.joinToString(" • ")
    }

    private fun dangerScore(flow: FlowRecord, siteHint: String?): Double {
        var score = 0.0
        val host = siteHint?.lowercase().orEmpty()
        score += (flow.destinationInsight.lookalikeScore * 0.45).coerceIn(0.0, 0.45)
        if (flow.destinationInsight.punycodePresent) {
            score += 0.22
        }
        if (flow.destinationInsight.suspiciousTld) {
            score += 0.18
        }
        if (flow.dstPort == 80 && isBrowserLikeFlow(flow, siteHint)) {
            score += 0.45
        }
        if (host.endsWith(".badssl.com") || host == "badssl.com") {
            score += 0.32
        }
        if (host.contains("expired.badssl.com") || host.contains("self-signed.badssl.com") || host.contains("wrong.host.badssl.com")) {
            score += 0.24
        }
        if (host.contains("http.badssl.com") || host.contains("neverssl.com")) {
            score += 0.28
        }
        if (host.contains("xn--") || host.endsWith(".zip") || host.endsWith(".mov")) {
            score += 0.35
        }
        if (host.contains("login-") || host.contains("verify-") || host.contains("secure-") || host.contains("update-") || host.contains("password-") || host.contains("billing-")) {
            score += 0.25
        }
        if (host.contains("doubleclick") || host.contains("googlesyndication") || host.contains("tracking") || host.contains("telemetry")) {
            score += 0.18
        }
        if (!flow.protocolEvidence.tlsLeafSubject.isNullOrBlank()) {
            score += 0.08
        }
        if (flow.protocolEvidence.http3Detected) {
            score += 0.05
        }
        if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) {
            score += 0.12
        }
        if (flow.dstPort !in setOf(53, 80, 123, 443, 853) && flow.dstPort > 0) {
            score += 0.12
        }
        return score.coerceIn(0.0, 1.0)
    }

    private fun minimumSeverityForDanger(
        flow: FlowRecord,
        siteHint: String?,
        reputationScore: Double
    ): AlertSeverity? {
        val host = siteHint?.lowercase().orEmpty()
        return when {
            flow.destinationInsight.lookalikeScore >= 0.80 -> AlertSeverity.HIGH
            flow.destinationInsight.lookalikeScore >= 0.55 -> AlertSeverity.MEDIUM
            host.contains("expired.badssl.com") || host.contains("self-signed.badssl.com") || host.contains("wrong.host.badssl.com") -> AlertSeverity.HIGH
            host.endsWith(".badssl.com") || host == "badssl.com" -> AlertSeverity.MEDIUM
            host.contains("http.badssl.com") || host.contains("neverssl.com") -> AlertSeverity.MEDIUM
            flow.dstPort == 80 && isBrowserLikeFlow(flow, siteHint) -> AlertSeverity.MEDIUM
            reputationScore >= 0.70 -> AlertSeverity.HIGH
            reputationScore >= 0.30 -> AlertSeverity.MEDIUM
            else -> null
        }
    }

    private fun buildFlowExportPreview(config: com.manta.app.core.settings.EndpointConfig): JSONObject {
        val salt = settingsStore.getDeviceSalt()
        val sampleFlow = FlowRecord(
            id = "preview-flow",
            timestampStartMillis = 1_700_000_000_000L,
            timestampEndMillis = 1_700_000_001_500L,
            appId = "com.android.chrome",
            ipVersion = 4,
            protocol = FlowProtocol.TCP,
            srcIp = "10.0.0.2",
            srcPort = 40123,
            dstIp = "93.184.216.34",
            dstPort = 443,
            bytesOut = 2048,
            bytesIn = 8192,
            packetsOut = 4,
            packetsIn = 7,
            durationMillis = 1500,
            destinationHash = CryptoUtils.sha256("93.184.216.34:443"),
            destinationNovelty = 0.42,
            protocolEvidence = ProtocolEvidence(
                tlsSni = "www.example.com",
                tlsAlpn = "h2",
                tlsVersion = "TLS1.3",
                tlsJa3Like = "sha256(ja3)",
                quicDetected = false
            ),
            destinationInsight = DestinationInsight(
                normalizedHost = "example.com",
                registrableDomain = "example.com",
                confidence = 0.35
            )
        )
        return JSONObject(
            sampleFlow.toJson(
                deviceIdPseudo = pseudonymousDeviceId(),
                privacyMode = config.privacyMode,
                deviceSalt = salt,
                customPrivacy = config.customPrivacy
            )
        )
    }

    private fun buildAlertExportPreview(config: com.manta.app.core.settings.EndpointConfig): JSONObject {
        val exportedAppId = when (config.privacyMode) {
            PrivacyMode.OFF -> "com.android.chrome"
            PrivacyMode.LOW -> "com.android.chrome"
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(app_id)"
            PrivacyMode.CUSTOM -> if (config.customPrivacy.includeAppId) "com.android.chrome" else "sha256(app_id)"
        }
        return JSONObject()
            .put("event_type", "mobile_alert")
            .put("event_version", "1.0")
            .put("device_id_pseudo", pseudonymousDeviceId())
            .put("alert_id", "preview-alert")
            .put("app_id", exportedAppId)
            .put("anomaly_score", 0.73)
            .put("base_anomaly_score", 0.69)
            .put("context_score", 0.18)
            .put("response_score", 0.73)
            .put("severity", "MEDIUM")
            .put("top_features", JSONArray(listOf("novelty", "destination_diversity")))
            .put("explanation", "Preview export payload")
            .put("source_model", config.detectionModel)
            .put("site_hint", exportSiteHint("www.example.com", config.privacyMode, config.customPrivacy))
            .put(
                "window_features",
                JSONObject()
                    .put("flow_count", 12)
                    .put("bytes_out", 2048)
                    .put("bytes_in", 8192)
                    .put("mean_packet_size", 930.0)
                    .put("outbound_ratio", 0.20)
                    .put("burstiness", 0.35)
                    .put("novelty_score", 0.42)
                    .put("connection_frequency_delta", 0.64)
                    .put("bytes_per_flow", 853.3)
                    .put("destination_diversity", 0.33)
                    .put("activity_ratio", 0.18)
                    .put("periodic_beacon_score", 0.04)
                    .put("byte_rate", 170.6)
                    .put("packet_rate", 4.2)
                    .put("mean_duration_ms", 482.0)
                    .put("duration_jitter", 141.0)
                    .put("port_diversity", 0.25)
                    .put("protocol_diversity", 0.08)
                    .put("packet_imbalance", 0.12)
                    .put("small_flow_ratio", 0.16)
                    .put("high_port_ratio", 0.75)
                    .put("hour_of_day", 14)
                    .put("is_weekend", false)
                    .put("data_quality_score", 0.96)
                    .put("ttl_gap", 0.08)
                    .put("ttl_metrics_present", 1.0)
                    .put("syn_rate_total", 0.12)
                    .put("rst_rate_total", 0.02)
                    .put("ack_rate_total", 0.84)
                    .put("fin_rate_total", 0.03)
                    .put("psh_rate_total", 0.09)
                    .put("fragment_rate_total", 0.0)
                    .put("tcp_window_mean", 4096.0)
                    .put("ack_delay_mean", 18.0)
                    .put("inter_packet_gap_mean", 33.0)
                    .put("payload_mean", 620.0)
                    .put("load_mean", 170.6)
                    .put("transport_metrics_present", 1.0)
            )
            .put("confidence", 0.68)
            .put("uncertainty", 0.32)
            .put("triage_status", "OPEN")
            .put("triage_note", "")
            .put("timestamp", 1_700_000_001_500L)
    }

    private fun applyAblations(
        window: FeatureWindow,
        config: com.manta.app.core.settings.EndpointConfig
    ): FeatureWindow {
        return window.copy(
            flowCount = if (config.ablateVolumeFeatures) 0 else window.flowCount,
            totalBytesOut = if (config.ablateVolumeFeatures) 0 else window.totalBytesOut,
            totalBytesIn = if (config.ablateVolumeFeatures) 0 else window.totalBytesIn,
            meanPacketSize = if (config.ablateVolumeFeatures) 0.0 else window.meanPacketSize,
            bytesPerFlow = if (config.ablateVolumeFeatures) 0.0 else window.bytesPerFlow,
            byteRate = if (config.ablateVolumeFeatures) 0.0 else window.byteRate,
            packetRate = if (config.ablateVolumeFeatures) 0.0 else window.packetRate,
            burstiness = if (config.ablateTimingFeatures) 0.0 else window.burstiness,
            connectionFrequencyDelta = if (config.ablateTimingFeatures) 0.0 else window.connectionFrequencyDelta,
            activityRatio = if (config.ablateTimingFeatures) 0.0 else window.activityRatio,
            meanDurationMillis = if (config.ablateTimingFeatures) 0.0 else window.meanDurationMillis,
            durationJitter = if (config.ablateTimingFeatures) 0.0 else window.durationJitter,
            periodicBeaconScore = if (config.ablateTimingFeatures) 0.0 else window.periodicBeaconScore,
            noveltyScore = if (config.ablateDestinationFeatures) 0.0 else window.noveltyScore,
            destinationDiversity = if (config.ablateDestinationFeatures) 0.0 else window.destinationDiversity,
            portDiversity = if (config.ablateDestinationFeatures) 0.0 else window.portDiversity,
            protocolDiversity = if (config.ablateDestinationFeatures) 0.0 else window.protocolDiversity,
            packetImbalance = if (config.ablateDestinationFeatures) 0.0 else window.packetImbalance,
            smallFlowRatio = if (config.ablateDestinationFeatures) 0.0 else window.smallFlowRatio,
            highPortRatio = if (config.ablateDestinationFeatures) 0.0 else window.highPortRatio
        )
    }

    private fun adjustedThresholdProfile(base: ThresholdProfile, profile: AppProfile, testModeEnabled: Boolean): ThresholdProfile {
        val profiled = when (profile) {
            AppProfile.DEFAULT -> base
            AppProfile.TRUSTED -> ThresholdProfile(base.low + 0.08, base.medium + 0.10, base.high + 0.12).normalize()
            AppProfile.HIGH_CHURN -> ThresholdProfile(base.low + 0.05, base.medium + 0.07, base.high + 0.08).normalize()
            AppProfile.BROWSER -> ThresholdProfile(base.low + 0.05, base.medium + 0.06, base.high + 0.08).normalize()
            AppProfile.SYSTEM -> ThresholdProfile(base.low + 0.10, base.medium + 0.12, base.high + 0.15).normalize()
        }
        return if (testModeEnabled) {
            ThresholdProfile(
                low = (profiled.low - 0.10).coerceIn(0.02, 1.0),
                medium = (profiled.medium - 0.10).coerceIn(0.15, 1.0),
                high = (profiled.high - 0.10).coerceIn(0.25, 1.0)
            ).normalize()
        } else {
            profiled
        }
    }

    private fun effectiveAppProfile(base: AppProfile, flow: FlowRecord, siteHint: String?): AppProfile {
        if (base != AppProfile.DEFAULT) {
            return base
        }
        return if (isBrowserLikeFlow(flow = flow, siteHint = siteHint)) {
            AppProfile.BROWSER
        } else {
            base
        }
    }

    private fun shouldSuppressForProfile(
        profile: AppProfile,
        alert: com.manta.app.domain.detection.AnomalyScoreResult,
        siteHint: String?,
        dangerSummary: String?,
        flow: FlowRecord
    ): Boolean {
        val onlyBurstLike = alert.topFeatures.all { it in setOf("burstiness", "conn_freq_delta", "flow_count", "activity_ratio") }
        return when (profile) {
            AppProfile.BROWSER ->
                onlyBurstLike &&
                    siteHint.isNullOrBlank() &&
                    dangerSummary.isNullOrBlank() &&
                    flow.dstPort in setOf(80, 443, 853)
            AppProfile.TRUSTED, AppProfile.HIGH_CHURN, AppProfile.SYSTEM ->
                onlyBurstLike && dangerSummary.isNullOrBlank()
            AppProfile.DEFAULT -> false
        }
    }

    private fun isBrowserLikeFlow(flow: FlowRecord, siteHint: String?): Boolean {
        return isBrowserApp(flow.appId) ||
            (
                flow.appId.startsWith("uid:") &&
                    flow.dstPort in setOf(80, 443, 8080, 8443, 853)
            ) ||
            (
                !siteHint.isNullOrBlank() &&
                    flow.dstPort in setOf(80, 443, 8080, 8443, 853)
            )
    }

    private fun appendSuppressionReason(existing: String?, next: String): String {
        return if (existing.isNullOrBlank()) next else "$existing,$next"
    }

    private fun csvCell(value: Any?): String {
        val raw = value?.toString() ?: ""
        if (raw.none { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            return raw
        }
        return "\"${raw.replace("\"", "\"\"")}\""
    }

    private fun exportAppId(appId: String, privacyMode: PrivacyMode, customPrivacy: com.manta.app.core.settings.CustomPrivacyOptions): String {
        return when (privacyMode) {
            PrivacyMode.OFF -> appId
            PrivacyMode.LOW -> appId
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> CryptoUtils.sha256("${settingsStore.getDeviceSalt()}:$appId")
            PrivacyMode.CUSTOM -> if (customPrivacy.includeAppId) appId else CryptoUtils.sha256("${settingsStore.getDeviceSalt()}:$appId")
        }
    }

    private fun exportFlowIp(
        ipAddress: String,
        privacyMode: PrivacyMode,
        customPrivacy: com.manta.app.core.settings.CustomPrivacyOptions,
        salt: String
    ): String {
        return when (privacyMode) {
            PrivacyMode.OFF -> ipAddress
            PrivacyMode.LOW, PrivacyMode.MEDIUM, PrivacyMode.STRICT -> CryptoUtils.sha256("$salt:$ipAddress")
            PrivacyMode.CUSTOM -> if (customPrivacy.includeIpAddresses) ipAddress else CryptoUtils.sha256("$salt:$ipAddress")
        }
    }

    private fun exportFlowPort(
        port: Int,
        privacyMode: PrivacyMode,
        customPrivacy: com.manta.app.core.settings.CustomPrivacyOptions
    ): Int {
        if (privacyMode != PrivacyMode.CUSTOM || customPrivacy.includeExactPorts) {
            return port
        }
        return when {
            port in setOf(53, 80, 123, 443, 853) -> port
            port in 1..1023 -> 1024
            port in 1024..49151 -> 49152
            else -> 65535
        }
    }

    private fun exportDestinationKey(
        flow: RawFlowEntity,
        privacyMode: PrivacyMode,
        customPrivacy: com.manta.app.core.settings.CustomPrivacyOptions,
        salt: String
    ): String {
        val siteHint = flow.siteHint?.takeIf { it.isNotBlank() }
        val exportedPort = exportFlowPort(flow.dstPort, privacyMode, customPrivacy)
        return when (privacyMode) {
            PrivacyMode.OFF -> "${siteHint ?: flow.dstIp}:$exportedPort"
            PrivacyMode.LOW -> "${siteHint ?: flow.dstIp}:$exportedPort"
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> flow.destinationHash
            PrivacyMode.CUSTOM -> when {
                customPrivacy.includeSiteHint && siteHint != null -> "$siteHint:$exportedPort"
                customPrivacy.includeIpAddresses -> "${flow.dstIp}:$exportedPort"
                else -> CryptoUtils.sha256("$salt:${siteHint ?: flow.dstIp}:$exportedPort")
            }
        }
    }

    private fun exportSiteHint(
        siteHint: String?,
        privacyMode: PrivacyMode,
        customPrivacy: com.manta.app.core.settings.CustomPrivacyOptions
    ): String? {
        return when (privacyMode) {
            PrivacyMode.OFF, PrivacyMode.LOW -> siteHint
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> null
            PrivacyMode.CUSTOM -> siteHint.takeIf { customPrivacy.includeSiteHint }
        }
    }
}
