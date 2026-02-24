package com.feelbachelor.app.data

import android.content.Context
import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.FeatureWindow
import com.feelbachelor.app.core.model.FlowProtocol
import com.feelbachelor.app.core.model.FlowRecord
import com.feelbachelor.app.core.model.TriageStatus
import com.feelbachelor.app.core.model.ThresholdProfile
import com.feelbachelor.app.core.net.NetworkEventClient
import com.feelbachelor.app.core.security.CryptoUtils
import com.feelbachelor.app.core.settings.SecureSettingsStore
import com.feelbachelor.app.data.db.AnomalyScoreEntity
import com.feelbachelor.app.data.db.AppDatabase
import com.feelbachelor.app.data.db.ExportQueueEntity
import com.feelbachelor.app.data.db.FeatureWindowEntity
import com.feelbachelor.app.data.db.RawFlowEntity
import com.feelbachelor.app.domain.detection.AnomalyEngine
import com.feelbachelor.app.domain.detection.ConceptDriftMonitor
import com.feelbachelor.app.domain.detection.DataQualityMonitor
import com.feelbachelor.app.domain.detection.ExplanationFormatter
import com.feelbachelor.app.domain.detection.FalsePositiveBudgetManager
import com.feelbachelor.app.domain.detection.PeriodicBeaconDetector
import com.feelbachelor.app.domain.detection.RuntimeGuardrailManager
import com.feelbachelor.app.domain.detection.SeverityStabilityGate
import com.feelbachelor.app.domain.detection.ThresholdResolver
import com.feelbachelor.app.domain.flow.FeatureWindowBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.math.min
import kotlin.system.measureNanoTime

private const val WINDOW_MILLIS = 60_000L
private const val ALERT_CORRELATION_WINDOW_MILLIS = 10 * 60_000L
private const val FEEDBACK_ADJUST_STEP_FP = 0.02
private const val FEEDBACK_ADJUST_STEP_TRUE_POSITIVE = 0.01

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
    private val runtimeGuardrailManager: RuntimeGuardrailManager
) {
    private val appContext = context.applicationContext
    private val db = AppDatabase.getInstance(context)
    private val dao = db.flowDao()

    suspend fun persistFlow(flow: FlowRecord): AnomalyAlert = withContext(Dispatchers.IO) {
        dao.insertRawFlow(
            RawFlowEntity(
                id = flow.id,
                timestampStartMillis = flow.timestampStartMillis,
                timestampEndMillis = flow.timestampEndMillis,
                appId = flow.appId,
                protocol = flow.protocol.name,
                srcIp = flow.srcIp,
                srcPort = flow.srcPort,
                dstIp = flow.dstIp,
                dstPort = flow.dstPort,
                bytesOut = flow.bytesOut,
                bytesIn = flow.bytesIn,
                packetsOut = flow.packetsOut,
                packetsIn = flow.packetsIn,
                durationMillis = flow.durationMillis,
                destinationHash = flow.destinationHash,
                destinationNovelty = flow.destinationNovelty
            )
        )

        enqueueFlowForExport(flow)
        val quality = dataQualityMonitor.evaluate(flow)
        val pendingExportQueue = dao.countPendingExports()
        val guardrail = runtimeGuardrailManager.decide(
            context = appContext,
            pendingExportQueue = pendingExportQueue
        )
        val beaconScore = periodicBeaconDetector.observe(flow)

        val windowStart = flow.timestampEndMillis - WINDOW_MILLIS
        val recent = dao.getRecentFlowsByApp(flow.appId, windowStart).map { entity ->
            FlowRecord(
                id = entity.id,
                timestampStartMillis = entity.timestampStartMillis,
                timestampEndMillis = entity.timestampEndMillis,
                appId = entity.appId,
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
                destinationNovelty = entity.destinationNovelty
            )
        }

        val config = settingsStore.readConfig()
        val activeModel = config.detectionModel
        val shadowModel = config.shadowModel
        val builtWindow = featureWindowBuilder.build(
            appId = flow.appId,
            flows = recent,
            windowStartMillis = windowStart,
            windowEndMillis = flow.timestampEndMillis,
            periodicBeaconScore = beaconScore,
            dataQualityScore = quality.score,
            sampledByGuardrail = guardrail.sampled,
            processingCostMillis = 0.0
        )
        var anomaly = anomalyEngine.score(window = builtWindow, configuredMode = activeModel)
        var shadowScore: Double? = null
        var driftScore = 0.0
        val dataQualityWarnings = quality.warnings
        var processingCostMillis: Double

        val processingNanos = measureNanoTime {
            if (!guardrail.processDetection) {
                anomaly = anomalyEngine.score(window = builtWindow, configuredMode = AnomalyEngine.MODE_STATISTICAL)
                anomaly = anomaly.copy(
                    score = anomaly.score * 0.35,
                    source = "${activeModel}-sampled",
                    diagnostics = anomaly.diagnostics + mapOf(
                        "sample_factor" to guardrail.sampleFactor.toDouble()
                    )
                )
            } else {
                anomaly = anomalyEngine.score(window = builtWindow, configuredMode = activeModel)
                if (!shadowModel.isNullOrBlank() && shadowModel != activeModel) {
                    shadowScore = anomalyEngine.score(window = builtWindow, configuredMode = shadowModel).score
                }
            }
            val drift = conceptDriftMonitor.evaluate(builtWindow)
            driftScore = drift.score

            val adjustedScore = (
                anomaly.score +
                    (0.15 * beaconScore) +
                    (0.10 * driftScore) -
                    (0.10 * (1.0 - quality.score))
                ).coerceIn(0.0, 1.0)
            val mergedContributions = anomaly.featureContributions.toMutableMap()
            if (beaconScore >= 0.4) {
                mergedContributions["periodic_beacon"] = beaconScore
            }
            if (driftScore >= 0.2) {
                mergedContributions["concept_drift"] = driftScore
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
                diagnostics = anomaly.diagnostics + mapOf(
                    "periodic_beacon_score" to beaconScore,
                    "drift_score" to driftScore,
                    "data_quality_score" to quality.score
                )
            )
        }
        processingCostMillis = processingNanos / 1_000_000.0
        runtimeGuardrailManager.recordProcessingCost(processingCostMillis)
        val window = builtWindow.copy(processingCostMillis = processingCostMillis)
        saveFeatureWindow(window)
        val thresholdProfile = settingsStore.getThresholdForApp(flow.appId)
        val proposedSeverity = ThresholdResolver.resolveSeverity(anomaly.score, thresholdProfile)
        val stabilizedSeverity = severityStabilityGate.adjust(flow.appId, proposedSeverity)
        val falsePositives = dao.countFalsePositivesForAppSince(
            appId = flow.appId,
            sinceMillis = flow.timestampEndMillis - 24L * 60L * 60L * 1000L
        )
        val budgetDecision = falsePositiveBudgetManager.apply(
            proposed = stabilizedSeverity,
            falsePositivesInWindow = falsePositives,
            budgetPerAppDay = config.falsePositiveBudgetPerAppDay
        )
        val severity = budgetDecision.severity
        val suppressionReason = budgetDecision.suppressionReason ?: guardrail.reason
        val explanation = ExplanationFormatter.summarize(
            topFeatures = anomaly.topFeatures,
            contributions = anomaly.featureContributions
        ) + if (suppressionReason != null) " Suppression: $suppressionReason." else ""

        val correlationKey = computeCorrelationKey(
            appId = flow.appId,
            sourceModel = anomaly.source,
            topFeatures = anomaly.topFeatures
        )
        val correlated = dao.findCorrelatedAlert(
            appId = flow.appId,
            correlationKey = correlationKey,
            sinceMillis = flow.timestampEndMillis - ALERT_CORRELATION_WINDOW_MILLIS
        )

        val alert = if (correlated != null) {
            val mergedSeverity = maxSeverity(
                AlertSeverity.valueOf(correlated.severity),
                severity
            )
            val updatedCount = (correlated.occurrenceCount + 1).coerceAtLeast(2)
            dao.updateCorrelatedAlert(
                alertId = correlated.id,
                score = maxOf(correlated.score, anomaly.score),
                severity = mergedSeverity.name,
                topFeaturesCsv = anomaly.topFeatures.joinToString(","),
                explanation = explanation,
                sourceModel = anomaly.source,
                triageStatus = correlated.triageStatus,
                triageNote = correlated.triageNote,
                triageUpdatedAtMillis = flow.timestampEndMillis,
                confidence = anomaly.confidence,
                uncertainty = anomaly.uncertainty,
                driftScore = maxOf(correlated.driftScore, driftScore),
                occurrenceCount = updatedCount,
                lastSeenMillis = flow.timestampEndMillis,
                shadowModel = shadowModel,
                shadowScore = shadowScore,
                suppressionReason = suppressionReason,
                dataQualityWarningsCsv = dataQualityWarnings.joinToString(","),
                beaconScore = maxOf(correlated.beaconScore, beaconScore)
            )
            mapEntityToAlert(
                dao.getScoreById(correlated.id) ?: correlated.copy(
                    score = maxOf(correlated.score, anomaly.score),
                    severity = mergedSeverity.name,
                    topFeaturesCsv = anomaly.topFeatures.joinToString(","),
                    explanation = explanation,
                    sourceModel = anomaly.source,
                    triageUpdatedAtMillis = flow.timestampEndMillis,
                    confidence = anomaly.confidence,
                    uncertainty = anomaly.uncertainty,
                    driftScore = maxOf(correlated.driftScore, driftScore),
                    occurrenceCount = updatedCount,
                    lastSeenMillis = flow.timestampEndMillis,
                    shadowModel = shadowModel,
                    shadowScore = shadowScore,
                    suppressionReason = suppressionReason,
                    dataQualityWarningsCsv = dataQualityWarnings.joinToString(","),
                    beaconScore = maxOf(correlated.beaconScore, beaconScore)
                )
            )
        } else {
            val newAlert = AnomalyAlert(
                id = UUID.randomUUID().toString(),
                featureWindowId = window.id,
                appId = flow.appId,
                anomalyScore = anomaly.score,
                severity = severity,
                topFeatures = anomaly.topFeatures,
                explanation = explanation,
                sourceModel = anomaly.source,
                triageStatus = TriageStatus.OPEN,
                triageNote = "",
                createdAtMillis = flow.timestampEndMillis,
                triageUpdatedAtMillis = flow.timestampEndMillis,
                confidence = anomaly.confidence,
                uncertainty = anomaly.uncertainty,
                driftScore = driftScore,
                occurrenceCount = 1,
                firstSeenMillis = flow.timestampEndMillis,
                lastSeenMillis = flow.timestampEndMillis,
                correlationKey = correlationKey,
                shadowModel = shadowModel,
                shadowScore = shadowScore,
                suppressionReason = suppressionReason,
                dataQualityWarnings = dataQualityWarnings,
                beaconScore = beaconScore
            )

            dao.insertAnomalyScore(
                AnomalyScoreEntity(
                    id = newAlert.id,
                    featureWindowId = newAlert.featureWindowId,
                    appId = newAlert.appId,
                    score = newAlert.anomalyScore,
                    severity = newAlert.severity.name,
                    topFeaturesCsv = newAlert.topFeatures.joinToString(","),
                    explanation = newAlert.explanation,
                    sourceModel = newAlert.sourceModel,
                    triageStatus = newAlert.triageStatus.name,
                    triageNote = newAlert.triageNote,
                    createdAtMillis = newAlert.createdAtMillis,
                    triageUpdatedAtMillis = newAlert.triageUpdatedAtMillis,
                    confidence = newAlert.confidence,
                    uncertainty = newAlert.uncertainty,
                    driftScore = newAlert.driftScore,
                    occurrenceCount = newAlert.occurrenceCount,
                    firstSeenMillis = newAlert.firstSeenMillis,
                    lastSeenMillis = newAlert.lastSeenMillis,
                    correlationKey = newAlert.correlationKey,
                    shadowModel = newAlert.shadowModel,
                    shadowScore = newAlert.shadowScore,
                    suppressionReason = newAlert.suppressionReason,
                    dataQualityWarningsCsv = newAlert.dataQualityWarnings.joinToString(","),
                    beaconScore = newAlert.beaconScore
                )
            )
            newAlert
        }

        if (alert.severity != AlertSeverity.LOW) {
            enqueueAlertForExport(alert)
        }

        alert
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
        }
        if (updatedEntity != null && settingsStore.readConfig().exportEnabled) {
            val payload = JSONObject()
                .put("event_type", "mobile_alert")
                .put("event_version", "1.0")
                .put("device_id_pseudo", pseudonymousDeviceId())
                .put("alert_id", updatedEntity.id)
                .put("app_id", updatedEntity.appId)
                .put("anomaly_score", updatedEntity.score)
                .put("severity", updatedEntity.severity)
                .put("top_features", updatedEntity.topFeaturesCsv.split(',').filter { it.isNotBlank() })
                .put("explanation", updatedEntity.explanation)
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
                .put("data_quality_warnings", updatedEntity.dataQualityWarningsCsv.split(',').filter { it.isNotBlank() })
                .put("beacon_score", updatedEntity.beaconScore)
                .put("triage_status", status.name)
                .put("triage_note", note)
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

    suspend fun processExportQueue(client: NetworkEventClient, batchSize: Int = 50): Int = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val pending = dao.getPendingExports(now, batchSize)
        if (pending.isEmpty()) {
            return@withContext 0
        }

        var sent = 0
        pending.forEach { entry ->
            val result = client.sendEvent(eventType = entry.eventType, payload = entry.payload)
            if (result.isSuccess) {
                dao.markExported(entry.queueId, now)
                sent += 1
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
        sent
    }

    suspend fun syncRemotePolicy(client: NetworkEventClient): Result<Unit> = withContext(Dispatchers.IO) {
        val result = client.fetchRemotePolicy(pseudonymousDeviceId())
        if (result.isFailure) {
            return@withContext Result.failure(result.exceptionOrNull() ?: IllegalStateException("Unknown policy sync error"))
        }

        val policy = result.getOrThrow()
        settingsStore.applyRemotePolicy(policy)
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

    suspend fun exportLatestFlowsCsv(maxRows: Int = 20_000): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val safeLimit = maxRows.coerceIn(1, 100_000)
            val flows = dao.getLatestFlows(safeLimit).asReversed()
            val exportRoot = File(appContext.getExternalFilesDir(null), "exports")
            if (!exportRoot.exists()) {
                exportRoot.mkdirs()
            }

            val outputFile = File(exportRoot, "flows-${System.currentTimeMillis()}.csv")
            val salt = settingsStore.getDeviceSalt()

            outputFile.bufferedWriter(Charsets.UTF_8).use { writer ->
                writer.appendLine(
                    "timestamp_start_ms,timestamp_end_ms,app_id_pseudo,protocol,src_ip_hash,src_port," +
                        "dst_ip_hash,dst_port,dst_host_hash,bytes_out,bytes_in,packets_out,packets_in,duration_ms,dst_novelty"
                )

                flows.forEach { flow ->
                    val appPseudo = CryptoUtils.sha256("$salt:${flow.appId}")
                    val srcIpHash = CryptoUtils.sha256("$salt:${flow.srcIp}")
                    val dstIpHash = CryptoUtils.sha256("$salt:${flow.dstIp}")

                    writer.appendLine(
                        listOf(
                            flow.timestampStartMillis,
                            flow.timestampEndMillis,
                            appPseudo,
                            flow.protocol,
                            srcIpHash,
                            flow.srcPort,
                            dstIpHash,
                            flow.dstPort,
                            flow.destinationHash,
                            flow.bytesOut,
                            flow.bytesIn,
                            flow.packetsOut,
                            flow.packetsIn,
                            flow.durationMillis,
                            flow.destinationNovelty
                        ).joinToString(",")
                    )
                }
            }

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
            val alertsPayload = JSONObject()
                .put("generated_at", timestamp)
                .put("alerts", dao.getLatestScores(25_000).map { entity ->
                    JSONObject()
                        .put("id", entity.id)
                        .put("app_id", entity.appId)
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
                        .put("top_features", entity.topFeaturesCsv.split(',').filter { it.isNotBlank() })
                })
            alertsFile.writeText(alertsPayload.toString(2), Charsets.UTF_8)

            val policyFile = File(bundleDir, "policy.json")
            val config = settingsStore.readConfig()
            val policyPayload = JSONObject()
                .put("backend_url", config.backendUrl)
                .put("export_enabled", config.exportEnabled)
                .put("detection_model", config.detectionModel)
                .put("shadow_model", config.shadowModel)
                .put("policy_version", config.policyVersion)
                .put("retention_days", config.retentionDays)
                .put("default_thresholds", JSONObject().put("medium", config.mediumThreshold).put("high", config.highThreshold))
                .put("false_positive_budget_per_app_day", config.falsePositiveBudgetPerAppDay)
                .put("drift_high_threshold", config.driftHighThreshold)
            policyFile.writeText(policyPayload.toString(2), Charsets.UTF_8)

            val diagnosticsFile = File(bundleDir, "diagnostics.json")
            val diagPayload = JSONObject()
                .put("generated_at", timestamp)
                .put("data_quality_counters", JSONObject(dataQualityMonitor.snapshotCounters()))
                .put("guardrail", JSONObject(runtimeGuardrailManager.diagnostics()))
            diagnosticsFile.writeText(diagPayload.toString(2), Charsets.UTF_8)

            val manifestFile = File(bundleDir, "manifest.json")
            val manifest = JSONObject()
                .put("generated_at", timestamp)
                .put("bundle_version", "1.0")
                .put("device_id_pseudo", pseudonymousDeviceId())
                .put("contents", listOf("flows.csv", "alerts.json", "policy.json", "diagnostics.json"))
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
                medium = (current.medium + FEEDBACK_ADJUST_STEP_FP).coerceAtMost(0.95),
                high = (current.high + FEEDBACK_ADJUST_STEP_FP).coerceAtMost(0.99)
            ).normalize()

            TriageStatus.RESOLVED -> ThresholdProfile(
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
                periodicBeaconScore = window.periodicBeaconScore,
                hourOfDay = window.hourOfDay,
                dayOfWeek = window.dayOfWeek,
                isWeekend = window.isWeekend,
                dataQualityScore = window.dataQualityScore,
                sampledByGuardrail = window.sampledByGuardrail,
                processingCostMillis = window.processingCostMillis
            )
        )
    }

    private suspend fun enqueueFlowForExport(flow: FlowRecord) {
        if (!settingsStore.readConfig().exportEnabled) {
            return
        }
        val payload = flow.toJson(
            deviceIdPseudo = pseudonymousDeviceId(),
            anomalyScore = null,
            explainTopFeatures = emptyList()
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

    private suspend fun enqueueAlertForExport(alert: AnomalyAlert) {
        if (!settingsStore.readConfig().exportEnabled) {
            return
        }

        val payload = JSONObject()
            .put("event_type", "mobile_alert")
            .put("event_version", "1.0")
            .put("device_id_pseudo", pseudonymousDeviceId())
            .put("alert_id", alert.id)
            .put("app_id", alert.appId)
            .put("anomaly_score", alert.anomalyScore)
            .put("severity", alert.severity.name)
            .put("top_features", alert.topFeatures)
            .put("explanation", alert.explanation)
            .put("source_model", alert.sourceModel)
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
            .put("data_quality_warnings", alert.dataQualityWarnings)
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
        val salt = settingsStore.getDeviceSalt()
        return CryptoUtils.pseudonymousDeviceId(appContext, salt)
    }

    private fun mapEntityToAlert(entity: AnomalyScoreEntity): AnomalyAlert {
        return AnomalyAlert(
            id = entity.id,
            featureWindowId = entity.featureWindowId,
            appId = entity.appId,
            anomalyScore = entity.score,
            severity = AlertSeverity.valueOf(entity.severity),
            topFeatures = entity.topFeaturesCsv.split(',').filter { it.isNotBlank() },
            explanation = entity.explanation,
            sourceModel = entity.sourceModel,
            triageStatus = TriageStatus.valueOf(entity.triageStatus),
            triageNote = entity.triageNote,
            createdAtMillis = entity.createdAtMillis,
            triageUpdatedAtMillis = entity.triageUpdatedAtMillis,
            confidence = entity.confidence,
            uncertainty = entity.uncertainty,
            driftScore = entity.driftScore,
            occurrenceCount = entity.occurrenceCount,
            firstSeenMillis = entity.firstSeenMillis,
            lastSeenMillis = entity.lastSeenMillis,
            correlationKey = entity.correlationKey,
            shadowModel = entity.shadowModel,
            shadowScore = entity.shadowScore,
            suppressionReason = entity.suppressionReason,
            dataQualityWarnings = entity.dataQualityWarningsCsv.split(',').filter { it.isNotBlank() },
            beaconScore = entity.beaconScore
        )
    }
}
