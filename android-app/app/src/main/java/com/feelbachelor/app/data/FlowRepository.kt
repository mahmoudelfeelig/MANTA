package com.feelbachelor.app.data

import android.content.Context
import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.FeatureWindow
import com.feelbachelor.app.core.model.FlowProtocol
import com.feelbachelor.app.core.model.FlowRecord
import com.feelbachelor.app.core.model.TriageStatus
import com.feelbachelor.app.core.net.NetworkEventClient
import com.feelbachelor.app.core.security.CryptoUtils
import com.feelbachelor.app.core.settings.SecureSettingsStore
import com.feelbachelor.app.data.db.AnomalyScoreEntity
import com.feelbachelor.app.data.db.AppDatabase
import com.feelbachelor.app.data.db.ExportQueueEntity
import com.feelbachelor.app.data.db.FeatureWindowEntity
import com.feelbachelor.app.data.db.RawFlowEntity
import com.feelbachelor.app.domain.detection.AnomalyEngine
import com.feelbachelor.app.domain.detection.ExplanationFormatter
import com.feelbachelor.app.domain.detection.ThresholdResolver
import com.feelbachelor.app.domain.flow.FeatureWindowBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.UUID
import kotlin.math.min

private const val WINDOW_MILLIS = 60_000L

class FlowRepository(
    context: Context,
    private val settingsStore: SecureSettingsStore,
    private val featureWindowBuilder: FeatureWindowBuilder,
    private val anomalyEngine: AnomalyEngine
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

        val window = featureWindowBuilder.build(
            appId = flow.appId,
            flows = recent,
            windowStartMillis = windowStart,
            windowEndMillis = flow.timestampEndMillis
        )
        saveFeatureWindow(window)

        val anomaly = anomalyEngine.score(window)
        val thresholdProfile = settingsStore.getThresholdForApp(flow.appId)
        val severity = ThresholdResolver.resolveSeverity(anomaly.score, thresholdProfile)
        val explanation = ExplanationFormatter.summarize(
            topFeatures = anomaly.topFeatures,
            contributions = anomaly.featureContributions
        )

        val alert = AnomalyAlert(
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
            triageUpdatedAtMillis = flow.timestampEndMillis
        )

        dao.insertAnomalyScore(
            AnomalyScoreEntity(
                id = alert.id,
                featureWindowId = alert.featureWindowId,
                appId = alert.appId,
                score = alert.anomalyScore,
                severity = alert.severity.name,
                topFeaturesCsv = alert.topFeatures.joinToString(","),
                explanation = alert.explanation,
                sourceModel = alert.sourceModel,
                triageStatus = alert.triageStatus.name,
                triageNote = alert.triageNote,
                createdAtMillis = alert.createdAtMillis,
                triageUpdatedAtMillis = alert.triageUpdatedAtMillis
            )
        )

        if (alert.severity != AlertSeverity.LOW) {
            enqueueAlertForExport(alert)
        }

        alert
    }

    suspend fun latestAlerts(limit: Int = 20): List<AnomalyAlert> = withContext(Dispatchers.IO) {
        dao.getLatestScores(limit).map { mapEntityToAlert(it) }
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
                connectionFrequencyDelta = window.connectionFrequencyDelta
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
            triageUpdatedAtMillis = entity.triageUpdatedAtMillis
        )
    }
}
