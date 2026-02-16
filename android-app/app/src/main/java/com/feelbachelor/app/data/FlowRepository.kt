package com.feelbachelor.app.data

import android.content.Context
import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.FeatureWindow
import com.feelbachelor.app.core.model.FlowProtocol
import com.feelbachelor.app.core.model.FlowRecord
import com.feelbachelor.app.core.net.NetworkEventClient
import com.feelbachelor.app.core.security.CryptoUtils
import com.feelbachelor.app.core.settings.SecureSettingsStore
import com.feelbachelor.app.data.db.AnomalyScoreEntity
import com.feelbachelor.app.data.db.AppDatabase
import com.feelbachelor.app.data.db.ExportQueueEntity
import com.feelbachelor.app.data.db.FeatureWindowEntity
import com.feelbachelor.app.data.db.RawFlowEntity
import com.feelbachelor.app.domain.detection.AnomalyEngine
import com.feelbachelor.app.domain.flow.FeatureWindowBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    suspend fun persistFlow(flow: FlowRecord): AnomalyAlert? = withContext(Dispatchers.IO) {
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
        val severity = when {
            anomaly.score >= 0.85 -> AlertSeverity.HIGH
            anomaly.score >= 0.6 -> AlertSeverity.MEDIUM
            else -> AlertSeverity.LOW
        }

        val alert = AnomalyAlert(
            id = UUID.randomUUID().toString(),
            featureWindowId = window.id,
            appId = flow.appId,
            anomalyScore = anomaly.score,
            severity = severity,
            topFeatures = anomaly.topFeatures,
            createdAtMillis = flow.timestampEndMillis
        )

        dao.insertAnomalyScore(
            AnomalyScoreEntity(
                id = alert.id,
                featureWindowId = alert.featureWindowId,
                appId = alert.appId,
                score = alert.anomalyScore,
                severity = alert.severity.name,
                topFeaturesCsv = alert.topFeatures.joinToString(","),
                createdAtMillis = alert.createdAtMillis
            )
        )

        if (alert.severity != AlertSeverity.LOW) {
            enqueueAlertForExport(alert)
        }

        alert
    }

    suspend fun latestAlerts(limit: Int = 20): List<AnomalyAlert> = withContext(Dispatchers.IO) {
        dao.getLatestScores(limit).map {
            AnomalyAlert(
                id = it.id,
                featureWindowId = it.featureWindowId,
                appId = it.appId,
                anomalyScore = it.score,
                severity = AlertSeverity.valueOf(it.severity),
                topFeatures = it.topFeaturesCsv.split(',').filter { item -> item.isNotBlank() },
                createdAtMillis = it.createdAtMillis
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
            val result = client.sendEvent(entry.payload)
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

    suspend fun runRetentionCleanup(retentionDays: Int = 7): Int = withContext(Dispatchers.IO) {
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
        val payload = """
            {
              "event_type": "mobile_alert",
              "event_version": "1.0",
              "device_id_pseudo": "${pseudonymousDeviceId()}",
              "alert_id": "${alert.id}",
              "app_id": "${alert.appId}",
              "anomaly_score": ${alert.anomalyScore},
              "severity": "${alert.severity.name}",
              "top_features": "${alert.topFeatures.joinToString(",")}",
              "timestamp": ${alert.createdAtMillis}
            }
        """.trimIndent()

        dao.enqueueExport(
            ExportQueueEntity(
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
}
