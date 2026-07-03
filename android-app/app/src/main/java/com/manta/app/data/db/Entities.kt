package com.manta.app.data.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "raw_flow_records",
    indices = [
        Index(value = ["appId", "timestampStartMillis"]),
        Index(value = ["timestampStartMillis"]),
        Index(value = ["timestampEndMillis"])
    ]
)
data class RawFlowEntity(
    @PrimaryKey val id: String,
    val timestampStartMillis: Long,
    val timestampEndMillis: Long,
    val appId: String,
    val ipVersion: Int = 4,
    val protocol: String,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val bytesOut: Long,
    val bytesIn: Long,
    val packetsOut: Int,
    val packetsIn: Int,
    val durationMillis: Long,
    val destinationHash: String,
    val destinationNovelty: Double,
    val siteHint: String? = null,
    val ttlGap: Double = 0.0,
    val ttlMetricsPresent: Double = 0.0,
    val synRateTotal: Double = 0.0,
    val rstRateTotal: Double = 0.0,
    val ackRateTotal: Double = 0.0,
    val finRateTotal: Double = 0.0,
    val pshRateTotal: Double = 0.0,
    val fragmentRateTotal: Double = 0.0,
    val tcpWindowMean: Double = 0.0,
    val ackDelayMean: Double = 0.0,
    val interPacketGapMean: Double = 0.0,
    val payloadMean: Double = 0.0,
    val loadMean: Double = 0.0,
    val transportMetricsPresent: Double = 0.0,
    val protocolEvidenceJson: String = "{}",
    val destinationInsightJson: String = "{}"
)

@Entity(
    tableName = "feature_windows",
    indices = [
        Index(value = ["appId", "windowEndMillis"]),
        Index(value = ["windowEndMillis"])
    ]
)
data class FeatureWindowEntity(
    @PrimaryKey val id: String,
    val appId: String,
    val windowStartMillis: Long,
    val windowEndMillis: Long,
    val flowCount: Int,
    val totalBytesOut: Long,
    val totalBytesIn: Long,
    val meanPacketSize: Double,
    val outboundRatio: Double,
    val burstiness: Double,
    val noveltyScore: Double,
    val connectionFrequencyDelta: Double,
    val bytesPerFlow: Double = 0.0,
    val destinationDiversity: Double = 0.0,
    val activityRatio: Double = 0.0,
    val byteRate: Double = 0.0,
    val packetRate: Double = 0.0,
    val meanDurationMillis: Double = 0.0,
    val durationJitter: Double = 0.0,
    val portDiversity: Double = 0.0,
    val protocolDiversity: Double = 0.0,
    val packetImbalance: Double = 0.0,
    val smallFlowRatio: Double = 0.0,
    val highPortRatio: Double = 0.0,
    val periodicBeaconScore: Double = 0.0,
    val hourOfDay: Int = 0,
    val dayOfWeek: Int = 1,
    val isWeekend: Boolean = false,
    val dataQualityScore: Double = 1.0,
    val ttlGap: Double = 0.0,
    val ttlMetricsPresent: Double = 0.0,
    val synRateTotal: Double = 0.0,
    val rstRateTotal: Double = 0.0,
    val ackRateTotal: Double = 0.0,
    val finRateTotal: Double = 0.0,
    val pshRateTotal: Double = 0.0,
    val fragmentRateTotal: Double = 0.0,
    val tcpWindowMean: Double = 0.0,
    val ackDelayMean: Double = 0.0,
    val interPacketGapMean: Double = 0.0,
    val payloadMean: Double = 0.0,
    val loadMean: Double = 0.0,
    val transportMetricsPresent: Double = 0.0,
    val destinationConcentration: Double = 0.0,
    val destinationTransitionRate: Double = 0.0,
    val dnsFlowRatio: Double = 0.0,
    val webFlowRatio: Double = 0.0,
    val privateDestinationRatio: Double = 0.0,
    val multicastDestinationRatio: Double = 0.0,
    val flowCountDeviation: Double = 0.0,
    val byteRateDeviation: Double = 0.0,
    val destinationDiversityShift: Double = 0.0,
    val noveltyShift: Double = 0.0,
    val recentFlowCountMean: Double = 0.0,
    val recentByteRateMean: Double = 0.0,
    val recentNoveltyMean: Double = 0.0,
    val flowCountTrend: Double = 0.0,
    val byteRateTrend: Double = 0.0,
    val noveltyTrend: Double = 0.0,
    val destinationDiversityTrend: Double = 0.0,
    val consecutiveBurstWindows: Double = 0.0,
    val lowVolumePeriodicScore: Double = 0.0,
    val destinationRiskScore: Double = 0.0,
    val lookalikeScore: Double = 0.0,
    val suspiciousDestinationRatio: Double = 0.0,
    val knownIdentityRatio: Double = 0.0,
    val mitreTechniqueRatio: Double = 0.0,
    val threatTagRatio: Double = 0.0,
    val sampledByGuardrail: Boolean = false,
    val processingCostMillis: Double = 0.0
)

@Entity(
    tableName = "anomaly_scores",
    indices = [
        Index(value = ["createdAtMillis"]),
        Index(value = ["triageStatus", "createdAtMillis"]),
        Index(value = ["appId", "correlationKey", "lastSeenMillis"]),
        Index(value = ["appId", "createdAtMillis"]),
        Index(value = ["featureWindowId"])
    ]
)
data class AnomalyScoreEntity(
    @PrimaryKey val id: String,
    val featureWindowId: String,
    val appId: String,
    val score: Double,
    val severity: String,
    val topFeaturesCsv: String,
    val featureContributionsJson: String = "{}",
    val explanation: String,
    val sourceModel: String,
    val triageStatus: String,
    val triageNote: String,
    val createdAtMillis: Long,
    val triageUpdatedAtMillis: Long,
    val confidence: Double = 0.5,
    val uncertainty: Double = 0.5,
    val anomalyScore: Double = score,
    val contextScore: Double = 0.0,
    val responseScore: Double = score,
    val driftScore: Double = 0.0,
    val occurrenceCount: Int = 1,
    val firstSeenMillis: Long = createdAtMillis,
    val lastSeenMillis: Long = createdAtMillis,
    val correlationKey: String = "",
    val shadowModel: String? = null,
    val shadowScore: Double? = null,
    val suppressionReason: String? = null,
    val dataQualityWarningsCsv: String = "",
    val beaconScore: Double = 0.0,
    val destinationIp: String? = null,
    val destinationPort: Int? = null,
    val destinationHash: String? = null,
    val siteHint: String? = null,
    val mitreTechniquesCsv: String = "",
    val destinationIdentity: String? = null,
    val lookalikeScore: Double = 0.0
)

@Entity(
    tableName = "pending_alert_candidates",
    indices = [
        Index(value = ["appId", "correlationKey"], unique = true),
        Index(value = ["lastSeenMillis"]),
        Index(value = ["appId", "lastSeenMillis"])
    ]
)
data class PendingAlertEntity(
    @PrimaryKey val id: String,
    val featureWindowId: String,
    val appId: String,
    val correlationKey: String,
    val score: Double,
    val severity: String,
    val topFeaturesCsv: String,
    val featureContributionsJson: String = "{}",
    val sourceModel: String,
    val firstSeenMillis: Long,
    val lastSeenMillis: Long,
    val occurrenceCount: Int,
    val evidenceStrength: Double,
    val maxEvidenceStrength: Double,
    val scoreTrend: Double,
    val suppressionReason: String? = null,
    val destinationIp: String? = null,
    val destinationPort: Int? = null,
    val destinationHash: String? = null,
    val siteHint: String? = null,
    val destinationIdentity: String? = null,
    val lookalikeScore: Double = 0.0
)

@Entity(
    tableName = "export_queue",
    indices = [
        Index(value = ["exported", "nextAttemptMillis", "createdAtMillis"]),
        Index(value = ["exported", "lastAttemptMillis"])
    ]
)
data class ExportQueueEntity(
    @PrimaryKey(autoGenerate = true) val queueId: Long = 0,
    val eventType: String,
    val payload: String,
    val createdAtMillis: Long,
    val lastAttemptMillis: Long,
    val nextAttemptMillis: Long,
    val attempts: Int,
    val exported: Boolean
)
