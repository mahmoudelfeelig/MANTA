package com.feelbachelor.app.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "raw_flow_records")
data class RawFlowEntity(
    @PrimaryKey val id: String,
    val timestampStartMillis: Long,
    val timestampEndMillis: Long,
    val appId: String,
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
    val destinationNovelty: Double
)

@Entity(tableName = "feature_windows")
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
    val connectionFrequencyDelta: Double
)

@Entity(tableName = "anomaly_scores")
data class AnomalyScoreEntity(
    @PrimaryKey val id: String,
    val featureWindowId: String,
    val appId: String,
    val score: Double,
    val severity: String,
    val topFeaturesCsv: String,
    val explanation: String,
    val sourceModel: String,
    val triageStatus: String,
    val triageNote: String,
    val createdAtMillis: Long,
    val triageUpdatedAtMillis: Long
)

@Entity(tableName = "export_queue")
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
