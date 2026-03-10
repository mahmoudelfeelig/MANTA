package com.manta.app.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface FlowDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRawFlow(flow: RawFlowEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFeatureWindow(window: FeatureWindowEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAnomalyScore(score: AnomalyScoreEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun enqueueExport(entity: ExportQueueEntity): Long

    @Query("SELECT * FROM raw_flow_records WHERE appId = :appId AND timestampStartMillis >= :sinceMillis ORDER BY timestampStartMillis DESC")
    suspend fun getRecentFlowsByApp(appId: String, sinceMillis: Long): List<RawFlowEntity>

    @Query("SELECT * FROM raw_flow_records ORDER BY timestampStartMillis DESC LIMIT :limit")
    suspend fun getLatestFlows(limit: Int): List<RawFlowEntity>

    @Query("SELECT * FROM anomaly_scores ORDER BY createdAtMillis DESC LIMIT :limit")
    suspend fun getLatestScores(limit: Int): List<AnomalyScoreEntity>

    @Query("SELECT COUNT(*) FROM anomaly_scores")
    suspend fun countScores(): Int

    @Query("SELECT COUNT(*) FROM anomaly_scores WHERE appId = :appId AND triageStatus = 'FALSE_POSITIVE' AND createdAtMillis >= :sinceMillis")
    suspend fun countFalsePositivesForAppSince(appId: String, sinceMillis: Long): Int

    @Query("SELECT * FROM anomaly_scores WHERE appId = :appId AND correlationKey = :correlationKey AND lastSeenMillis >= :sinceMillis ORDER BY lastSeenMillis DESC LIMIT 1")
    suspend fun findCorrelatedAlert(appId: String, correlationKey: String, sinceMillis: Long): AnomalyScoreEntity?

    @Query(
        "UPDATE anomaly_scores SET " +
            "score = :score, " +
            "severity = :severity, " +
            "topFeaturesCsv = :topFeaturesCsv, " +
            "featureContributionsJson = :featureContributionsJson, " +
            "explanation = :explanation, " +
            "sourceModel = :sourceModel, " +
            "triageStatus = :triageStatus, " +
            "triageNote = :triageNote, " +
            "triageUpdatedAtMillis = :triageUpdatedAtMillis, " +
            "confidence = :confidence, " +
            "uncertainty = :uncertainty, " +
            "anomalyScore = :anomalyScore, " +
            "contextScore = :contextScore, " +
            "responseScore = :responseScore, " +
            "driftScore = :driftScore, " +
            "occurrenceCount = :occurrenceCount, " +
            "lastSeenMillis = :lastSeenMillis, " +
            "shadowModel = :shadowModel, " +
            "shadowScore = :shadowScore, " +
            "suppressionReason = :suppressionReason, " +
            "dataQualityWarningsCsv = :dataQualityWarningsCsv, " +
            "beaconScore = :beaconScore, " +
            "destinationIp = :destinationIp, " +
            "destinationPort = :destinationPort, " +
            "destinationHash = :destinationHash, " +
            "siteHint = :siteHint " +
            "WHERE id = :alertId"
    )
    suspend fun updateCorrelatedAlert(
        alertId: String,
        score: Double,
        severity: String,
        topFeaturesCsv: String,
        featureContributionsJson: String,
        explanation: String,
        sourceModel: String,
        triageStatus: String,
        triageNote: String,
        triageUpdatedAtMillis: Long,
        confidence: Double,
        uncertainty: Double,
        anomalyScore: Double,
        contextScore: Double,
        responseScore: Double,
        driftScore: Double,
        occurrenceCount: Int,
        lastSeenMillis: Long,
        shadowModel: String?,
        shadowScore: Double?,
        suppressionReason: String?,
        dataQualityWarningsCsv: String,
        beaconScore: Double,
        destinationIp: String?,
        destinationPort: Int?,
        destinationHash: String?,
        siteHint: String?
    ): Int

    @Query("SELECT * FROM anomaly_scores WHERE triageStatus = :triageStatus ORDER BY createdAtMillis DESC LIMIT :limit")
    suspend fun getScoresByTriage(triageStatus: String, limit: Int): List<AnomalyScoreEntity>

    @Query("SELECT * FROM anomaly_scores WHERE id = :alertId LIMIT 1")
    suspend fun getScoreById(alertId: String): AnomalyScoreEntity?

    @Query("SELECT * FROM feature_windows WHERE id = :windowId LIMIT 1")
    suspend fun getFeatureWindowById(windowId: String): FeatureWindowEntity?

    @Query("UPDATE anomaly_scores SET triageStatus = :triageStatus, triageNote = :triageNote, triageUpdatedAtMillis = :updatedAtMillis WHERE id = :alertId")
    suspend fun updateAlertTriage(alertId: String, triageStatus: String, triageNote: String, updatedAtMillis: Long): Int

    @Query("DELETE FROM anomaly_scores WHERE id = :alertId")
    suspend fun deleteAlertById(alertId: String): Int

    @Query("SELECT * FROM export_queue WHERE exported = 0 AND nextAttemptMillis <= :nowMillis ORDER BY createdAtMillis ASC LIMIT :limit")
    suspend fun getPendingExports(nowMillis: Long, limit: Int): List<ExportQueueEntity>

    @Query("SELECT COUNT(*) FROM export_queue WHERE exported = 0")
    suspend fun countPendingExports(): Int

    @Query("UPDATE export_queue SET exported = 1, lastAttemptMillis = :attemptMillis WHERE queueId = :queueId")
    suspend fun markExported(queueId: Long, attemptMillis: Long): Int

    @Query("UPDATE export_queue SET attempts = :attempts, lastAttemptMillis = :attemptMillis, nextAttemptMillis = :nextAttemptMillis WHERE queueId = :queueId")
    suspend fun rescheduleExport(queueId: Long, attempts: Int, attemptMillis: Long, nextAttemptMillis: Long): Int

    @Query("DELETE FROM raw_flow_records WHERE timestampEndMillis < :cutoffMillis")
    suspend fun deleteOldFlows(cutoffMillis: Long): Int

    @Query("DELETE FROM feature_windows WHERE windowEndMillis < :cutoffMillis")
    suspend fun deleteOldFeatureWindows(cutoffMillis: Long): Int

    @Query("DELETE FROM anomaly_scores WHERE createdAtMillis < :cutoffMillis")
    suspend fun deleteOldScores(cutoffMillis: Long): Int

    @Query("DELETE FROM export_queue WHERE exported = 1 AND lastAttemptMillis < :cutoffMillis")
    suspend fun deleteOldExported(cutoffMillis: Long): Int

    @Query("DELETE FROM raw_flow_records")
    suspend fun purgeRawFlows(): Int

    @Query("DELETE FROM feature_windows")
    suspend fun purgeFeatureWindows(): Int

    @Query("DELETE FROM anomaly_scores")
    suspend fun purgeScores(): Int

    @Query("DELETE FROM export_queue")
    suspend fun purgeExportQueue(): Int
}
