package com.feelbachelor.app.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface FlowDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRawFlow(flow: RawFlowEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFeatureWindow(window: FeatureWindowEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAnomalyScore(score: AnomalyScoreEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun enqueueExport(entity: ExportQueueEntity)

    @Query("SELECT * FROM raw_flow_records WHERE appId = :appId AND timestampStartMillis >= :sinceMillis ORDER BY timestampStartMillis DESC")
    suspend fun getRecentFlowsByApp(appId: String, sinceMillis: Long): List<RawFlowEntity>

    @Query("SELECT * FROM raw_flow_records ORDER BY timestampStartMillis DESC LIMIT :limit")
    suspend fun getLatestFlows(limit: Int): List<RawFlowEntity>

    @Query("SELECT * FROM anomaly_scores ORDER BY createdAtMillis DESC LIMIT :limit")
    suspend fun getLatestScores(limit: Int): List<AnomalyScoreEntity>

    @Query("SELECT * FROM anomaly_scores WHERE triageStatus = :triageStatus ORDER BY createdAtMillis DESC LIMIT :limit")
    suspend fun getScoresByTriage(triageStatus: String, limit: Int): List<AnomalyScoreEntity>

    @Query("SELECT * FROM anomaly_scores WHERE id = :alertId LIMIT 1")
    suspend fun getScoreById(alertId: String): AnomalyScoreEntity?

    @Query("UPDATE anomaly_scores SET triageStatus = :triageStatus, triageNote = :triageNote, triageUpdatedAtMillis = :updatedAtMillis WHERE id = :alertId")
    suspend fun updateAlertTriage(alertId: String, triageStatus: String, triageNote: String, updatedAtMillis: Long)

    @Query("SELECT * FROM export_queue WHERE exported = 0 AND nextAttemptMillis <= :nowMillis ORDER BY createdAtMillis ASC LIMIT :limit")
    suspend fun getPendingExports(nowMillis: Long, limit: Int): List<ExportQueueEntity>

    @Query("UPDATE export_queue SET exported = 1, lastAttemptMillis = :attemptMillis WHERE queueId = :queueId")
    suspend fun markExported(queueId: Long, attemptMillis: Long)

    @Query("UPDATE export_queue SET attempts = :attempts, lastAttemptMillis = :attemptMillis, nextAttemptMillis = :nextAttemptMillis WHERE queueId = :queueId")
    suspend fun rescheduleExport(queueId: Long, attempts: Int, attemptMillis: Long, nextAttemptMillis: Long)

    @Query("DELETE FROM raw_flow_records WHERE timestampEndMillis < :cutoffMillis")
    suspend fun deleteOldFlows(cutoffMillis: Long): Int

    @Query("DELETE FROM feature_windows WHERE windowEndMillis < :cutoffMillis")
    suspend fun deleteOldFeatureWindows(cutoffMillis: Long): Int

    @Query("DELETE FROM anomaly_scores WHERE createdAtMillis < :cutoffMillis")
    suspend fun deleteOldScores(cutoffMillis: Long): Int

    @Query("DELETE FROM export_queue WHERE exported = 1 AND lastAttemptMillis < :cutoffMillis")
    suspend fun deleteOldExported(cutoffMillis: Long): Int

    @Query("DELETE FROM raw_flow_records")
    suspend fun purgeRawFlows()

    @Query("DELETE FROM feature_windows")
    suspend fun purgeFeatureWindows()

    @Query("DELETE FROM anomaly_scores")
    suspend fun purgeScores()

    @Query("DELETE FROM export_queue")
    suspend fun purgeExportQueue()
}
