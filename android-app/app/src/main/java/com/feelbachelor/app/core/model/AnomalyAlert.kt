package com.feelbachelor.app.core.model

enum class AlertSeverity {
    LOW,
    MEDIUM,
    HIGH
}

enum class TriageStatus {
    OPEN,
    INVESTIGATING,
    RESOLVED,
    FALSE_POSITIVE
}

data class AnomalyAlert(
    val id: String,
    val featureWindowId: String,
    val appId: String,
    val anomalyScore: Double,
    val severity: AlertSeverity,
    val topFeatures: List<String>,
    val explanation: String,
    val sourceModel: String,
    val triageStatus: TriageStatus,
    val triageNote: String,
    val createdAtMillis: Long,
    val triageUpdatedAtMillis: Long
)
