package com.feelbachelor.app.core.model

enum class AlertSeverity {
    LOW,
    MEDIUM,
    HIGH
}

data class AnomalyAlert(
    val id: String,
    val featureWindowId: String,
    val appId: String,
    val anomalyScore: Double,
    val severity: AlertSeverity,
    val topFeatures: List<String>,
    val createdAtMillis: Long
)
