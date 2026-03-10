package com.manta.app.core.model

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
    val featureContributions: Map<String, Double>,
    val explanation: String,
    val sourceModel: String,
    val triageStatus: TriageStatus,
    val triageNote: String,
    val createdAtMillis: Long,
    val triageUpdatedAtMillis: Long,
    val confidence: Double = 0.5,
    val uncertainty: Double = 0.5,
    val baseAnomalyScore: Double = anomalyScore,
    val contextScore: Double = 0.0,
    val responseScore: Double = anomalyScore,
    val driftScore: Double = 0.0,
    val occurrenceCount: Int = 1,
    val firstSeenMillis: Long = createdAtMillis,
    val lastSeenMillis: Long = createdAtMillis,
    val correlationKey: String = "",
    val shadowModel: String? = null,
    val shadowScore: Double? = null,
    val suppressionReason: String? = null,
    val dataQualityWarnings: List<String> = emptyList(),
    val beaconScore: Double = 0.0,
    val destinationIp: String? = null,
    val destinationPort: Int? = null,
    val destinationHash: String? = null,
    val siteHint: String? = null
)
