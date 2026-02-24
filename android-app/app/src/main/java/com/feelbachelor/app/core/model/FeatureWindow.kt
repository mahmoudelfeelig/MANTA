package com.feelbachelor.app.core.model

/**
 * Windowed feature representation passed into detectors.
 */
data class FeatureWindow(
    val id: String,
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
    val periodicBeaconScore: Double = 0.0,
    val hourOfDay: Int = 0,
    val dayOfWeek: Int = 1,
    val isWeekend: Boolean = false,
    val dataQualityScore: Double = 1.0,
    val sampledByGuardrail: Boolean = false,
    val processingCostMillis: Double = 0.0
)
