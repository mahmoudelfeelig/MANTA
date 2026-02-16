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
    val connectionFrequencyDelta: Double
)
