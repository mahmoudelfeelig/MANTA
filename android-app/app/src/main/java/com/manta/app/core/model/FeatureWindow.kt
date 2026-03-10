package com.manta.app.core.model

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
    val siteHint: String? = null,
    val periodicBeaconScore: Double = 0.0,
    val hourOfDay: Int = 0,
    val dayOfWeek: Int = 1,
    val isWeekend: Boolean = false,
    val dataQualityScore: Double = 1.0,
    val sampledByGuardrail: Boolean = false,
    val processingCostMillis: Double = 0.0
) {
    fun portableFeatureMap(): Map<String, Double> = mapOf(
        "flow_count" to flowCount.toDouble(),
        "total_bytes_out" to totalBytesOut.toDouble(),
        "bytes_out" to totalBytesOut.toDouble(),
        "total_bytes_in" to totalBytesIn.toDouble(),
        "bytes_in" to totalBytesIn.toDouble(),
        "mean_packet_size" to meanPacketSize,
        "outbound_ratio" to outboundRatio,
        "burstiness" to burstiness,
        "novelty_score" to noveltyScore,
        "novelty" to noveltyScore,
        "connection_frequency_delta" to connectionFrequencyDelta,
        "conn_freq_delta" to connectionFrequencyDelta,
        "bytes_per_flow" to bytesPerFlow,
        "destination_diversity" to destinationDiversity,
        "activity_ratio" to activityRatio,
        "periodic_beacon_score" to periodicBeaconScore,
        "byte_rate" to byteRate,
        "packet_rate" to packetRate,
        "mean_duration_ms" to meanDurationMillis,
        "duration_jitter" to durationJitter,
        "port_diversity" to portDiversity,
        "protocol_diversity" to protocolDiversity,
        "packet_imbalance" to packetImbalance,
        "small_flow_ratio" to smallFlowRatio,
        "high_port_ratio" to highPortRatio
    )

    companion object {
        val portableFeatureOrder = listOf(
            "flow_count",
            "total_bytes_out",
            "total_bytes_in",
            "mean_packet_size",
            "outbound_ratio",
            "burstiness",
            "novelty_score",
            "connection_frequency_delta",
            "bytes_per_flow",
            "destination_diversity",
            "activity_ratio",
            "periodic_beacon_score",
            "byte_rate",
            "packet_rate",
            "mean_duration_ms",
            "duration_jitter",
            "port_diversity",
            "protocol_diversity",
            "packet_imbalance",
            "small_flow_ratio",
            "high_port_ratio"
        )
    }
}
