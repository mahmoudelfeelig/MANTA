package com.feelbachelor.app.core.model

/**
 * Metadata-only flow record for local detection and optional export.
 */
data class FlowRecord(
    val id: String,
    val timestampStartMillis: Long,
    val timestampEndMillis: Long,
    val appId: String,
    val protocol: FlowProtocol,
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
) {
    fun toJson(deviceIdPseudo: String, anomalyScore: Double? = null, explainTopFeatures: List<String> = emptyList()): String {
        return IpfixMapper.toMobileFlowJson(
            flow = this,
            deviceIdPseudo = deviceIdPseudo,
            anomalyScore = anomalyScore,
            explainTopFeatures = explainTopFeatures
        )
    }
}
