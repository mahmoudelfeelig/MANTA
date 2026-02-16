package com.feelbachelor.app.core.model

import org.json.JSONObject

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
        val json = JSONObject()
            .put("event_type", "mobile_flow")
            .put("event_version", "1.0")
            .put("device_id_pseudo", deviceIdPseudo)
            .put("app_id", appId)
            .put("protocol", protocol.name)
            .put("src_ip", srcIp)
            .put("src_port", srcPort)
            .put("dst_ip", dstIp)
            .put("dst_port", dstPort)
            .put("dst_host_hash", destinationHash)
            .put("bytes_out", bytesOut)
            .put("bytes_in", bytesIn)
            .put("packets_out", packetsOut)
            .put("packets_in", packetsIn)
            .put("duration_ms", durationMillis)
            .put("timestamp_start", timestampStartMillis)
            .put("timestamp_end", timestampEndMillis)
            .put("dst_novelty", destinationNovelty)

        if (anomalyScore != null) {
            json.put("anomaly_score", anomalyScore)
        }
        if (explainTopFeatures.isNotEmpty()) {
            json.put("explain_top_features", explainTopFeatures)
        }
        return json.toString()
    }
}
