package com.feelbachelor.app.core.model

import org.json.JSONArray
import org.json.JSONObject

object IpfixMapper {
    private const val IPFIX_TEMPLATE_ID = 256
    private const val NETFLOW_VERSION = 9

    fun toMobileFlowJson(
        flow: FlowRecord,
        deviceIdPseudo: String,
        anomalyScore: Double? = null,
        explainTopFeatures: List<String> = emptyList()
    ): String {
        val ipfixElements = JSONArray()
            .put(element(8, "sourceIPv4Address", flow.srcIp))
            .put(element(12, "destinationIPv4Address", flow.dstIp))
            .put(element(7, "sourceTransportPort", flow.srcPort))
            .put(element(11, "destinationTransportPort", flow.dstPort))
            .put(element(4, "protocolIdentifier", flow.protocol.code))
            .put(element(2, "packetDeltaCountOut", flow.packetsOut))
            .put(element(1, "octetDeltaCountOut", flow.bytesOut))
            .put(element(152, "flowStartMilliseconds", flow.timestampStartMillis))
            .put(element(153, "flowEndMilliseconds", flow.timestampEndMillis))

        val json = JSONObject()
            .put("event_type", "mobile_flow")
            .put("event_version", "1.1")
            .put("device_id_pseudo", deviceIdPseudo)
            .put("app_id", flow.appId)
            .put("protocol", flow.protocol.name)
            .put("src_ip", flow.srcIp)
            .put("src_port", flow.srcPort)
            .put("dst_ip", flow.dstIp)
            .put("dst_port", flow.dstPort)
            .put("dst_host_hash", flow.destinationHash)
            .put("bytes_out", flow.bytesOut)
            .put("bytes_in", flow.bytesIn)
            .put("packets_out", flow.packetsOut)
            .put("packets_in", flow.packetsIn)
            .put("duration_ms", flow.durationMillis)
            .put("timestamp_start", flow.timestampStartMillis)
            .put("timestamp_end", flow.timestampEndMillis)
            .put("dst_novelty", flow.destinationNovelty)
            .put("netflow_version", NETFLOW_VERSION)
            .put("ipfix_template_id", IPFIX_TEMPLATE_ID)
            .put("ipfix_elements", ipfixElements)

        if (anomalyScore != null) {
            json.put("anomaly_score", anomalyScore)
        }
        if (explainTopFeatures.isNotEmpty()) {
            json.put("explain_top_features", explainTopFeatures)
        }
        return json.toString()
    }

    private fun element(id: Int, name: String, value: Any): JSONObject {
        return JSONObject()
            .put("id", id)
            .put("name", name)
            .put("value", value)
    }
}
