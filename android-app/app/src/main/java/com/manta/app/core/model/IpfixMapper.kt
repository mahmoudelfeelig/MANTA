package com.manta.app.core.model

import com.manta.app.core.security.CryptoUtils
import com.manta.app.core.settings.CustomPrivacyOptions
import com.manta.app.core.settings.PrivacyMode
import org.json.JSONArray
import org.json.JSONObject

object IpfixMapper {
    private const val IPFIX_TEMPLATE_ID = 256
    private const val NETFLOW_VERSION = 9

    fun toMobileFlowJson(
        flow: FlowRecord,
        deviceIdPseudo: String,
        anomalyScore: Double? = null,
        explainTopFeatures: List<String> = emptyList(),
        siteHint: String? = null,
        deviceLabel: String? = null,
        privacyMode: PrivacyMode = PrivacyMode.OFF,
        deviceSalt: String = "",
        customPrivacy: CustomPrivacyOptions = CustomPrivacyOptions()
    ): String {
        val exportedAppId = when (privacyMode) {
            PrivacyMode.OFF -> flow.appId
            PrivacyMode.STRICT, PrivacyMode.BALANCED -> CryptoUtils.sha256("$deviceSalt:${flow.appId}")
            PrivacyMode.RESEARCH -> flow.appId
            PrivacyMode.CUSTOM ->
                if (customPrivacy.includeAppId) flow.appId else CryptoUtils.sha256("$deviceSalt:${flow.appId}")
        }
        val exportedSrcIp = when (privacyMode) {
            PrivacyMode.OFF -> flow.srcIp
            PrivacyMode.CUSTOM ->
                if (customPrivacy.includeIpAddresses) flow.srcIp else CryptoUtils.sha256("$deviceSalt:${flow.srcIp}")
            else -> CryptoUtils.sha256("$deviceSalt:${flow.srcIp}")
        }
        val exportedDstIp = when (privacyMode) {
            PrivacyMode.OFF -> flow.dstIp
            PrivacyMode.CUSTOM ->
                if (customPrivacy.includeIpAddresses) flow.dstIp else CryptoUtils.sha256("$deviceSalt:${flow.dstIp}")
            else -> CryptoUtils.sha256("$deviceSalt:${flow.dstIp}")
        }
        val exportedSrcPort = exportPort(flow.srcPort, privacyMode, customPrivacy)
        val exportedDstPort = exportPort(flow.dstPort, privacyMode, customPrivacy)
        val ipfixElements = JSONArray()
            .put(element(8, "sourceIPv4Address", exportedSrcIp))
            .put(element(12, "destinationIPv4Address", exportedDstIp))
            .put(element(7, "sourceTransportPort", exportedSrcPort))
            .put(element(11, "destinationTransportPort", exportedDstPort))
            .put(element(4, "protocolIdentifier", flow.protocol.code))
            .put(element(2, "packetDeltaCountOut", flow.packetsOut))
            .put(element(1, "octetDeltaCountOut", flow.bytesOut))
            .put(element(152, "flowStartMilliseconds", flow.timestampStartMillis))
            .put(element(153, "flowEndMilliseconds", flow.timestampEndMillis))

        val json = JSONObject()
            .put("event_type", "mobile_flow")
            .put("event_version", "1.1")
            .put("device_id_pseudo", deviceIdPseudo)
            .put("device_label", exportDeviceLabel(deviceLabel, privacyMode, customPrivacy))
            .put("app_id", exportedAppId)
            .put("protocol", flow.protocol.name)
            .put("src_ip", exportedSrcIp)
            .put("src_port", exportedSrcPort)
            .put("dst_ip", exportedDstIp)
            .put("dst_port", exportedDstPort)
            .put("dst_host_hash", flow.destinationHash)
            .put("bytes_out", flow.bytesOut)
            .put("bytes_in", flow.bytesIn)
            .put("packets_out", flow.packetsOut)
            .put("packets_in", flow.packetsIn)
            .put("duration_ms", flow.durationMillis)
            .put("timestamp_start", flow.timestampStartMillis)
            .put("timestamp_end", flow.timestampEndMillis)
            .put("dst_novelty", flow.destinationNovelty)
            .put("site_hint", exportSiteHint(siteHint, privacyMode, customPrivacy))
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

    private fun exportSiteHint(
        siteHint: String?,
        privacyMode: PrivacyMode,
        customPrivacy: CustomPrivacyOptions
    ): String? {
        return when (privacyMode) {
            PrivacyMode.OFF, PrivacyMode.RESEARCH -> siteHint
            PrivacyMode.STRICT, PrivacyMode.BALANCED -> null
            PrivacyMode.CUSTOM -> siteHint.takeIf { customPrivacy.includeSiteHint }
        }
    }

    private fun exportDeviceLabel(
        deviceLabel: String?,
        privacyMode: PrivacyMode,
        customPrivacy: CustomPrivacyOptions
    ): String? {
        return when (privacyMode) {
            PrivacyMode.CUSTOM -> deviceLabel.takeIf { customPrivacy.includeDeviceLabel }
            else -> deviceLabel
        }
    }

    private fun exportPort(
        port: Int,
        privacyMode: PrivacyMode,
        customPrivacy: CustomPrivacyOptions
    ): Int {
        if (privacyMode != PrivacyMode.CUSTOM || customPrivacy.includeExactPorts) {
            return port
        }
        return when {
            port in setOf(53, 80, 123, 443, 853) -> port
            port in 1..1023 -> 1024
            port in 1024..49151 -> 49152
            else -> 65535
        }
    }
}
