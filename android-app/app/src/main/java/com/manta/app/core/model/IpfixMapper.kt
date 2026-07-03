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
            PrivacyMode.LOW -> flow.appId
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> CryptoUtils.sha256("$deviceSalt:${flow.appId}")
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
        val exportedDestinationKey = exportDestinationKey(flow, privacyMode, customPrivacy)
        val hostMetadataAllowed = privacyMode == PrivacyMode.OFF ||
            privacyMode == PrivacyMode.LOW ||
            (privacyMode == PrivacyMode.CUSTOM && customPrivacy.includeSiteHint)
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
            .put("destination_key", exportedDestinationKey)
            .put("bytes_out", flow.bytesOut)
            .put("bytes_in", flow.bytesIn)
            .put("packets_out", flow.packetsOut)
            .put("packets_in", flow.packetsIn)
            .put("duration_ms", flow.durationMillis)
            .put("timestamp_start", flow.timestampStartMillis)
            .put("timestamp_end", flow.timestampEndMillis)
            .put("is_new_destination_for_app", flow.destinationNovelty)
            .put("dst_novelty", flow.destinationNovelty)
            .put("site_hint", exportSiteHint(siteHint, privacyMode, customPrivacy))
            .put("dns_query_name", flow.protocolEvidence.dnsQueryName.takeIf { hostMetadataAllowed })
            .put("dns_query_type", flow.protocolEvidence.dnsQueryType)
            .put("dns_response_code", flow.protocolEvidence.dnsResponseCode)
            .put("dns_answer_value", flow.protocolEvidence.dnsAnswerValue.takeIf { hostMetadataAllowed })
            .put("tls_sni", flow.protocolEvidence.tlsSni.takeIf { hostMetadataAllowed })
            .put("tls_alpn", flow.protocolEvidence.tlsAlpn)
            .put("tls_version", flow.protocolEvidence.tlsVersion)
            .put("tls_ja3_like", flow.protocolEvidence.tlsJa3Like)
            .put("tls_leaf_subject", flow.protocolEvidence.tlsLeafSubject.takeIf { hostMetadataAllowed })
            .put("tls_leaf_issuer", flow.protocolEvidence.tlsLeafIssuer.takeIf { hostMetadataAllowed })
            .put("tls_leaf_san", flow.protocolEvidence.tlsLeafSan.takeIf { hostMetadataAllowed })
            .put("http_method", flow.protocolEvidence.httpMethod)
            .put("http_host", flow.protocolEvidence.httpHost.takeIf { hostMetadataAllowed })
            .put("http_path", flow.protocolEvidence.httpPath.takeIf { privacyMode == PrivacyMode.OFF || privacyMode == PrivacyMode.LOW })
            .put("quic_version", flow.protocolEvidence.quicVersion)
            .put("quic_detected", flow.protocolEvidence.quicDetected)
            .put("http3_detected", flow.protocolEvidence.http3Detected)
            .put("registrable_domain", flow.destinationInsight.registrableDomain.takeIf { hostMetadataAllowed })
            .put("brand_match", flow.destinationInsight.brandMatch.takeIf { hostMetadataAllowed })
            .put("lookalike_score", flow.destinationInsight.lookalikeScore)
            .put("threat_tags", JSONArray(flow.destinationInsight.threatTags))
            .put("mitre_techniques", JSONArray(flow.destinationInsight.mitreTechniques))
            .put("netflow_version", NETFLOW_VERSION)
            .put("ipfix_template_id", IPFIX_TEMPLATE_ID)
            .put("ipfix_elements", ipfixElements)

        if (anomalyScore != null) {
            json.put("anomaly_score", anomalyScore)
        }
        if (explainTopFeatures.isNotEmpty()) {
            json.put("explain_top_features", JSONArray(explainTopFeatures))
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
            PrivacyMode.OFF, PrivacyMode.LOW -> siteHint
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> null
            PrivacyMode.CUSTOM -> siteHint.takeIf { customPrivacy.includeSiteHint }
        }
    }

    private fun exportDestinationKey(
        flow: FlowRecord,
        privacyMode: PrivacyMode,
        customPrivacy: CustomPrivacyOptions
    ): String {
        val visibleHost = exportSiteHint(flow.siteHint, privacyMode, customPrivacy)
        return when {
            !visibleHost.isNullOrBlank() -> "${visibleHost}:${exportPort(flow.dstPort, privacyMode, customPrivacy)}"
            privacyMode == PrivacyMode.OFF -> "${flow.dstIp}:${flow.dstPort}"
            privacyMode == PrivacyMode.CUSTOM && customPrivacy.includeIpAddresses ->
                "${flow.dstIp}:${exportPort(flow.dstPort, privacyMode, customPrivacy)}"
            else -> flow.destinationHash
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
