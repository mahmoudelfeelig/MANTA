package com.manta.app.core.model

import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.CustomPrivacyOptions

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
    val destinationNovelty: Double,
    val siteHint: String? = null,
    val ttlGap: Double = 0.0,
    val ttlMetricsPresent: Double = 0.0,
    val synRateTotal: Double = 0.0,
    val rstRateTotal: Double = 0.0,
    val ackRateTotal: Double = 0.0,
    val finRateTotal: Double = 0.0,
    val pshRateTotal: Double = 0.0,
    val fragmentRateTotal: Double = 0.0,
    val tcpWindowMean: Double = 0.0,
    val ackDelayMean: Double = 0.0,
    val interPacketGapMean: Double = 0.0,
    val payloadMean: Double = 0.0,
    val loadMean: Double = 0.0,
    val transportMetricsPresent: Double = 0.0
) {
    fun toJson(
        deviceIdPseudo: String,
        anomalyScore: Double? = null,
        explainTopFeatures: List<String> = emptyList(),
        siteHint: String? = null,
        deviceLabel: String? = null,
        privacyMode: PrivacyMode = PrivacyMode.OFF,
        deviceSalt: String = "",
        customPrivacy: CustomPrivacyOptions = CustomPrivacyOptions()
    ): String {
        return IpfixMapper.toMobileFlowJson(
            flow = this,
            deviceIdPseudo = deviceIdPseudo,
            anomalyScore = anomalyScore,
            explainTopFeatures = explainTopFeatures,
            siteHint = siteHint ?: this.siteHint,
            deviceLabel = deviceLabel,
            privacyMode = privacyMode,
            deviceSalt = deviceSalt,
            customPrivacy = customPrivacy
        )
    }
}
