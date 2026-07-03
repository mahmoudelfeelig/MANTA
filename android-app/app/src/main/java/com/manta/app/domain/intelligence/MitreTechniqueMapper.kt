package com.manta.app.domain.intelligence

import com.manta.app.core.model.DestinationInsight
import com.manta.app.core.model.FlowRecord
import com.manta.app.core.model.ProtocolEvidence

class MitreTechniqueMapper {
    fun map(flow: FlowRecord, evidence: ProtocolEvidence, insight: DestinationInsight): List<String> {
        val techniques = linkedSetOf<String>()
        if (insight.threatTags.any { it.contains("lookalike") || it.contains("phishing") }) {
            techniques += "T1566"
        }
        if (!evidence.dnsQueryName.isNullOrBlank()) {
            techniques += "T1071.004"
            if (flow.destinationNovelty >= 0.95 && evidence.dnsQueryName.count { it == '.' } >= 4) {
                techniques += "T1568"
            }
        }
        if (!evidence.tlsSni.isNullOrBlank() || evidence.http3Detected || !evidence.tlsAlpn.isNullOrBlank()) {
            techniques += "T1573"
            techniques += "T1071.001"
        }
        if (flow.dstPort !in setOf(53, 80, 123, 443, 853) && flow.dstPort > 0) {
            techniques += "T1571"
        }
        if (!evidence.httpPath.isNullOrBlank() && evidence.httpMethod in setOf("GET", "POST")) {
            techniques += "T1105"
        }
        return techniques.toList()
    }
}
