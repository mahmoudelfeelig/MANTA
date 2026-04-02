package com.manta.app.core.model

import org.json.JSONObject

data class ProtocolEvidence(
    val dnsQueryName: String? = null,
    val dnsQueryType: String? = null,
    val dnsResponseCode: Int? = null,
    val dnsAnswerValue: String? = null,
    val tlsSni: String? = null,
    val tlsAlpn: String? = null,
    val tlsVersion: String? = null,
    val tlsJa3Like: String? = null,
    val tlsLeafSubject: String? = null,
    val tlsLeafIssuer: String? = null,
    val tlsLeafSan: String? = null,
    val httpMethod: String? = null,
    val httpHost: String? = null,
    val httpPath: String? = null,
    val quicVersion: String? = null,
    val quicDetected: Boolean = false,
    val http3Detected: Boolean = false
) {
    fun merge(other: ProtocolEvidence): ProtocolEvidence {
        val preferredDnsName = dnsQueryName ?: other.dnsQueryName
        val preferredHttpHost = httpHost ?: other.httpHost
        val preferredTlsSni = tlsSni ?: other.tlsSni
        return copy(
            dnsQueryName = preferredDnsName,
            dnsQueryType = dnsQueryType ?: other.dnsQueryType,
            dnsResponseCode = dnsResponseCode ?: other.dnsResponseCode,
            dnsAnswerValue = dnsAnswerValue ?: other.dnsAnswerValue,
            tlsSni = preferredTlsSni,
            tlsAlpn = tlsAlpn ?: other.tlsAlpn,
            tlsVersion = tlsVersion ?: other.tlsVersion,
            tlsJa3Like = tlsJa3Like ?: other.tlsJa3Like,
            tlsLeafSubject = tlsLeafSubject ?: other.tlsLeafSubject,
            tlsLeafIssuer = tlsLeafIssuer ?: other.tlsLeafIssuer,
            tlsLeafSan = tlsLeafSan ?: other.tlsLeafSan,
            httpMethod = httpMethod ?: other.httpMethod,
            httpHost = preferredHttpHost,
            httpPath = httpPath ?: other.httpPath,
            quicVersion = quicVersion ?: other.quicVersion,
            quicDetected = quicDetected || other.quicDetected,
            http3Detected = http3Detected || other.http3Detected
        )
    }

    fun preferredHost(): String? {
        return httpHost ?: tlsSni ?: dnsQueryName
    }

    fun toJsonString(): String {
        return JSONObject()
            .put("dns_query_name", dnsQueryName)
            .put("dns_query_type", dnsQueryType)
            .put("dns_response_code", dnsResponseCode)
            .put("dns_answer_value", dnsAnswerValue)
            .put("tls_sni", tlsSni)
            .put("tls_alpn", tlsAlpn)
            .put("tls_version", tlsVersion)
            .put("tls_ja3_like", tlsJa3Like)
            .put("tls_leaf_subject", tlsLeafSubject)
            .put("tls_leaf_issuer", tlsLeafIssuer)
            .put("tls_leaf_san", tlsLeafSan)
            .put("http_method", httpMethod)
            .put("http_host", httpHost)
            .put("http_path", httpPath)
            .put("quic_version", quicVersion)
            .put("quic_detected", quicDetected)
            .put("http3_detected", http3Detected)
            .toString()
    }

    companion object {
        fun fromJsonString(raw: String?): ProtocolEvidence {
            val root = runCatching { JSONObject(raw ?: "{}") }.getOrDefault(JSONObject())
            return ProtocolEvidence(
                dnsQueryName = root.optString("dns_query_name", "").ifBlank { null },
                dnsQueryType = root.optString("dns_query_type", "").ifBlank { null },
                dnsResponseCode = root.takeIf { it.has("dns_response_code") }?.optInt("dns_response_code"),
                dnsAnswerValue = root.optString("dns_answer_value", "").ifBlank { null },
                tlsSni = root.optString("tls_sni", "").ifBlank { null },
                tlsAlpn = root.optString("tls_alpn", "").ifBlank { null },
                tlsVersion = root.optString("tls_version", "").ifBlank { null },
                tlsJa3Like = root.optString("tls_ja3_like", "").ifBlank { null },
                tlsLeafSubject = root.optString("tls_leaf_subject", "").ifBlank { null },
                tlsLeafIssuer = root.optString("tls_leaf_issuer", "").ifBlank { null },
                tlsLeafSan = root.optString("tls_leaf_san", "").ifBlank { null },
                httpMethod = root.optString("http_method", "").ifBlank { null },
                httpHost = root.optString("http_host", "").ifBlank { null },
                httpPath = root.optString("http_path", "").ifBlank { null },
                quicVersion = root.optString("quic_version", "").ifBlank { null },
                quicDetected = root.optBoolean("quic_detected", false),
                http3Detected = root.optBoolean("http3_detected", false)
            )
        }
    }
}
