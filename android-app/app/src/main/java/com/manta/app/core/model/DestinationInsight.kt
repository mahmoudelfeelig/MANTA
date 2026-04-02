package com.manta.app.core.model

import org.json.JSONArray
import org.json.JSONObject

data class DestinationInsight(
    val normalizedHost: String? = null,
    val registrableDomain: String? = null,
    val brandMatch: String? = null,
    val lookalikeScore: Double = 0.0,
    val punycodePresent: Boolean = false,
    val digitSubstitutionPresent: Boolean = false,
    val suspiciousTld: Boolean = false,
    val threatTags: List<String> = emptyList(),
    val mitreTechniques: List<String> = emptyList(),
    val confidence: Double = 0.0
) {
    fun summary(): String? {
        val parts = buildList {
            normalizedHost?.let { add("host=$it") }
            registrableDomain?.let { add("domain=$it") }
            brandMatch?.let { add("brand=$it") }
            if (lookalikeScore > 0.0) add("lookalike=${"%.2f".format(lookalikeScore)}")
            if (punycodePresent) add("punycode")
            if (digitSubstitutionPresent) add("digit-substitution")
            if (suspiciousTld) add("suspicious-tld")
            if (threatTags.isNotEmpty()) add("tags=${threatTags.joinToString("|")}")
            if (mitreTechniques.isNotEmpty()) add("mitre=${mitreTechniques.joinToString("|")}")
        }
        return parts.takeIf { it.isNotEmpty() }?.joinToString(", ")
    }

    fun toJsonString(): String {
        return JSONObject()
            .put("normalized_host", normalizedHost)
            .put("registrable_domain", registrableDomain)
            .put("brand_match", brandMatch)
            .put("lookalike_score", lookalikeScore)
            .put("punycode_present", punycodePresent)
            .put("digit_substitution_present", digitSubstitutionPresent)
            .put("suspicious_tld", suspiciousTld)
            .put("threat_tags", JSONArray(threatTags))
            .put("mitre_techniques", JSONArray(mitreTechniques))
            .put("confidence", confidence)
            .toString()
    }

    companion object {
        fun fromJsonString(raw: String?): DestinationInsight {
            val root = runCatching { JSONObject(raw ?: "{}") }.getOrDefault(JSONObject())
            fun array(name: String): List<String> {
                val node = root.optJSONArray(name) ?: return emptyList()
                return buildList {
                    for (index in 0 until node.length()) {
                        val value = node.optString(index).trim()
                        if (value.isNotBlank()) add(value)
                    }
                }
            }
            return DestinationInsight(
                normalizedHost = root.optString("normalized_host", "").ifBlank { null },
                registrableDomain = root.optString("registrable_domain", "").ifBlank { null },
                brandMatch = root.optString("brand_match", "").ifBlank { null },
                lookalikeScore = root.optDouble("lookalike_score", 0.0),
                punycodePresent = root.optBoolean("punycode_present", false),
                digitSubstitutionPresent = root.optBoolean("digit_substitution_present", false),
                suspiciousTld = root.optBoolean("suspicious_tld", false),
                threatTags = array("threat_tags"),
                mitreTechniques = array("mitre_techniques"),
                confidence = root.optDouble("confidence", 0.0)
            )
        }
    }
}
