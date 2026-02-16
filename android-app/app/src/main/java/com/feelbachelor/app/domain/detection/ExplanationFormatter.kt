package com.feelbachelor.app.domain.detection

import kotlin.math.abs

object ExplanationFormatter {
    fun summarize(topFeatures: List<String>, contributions: Map<String, Double>): String {
        if (topFeatures.isEmpty()) {
            return "No dominant contributing features were detected."
        }

        val ranked = topFeatures.mapNotNull { feature ->
            contributions[feature]?.let { contribution ->
                feature to contribution
            }
        }

        if (ranked.isEmpty()) {
            return "Anomaly detected but detailed contributions are unavailable."
        }

        val parts = ranked.map { (feature, contribution) ->
            val impact = when {
                abs(contribution) >= 3.0 -> "high"
                abs(contribution) >= 1.5 -> "moderate"
                else -> "low"
            }
            "$feature ($impact impact)"
        }

        return "Top contributors: ${parts.joinToString(", ")}."
    }
}
