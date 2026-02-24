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

        val maxMagnitude = ranked.maxOf { (_, contribution) -> abs(contribution) }.coerceAtLeast(1e-9)
        val parts = ranked.map { (feature, contribution) ->
            val normalizedImpact = abs(contribution) / maxMagnitude
            val impact = when {
                normalizedImpact >= 0.66 -> "high"
                normalizedImpact >= 0.33 -> "moderate"
                else -> "low"
            }
            "$feature ($impact impact)"
        }

        return "Top contributors: ${parts.joinToString(", ")}."
    }
}
