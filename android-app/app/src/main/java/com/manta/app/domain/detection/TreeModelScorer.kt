package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import kotlin.math.abs
import kotlin.math.exp

data class TreeNodeSpec(
    val featureIndex: Int,
    val threshold: Double,
    val left: Int,
    val right: Int,
    val value: Double
)

data class TreeSpec(
    val nodes: List<TreeNodeSpec>
)

data class TreeEnsembleModelSpec(
    val featureOrder: List<String>,
    val trees: List<TreeSpec>,
    val recommendedThreshold: Double,
    val appFamilyThresholds: Map<String, Double> = emptyMap(),
    val appIdThresholds: Map<String, Double> = emptyMap(),
    val aggregation: String = "mean_positive_probability",
    val initialScore: Double = 0.0,
    val learningRate: Double = 1.0,
    val inputTransform: String? = null
) {
    fun isValid(): Boolean {
        return featureOrder.isNotEmpty() &&
            trees.isNotEmpty() &&
            trees.all { tree -> tree.nodes.isNotEmpty() }
    }
}

class TreeEnsembleModelScorer(
    private val spec: TreeEnsembleModelSpec,
    private val sourceLabel: String = "tree-ensemble-model"
) : AnomalyScorer {

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        if (!spec.isValid()) {
            return AnomalyScoreResult(
                score = 0.0,
                topFeatures = listOf("invalid_model"),
                featureContributions = emptyMap(),
                source = "$sourceLabel-invalid",
                confidence = 0.0,
                uncertainty = 1.0
            )
        }

        val featureValues = FeatureInputTransforms.apply(spec.inputTransform, window.portableFeatureMap())
        val orderedValues = spec.featureOrder.map { featureValues[it] ?: 0.0 }
        val contributions = linkedMapOf<String, Double>()
        var total = if (spec.aggregation == "log_odds_sum") spec.initialScore else 0.0
        var scoredTrees = 0

        spec.trees.forEach { tree ->
            val result = scoreTree(tree, orderedValues, contributions)
            if (result != null) {
                total += if (spec.aggregation == "log_odds_sum") spec.learningRate * result else result
                scoredTrees += 1
            }
        }

        val rawScore = when {
            scoredTrees <= 0 -> 0.0
            spec.aggregation == "log_odds_sum" -> sigmoid(total)
            else -> (total / scoredTrees).coerceIn(0.0, 1.0)
        }
        val effectiveThreshold = thresholdForApp(window.appId)
        val score = calibrateScore(rawScore, effectiveThreshold)
        val topFeatures = contributions.entries
            .sortedByDescending { it.value }
            .take(3)
            .map { it.key }
            .ifEmpty { listOf("tree_vote") }
        val thresholdDistance = abs(score - spec.recommendedThreshold).coerceIn(0.0, 1.0)
        val confidence = (0.50 + 0.50 * thresholdDistance).coerceIn(0.0, 1.0)

        return AnomalyScoreResult(
            score = score,
            topFeatures = topFeatures,
            featureContributions = contributions,
            source = sourceLabel,
            confidence = confidence,
            uncertainty = (1.0 - confidence).coerceIn(0.0, 1.0),
            diagnostics = mapOf(
                "recommended_threshold" to spec.recommendedThreshold,
                "effective_threshold" to effectiveThreshold,
                "threshold_distance" to thresholdDistance,
                "raw_score" to rawScore,
                "raw_margin" to total,
                "tree_count" to scoredTrees.toDouble()
            )
        )
    }

    private fun scoreTree(
        tree: TreeSpec,
        orderedValues: List<Double>,
        contributions: MutableMap<String, Double>
    ): Double? {
        var nodeIndex = 0
        var depth = 0
        while (nodeIndex >= 0 && nodeIndex < tree.nodes.size && depth < 64) {
            val node = tree.nodes[nodeIndex]
            if (node.left < 0 || node.right < 0 || node.featureIndex < 0) {
                return node.value
            }
            val featureValue = orderedValues.getOrNull(node.featureIndex) ?: 0.0
            val featureName = spec.featureOrder.getOrNull(node.featureIndex) ?: "feature_${node.featureIndex}"
            contributions[featureName] = (contributions[featureName] ?: 0.0) + abs(featureValue - node.threshold)
            nodeIndex = if (featureValue <= node.threshold) node.left else node.right
            depth += 1
        }
        return null
    }

    private fun thresholdForApp(appId: String): Double {
        spec.appIdThresholds[appId]?.let { return it }
        val family = deriveAppFamily(appId)
        return spec.appFamilyThresholds[family] ?: spec.recommendedThreshold
    }

    private fun calibrateScore(rawScore: Double, effectiveThreshold: Double): Double {
        return (rawScore * (spec.recommendedThreshold / effectiveThreshold.coerceIn(0.05, 1.0))).coerceIn(0.0, 1.0)
    }

    private fun sigmoid(value: Double): Double {
        return 1.0 / (1.0 + exp(-value))
    }

    private fun deriveAppFamily(appId: String): String {
        val normalized = appId.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')
        return when {
            normalized.startsWith("service_") -> "service"
            normalized.startsWith("uid_") -> "system"
            listOf("chrome", "firefox", "browser", "opera", "edge", "safari", "duckduckgo", "brave").any { it in normalized } -> "browser"
            listOf("analytics", "telemetry", "doubleclick", "googleads", "scorecardresearch", "tracking").any { it in normalized } -> "telemetry"
            listOf("vpn", "ssh", "rdp", "teamviewer", "anydesk", "openvpn", "ipsec", "l2tp").any { it in normalized } -> "remote_access"
            listOf("gmail", "outlook", "telegram", "whatsapp", "fbmessenger", "facebook", "instagram", "snapchat", "twitter", "tiktok", "spotify", "netflix", "youtube").any { it in normalized } -> "consumer_app"
            listOf("android", "systemui", "gms", "play_services", "packageinstaller").any { it in normalized } -> "system"
            listOf("background", "daemon", "worker", "sensor", "watersensor", "temp_humidity").any { it in normalized } -> "background"
            listOf("spy", "rat", "mal", "phish", "attack", "anomaly", "bot").any { it in normalized } -> "malware"
            else -> "other_app"
        }
    }
}
