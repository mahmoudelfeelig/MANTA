package com.manta.app.domain.detection

import android.content.Context
import com.manta.app.core.model.FeatureWindow
import org.json.JSONObject

class ExportedModelAnomalyScorer(
    private val context: Context,
    private val modelAssetPath: String = "models/anomaly-local.json"
) : AnomalyScorer {

    private data class ParsedExportedModel(
        val baseScorer: AnomalyScorer,
        val appFamilySpecialists: Map<String, SpecialistScorer>
    )

    private data class SpecialistScorer(
        val scorer: AnomalyScorer,
        val scoreScale: Double
    )

    private val model: ParsedExportedModel? by lazy {
        runCatching {
            val jsonText = context.assets.open(modelAssetPath).bufferedReader(Charsets.UTF_8).use { it.readText() }
            val root = JSONObject(jsonText)
            val baseScorer = parseScorer(root, "android") ?: return@runCatching null
            ParsedExportedModel(
                baseScorer = baseScorer,
                appFamilySpecialists = parseAppFamilySpecialists(root)
            )
        }.getOrNull()
    }

    fun isModelAvailable(): Boolean = model != null

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val parsed = model ?: return AnomalyScoreResult(
            score = 0.0,
            topFeatures = listOf("model_unavailable"),
            featureContributions = emptyMap(),
            source = "android-model-unavailable"
        )
        val family = deriveAppFamily(window.appId)
        val specialist = parsed.appFamilySpecialists[family]
        if (specialist != null) {
            val result = specialist.scorer.score(window)
            val scaledScore = (result.score * specialist.scoreScale).coerceIn(0.0, 1.0)
            return result.copy(
                score = scaledScore,
                source = "${result.source}-$family-specialist",
                diagnostics = result.diagnostics + mapOf("specialist_score_scale" to specialist.scoreScale),
                anomalyScore = scaledScore,
                responseScore = scaledScore
            )
        }
        return parsed.baseScorer.score(window)
    }

    private fun parseScorer(root: JSONObject, labelPrefix: String): AnomalyScorer? {
        return when (root.optString("model_type")) {
            "logistic_regression" -> {
                val spec = parseLinearSpec(root)
                if (spec.isValid()) LinearModelScorer(spec = spec, sourceLabel = "$labelPrefix-linear-model") else null
            }
            "random_forest_classifier", "boosted_tree_classifier" -> {
                val spec = parseTreeSpec(root)
                val label = if (root.optString("model_type") == "boosted_tree_classifier") {
                    "$labelPrefix-boosted-tree-model"
                } else {
                    "$labelPrefix-random-forest-model"
                }
                if (spec.isValid()) TreeEnsembleModelScorer(spec = spec, sourceLabel = label) else null
            }
            else -> null
        }
    }

    private fun parseLinearSpec(root: JSONObject): LinearModelSpec {
        return LinearModelSpec(
            featureOrder = root.getJSONArray("feature_order").toStringList(),
            means = root.getJSONArray("means").toDoubleList(),
            scales = root.getJSONArray("scales").toDoubleList(),
            weights = root.getJSONArray("weights").toDoubleList(),
            bias = root.optDouble("bias", 0.0),
            recommendedThreshold = root.optDouble("recommended_threshold", 0.6),
            appFamilyThresholds = parseThresholdOverrides(root, "app_family"),
            appIdThresholds = parseThresholdOverrides(root, "app_id"),
            inputTransform = root.optString("input_transform").takeIf { it.isNotBlank() }
        )
    }

    private fun parseTreeSpec(root: JSONObject): TreeEnsembleModelSpec {
        val treeArray = root.getJSONArray("trees")
        return TreeEnsembleModelSpec(
            featureOrder = root.getJSONArray("feature_order").toStringList(),
            trees = buildList {
                for (treeIndex in 0 until treeArray.length()) {
                    val treeRoot = treeArray.getJSONObject(treeIndex)
                    val nodeArray = treeRoot.getJSONArray("nodes")
                    add(
                        TreeSpec(
                            nodes = buildList {
                                for (nodeIndex in 0 until nodeArray.length()) {
                                    val node = nodeArray.getJSONObject(nodeIndex)
                                    add(
                                        TreeNodeSpec(
                                            featureIndex = node.optInt("feature_index", -1),
                                            threshold = node.optDouble("threshold", 0.0),
                                            left = node.optInt("left", -1),
                                            right = node.optInt("right", -1),
                                            value = node.optDouble("value", 0.0)
                                        )
                                    )
                                }
                            }
                        )
                    )
                }
            },
            recommendedThreshold = root.optDouble("recommended_threshold", 0.6),
            appFamilyThresholds = parseThresholdOverrides(root, "app_family"),
            appIdThresholds = parseThresholdOverrides(root, "app_id"),
            aggregation = root.optString("aggregation", "mean_positive_probability"),
            initialScore = root.optDouble("initial_score", 0.0),
            learningRate = root.optDouble("learning_rate", 1.0),
            inputTransform = root.optString("input_transform").takeIf { it.isNotBlank() }
        )
    }

    private fun parseThresholdOverrides(root: JSONObject, key: String): Map<String, Double> {
        val thresholdRoot = root.optJSONObject("threshold_overrides") ?: return emptyMap()
        val familyRoot = thresholdRoot.optJSONObject(key) ?: return emptyMap()
        return buildMap {
            familyRoot.keys().forEach { overrideKey ->
                put(overrideKey, familyRoot.optDouble(overrideKey).coerceIn(0.05, 1.0))
            }
        }
    }

    private fun parseAppFamilySpecialists(root: JSONObject): Map<String, SpecialistScorer> {
        val specialistsRoot = root.optJSONObject("specialists") ?: return emptyMap()
        val familyRoot = specialistsRoot.optJSONObject("app_family") ?: return emptyMap()
        return buildMap {
            familyRoot.keys().forEach { family ->
                val specialistRoot = familyRoot.optJSONObject(family) ?: return@forEach
                val specialistScorer = parseScorer(specialistRoot, "android-$family") ?: return@forEach
                put(
                    family,
                    SpecialistScorer(
                        scorer = specialistScorer,
                        scoreScale = specialistRoot.optDouble("score_scale", 1.0)
                    )
                )
            }
        }
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

    private fun org.json.JSONArray.toStringList(): List<String> {
        return buildList {
            for (index in 0 until length()) {
                add(optString(index))
            }
        }
    }

    private fun org.json.JSONArray.toDoubleList(): List<Double> {
        return buildList {
            for (index in 0 until length()) {
                add(optDouble(index))
            }
        }
    }
}
