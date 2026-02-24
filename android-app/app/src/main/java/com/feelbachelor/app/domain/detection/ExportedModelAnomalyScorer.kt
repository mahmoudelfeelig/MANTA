package com.feelbachelor.app.domain.detection

import android.content.Context
import com.feelbachelor.app.core.model.FeatureWindow
import org.json.JSONObject

class ExportedModelAnomalyScorer(
    private val context: Context,
    private val modelAssetPath: String = "models/anomaly-linear.json"
) : AnomalyScorer {

    private val scorer: LinearModelScorer? by lazy {
        runCatching {
            val jsonText = context.assets.open(modelAssetPath).bufferedReader(Charsets.UTF_8).use { it.readText() }
            val spec = parseSpec(jsonText)
            if (spec.isValid()) {
                LinearModelScorer(spec = spec, sourceLabel = "android-linear-model")
            } else {
                null
            }
        }.getOrNull()
    }

    fun isModelAvailable(): Boolean = scorer != null

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val scorer = scorer ?: return AnomalyScoreResult(
            score = 0.0,
            topFeatures = listOf("model_unavailable"),
            featureContributions = emptyMap(),
            source = "android-linear-unavailable"
        )
        return scorer.score(window)
    }

    private fun parseSpec(jsonText: String): LinearModelSpec {
        val root = JSONObject(jsonText)
        return LinearModelSpec(
            featureOrder = root.getJSONArray("feature_order").toStringList(),
            means = root.getJSONArray("means").toDoubleList(),
            scales = root.getJSONArray("scales").toDoubleList(),
            weights = root.getJSONArray("weights").toDoubleList(),
            bias = root.optDouble("bias", 0.0),
            recommendedThreshold = root.optDouble("recommended_threshold", 0.6)
        )
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
