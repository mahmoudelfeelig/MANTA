package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.security.CryptoUtils
import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.SecureSettingsStore
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class RemoteAssistedAnomalyScorer(
    private val settingsStore: SecureSettingsStore
) : AnomalyScorer {
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .writeTimeout(6, TimeUnit.SECONDS)
        .callTimeout(10, TimeUnit.SECONDS)
        .build()

    override fun score(window: FeatureWindow): AnomalyScoreResult {
        val config = settingsStore.readConfig()
        if (!config.isConfigured()) {
            return unavailable("backend_not_configured")
        }

        val baseUrl = config.backendUrl.toHttpUrlOrNull()
            ?.takeIf {
                it.scheme == "https" || (it.scheme == "http" && isLocalDevelopmentHost(it.host))
            }
            ?: return unavailable("invalid_backend_url")

        val requestUrl = baseUrl.newBuilder()
            .addPathSegments("api/v1/inference/window")
            .build()

        val deviceSalt = settingsStore.getDeviceSalt()
        val customPrivacy = config.customPrivacy
        val exportedAppId = when (config.privacyMode) {
            PrivacyMode.OFF -> window.appId
            PrivacyMode.LOW -> window.appId
            PrivacyMode.MEDIUM, PrivacyMode.STRICT -> CryptoUtils.sha256("$deviceSalt:${window.appId}")
            PrivacyMode.CUSTOM -> if (customPrivacy.includeAppId) window.appId else CryptoUtils.sha256("$deviceSalt:${window.appId}")
        }

        val payload = JSONObject()
            .put("device_id_pseudo", settingsStore.getPseudonymousDeviceId())
            .put("app_id", exportedAppId)
            .put(
                "site_hint",
                when (config.privacyMode) {
                    PrivacyMode.OFF, PrivacyMode.LOW -> window.siteHint
                    PrivacyMode.MEDIUM, PrivacyMode.STRICT -> null
                    PrivacyMode.CUSTOM -> window.siteHint.takeIf { customPrivacy.includeSiteHint }
                }
            )
            .put(
                "feature_window",
                featureWindowPayload(window)
            )
            .toString()

        val request = Request.Builder()
            .url(requestUrl)
            .addHeader("Authorization", "Bearer ${config.apiToken}")
            .addHeader("Content-Type", "application/json")
            .post(payload.toRequestBody(jsonMediaType))
            .build()

        return runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    error("Remote inference failed with status ${response.code}")
                }
                parseResponse(response.body?.string().orEmpty())
            }
        }.getOrElse { unavailable("remote_inference_failed") }
    }

    private fun featureWindowPayload(window: FeatureWindow): JSONObject {
        val features = window.portableFeatureMap()
        return JSONObject().apply {
            FeatureWindow.portableFeatureOrder.forEach { key ->
                put(key, features[key] ?: 0.0)
            }
            put("bytes_out", window.totalBytesOut)
            put("bytes_in", window.totalBytesIn)
            put("is_weekend", window.isWeekend)
        }
    }

    private fun parseResponse(rawJson: String): AnomalyScoreResult {
        val root = JSONObject(rawJson)
        val contributionsNode = root.optJSONObject("feature_contributions") ?: JSONObject()
        val contributions = buildMap {
            contributionsNode.keys().forEach { key ->
                put(key, contributionsNode.optDouble(key, 0.0))
            }
        }
        val topFeaturesNode = root.optJSONArray("top_features")
        val topFeatures = buildList {
            if (topFeaturesNode != null) {
                for (index in 0 until topFeaturesNode.length()) {
                    add(topFeaturesNode.optString(index))
                }
            }
        }

        return AnomalyScoreResult(
            score = root.optDouble("score", 0.0).coerceIn(0.0, 1.0),
            topFeatures = topFeatures,
            featureContributions = contributions,
            source = "remote_assisted",
            confidence = root.optDouble("confidence", 0.55).coerceIn(0.0, 1.0),
            uncertainty = root.optDouble("uncertainty", 0.45).coerceIn(0.0, 1.0),
            anomalyScore = root.optDouble("anomaly_score", root.optDouble("score", 0.0)).coerceIn(0.0, 1.0),
            contextScore = root.optDouble("context_score", 0.0).coerceIn(0.0, 1.0),
            responseScore = root.optDouble("response_score", root.optDouble("score", 0.0)).coerceIn(0.0, 1.0),
            diagnostics = buildMap {
                val diagnosticsNode = root.optJSONObject("diagnostics") ?: JSONObject()
                diagnosticsNode.keys().forEach { key ->
                    put(key, diagnosticsNode.optDouble(key, 0.0))
                }
            }
        )
    }

    private fun unavailable(reason: String): AnomalyScoreResult {
        return AnomalyScoreResult(
            score = 0.0,
            topFeatures = listOf(reason),
            featureContributions = emptyMap(),
            source = "remote_assisted_unavailable",
            confidence = 0.0,
            uncertainty = 1.0
        )
    }

    private fun isLocalDevelopmentHost(host: String): Boolean {
        val normalized = host.trim().lowercase()
        if (normalized.isBlank()) {
            return false
        }
        if (normalized == "localhost" || normalized == "::1" || normalized.endsWith(".local")) {
            return true
        }
        if (normalized.startsWith("127.") || normalized.startsWith("10.") || normalized.startsWith("192.168.")) {
            return true
        }
        if (normalized.startsWith("172.")) {
            val secondOctet = normalized.split('.').getOrNull(1)?.toIntOrNull()
            if (secondOctet != null && secondOctet in 16..31) {
                return true
            }
        }
        return false
    }
}
