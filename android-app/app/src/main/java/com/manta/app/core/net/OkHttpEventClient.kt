package com.manta.app.core.net

import android.util.Log
import com.manta.app.BuildConfig
import com.manta.app.core.model.RemotePolicy
import com.manta.app.core.model.RemotePolicyParser
import com.manta.app.core.settings.SecureSettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.logging.HttpLoggingInterceptor
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.json.JSONObject

private const val TAG = "OkHttpEventClient"

class OkHttpEventClient(
    private val settingsStore: SecureSettingsStore
) : NetworkEventClient {

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .writeTimeout(10, TimeUnit.SECONDS)
        .callTimeout(20, TimeUnit.SECONDS)
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = if (BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BASIC
            } else {
                HttpLoggingInterceptor.Level.NONE
            }
        })
        .build()

    override suspend fun sendEvent(eventType: String, payload: String): Result<Unit> = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (!config.exportEnabled || !config.isConfigured()) {
            return@withContext Result.failure(IllegalStateException("Export disabled or backend not configured"))
        }

        val endpointUrl = validateBackendUrl(settingsStore.getEventIngestUrl(eventType))
            ?: return@withContext Result.failure(IllegalArgumentException("Insecure or invalid backend URL rejected"))

        val request = Request.Builder()
            .url(endpointUrl)
            .addHeader("Authorization", "Bearer ${config.apiToken}")
            .addHeader("Content-Type", "application/json")
            .addHeader("X-Request-Id", UUID.randomUUID().toString())
            .post(payload.toRequestBody(jsonMediaType))
            .build()

        runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val bodyText = response.body?.string().orEmpty().replace('\n', ' ').trim()
                    val detail = bodyText.take(400).takeIf { it.isNotBlank() }
                    error(
                        buildString {
                            append("Backend rejected ")
                            append(eventType)
                            append(" with status ")
                            append(response.code)
                            if (detail != null) {
                                append(": ")
                                append(detail)
                            }
                        }
                    )
                }
            }
        }.onFailure {
            Log.w(TAG, "sendEvent failed: ${it.message}")
        }
    }

    override suspend fun sendBatch(eventType: String, payloads: List<String>): Result<Unit> = withContext(Dispatchers.IO) {
        payloads.forEach { payload ->
            val result = sendEvent(eventType = eventType, payload = payload)
            if (result.isFailure) {
                return@withContext result
            }
        }
        Result.success(Unit)
    }

    override suspend fun fetchRemotePolicy(deviceIdPseudo: String): Result<RemotePolicy> = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (!config.isConfigured()) {
            return@withContext Result.failure(IllegalStateException("Backend not configured"))
        }

        val policyUrl = validateBackendUrl(settingsStore.getPolicySyncUrl(deviceIdPseudo))
            ?: return@withContext Result.failure(IllegalArgumentException("Insecure or invalid policy URL rejected"))

        val request = Request.Builder()
            .url(policyUrl)
            .addHeader("Authorization", "Bearer ${config.apiToken}")
            .addHeader("X-Request-Id", UUID.randomUUID().toString())
            .get()
            .build()

        runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    error("Policy fetch failed with status ${response.code}")
                }
                val body = response.body?.string().orEmpty()
                RemotePolicyParser.parse(body)
            }
        }.onFailure {
            Log.w(TAG, "fetchRemotePolicy failed: ${it.message}")
        }
    }

    override suspend fun pingBackend(): Result<String> = withContext(Dispatchers.IO) {
        val healthUrl = validateBackendUrl(settingsStore.getHealthUrl())
            ?: return@withContext Result.failure(IllegalArgumentException("Insecure or invalid backend URL rejected"))
        val request = Request.Builder()
            .url(healthUrl)
            .addHeader("X-Request-Id", UUID.randomUUID().toString())
            .get()
            .build()

        runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    error("Server ping failed with status ${response.code}")
                }
                response.body?.string().orEmpty().ifBlank { "Server reachable" }
            }
        }.onFailure {
            Log.w(TAG, "pingBackend failed: ${it.message}")
        }
    }

    override suspend fun sendDeviceHeartbeat(deviceIdPseudo: String, deviceLabel: String): Result<String> = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (!config.isConfigured()) {
            return@withContext Result.failure(IllegalStateException("Backend not configured"))
        }

        val heartbeatUrl = validateBackendUrl(settingsStore.getDeviceHeartbeatUrl())
            ?: return@withContext Result.failure(IllegalArgumentException("Insecure or invalid backend URL rejected"))

        val payload = JSONObject()
            .put("device_id_pseudo", deviceIdPseudo)
            .put("device_label", deviceLabel)
            .put("capture_enabled", config.captureEnabled)
            .put("export_enabled", config.exportEnabled)
            .put("policy_version", config.policyVersion)
            .toString()

        val request = Request.Builder()
            .url(heartbeatUrl)
            .addHeader("Authorization", "Bearer ${config.apiToken}")
            .addHeader("Content-Type", "application/json")
            .addHeader("X-Request-Id", UUID.randomUUID().toString())
            .post(payload.toRequestBody(jsonMediaType))
            .build()

        runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    error("Device heartbeat failed with status ${response.code}")
                }
                response.body?.string().orEmpty().ifBlank { "Device presence refreshed" }
            }
        }.onFailure {
            Log.w(TAG, "sendDeviceHeartbeat failed: ${it.message}")
        }
    }

    private fun validateBackendUrl(raw: String): String? {
        val parsed = raw.toHttpUrlOrNull() ?: return null
        if (parsed.host.isBlank()) {
            return null
        }
        if (parsed.username.isNotBlank() || parsed.password.isNotBlank()) {
            return null
        }
        return when (parsed.scheme.lowercase()) {
            "https" -> parsed.toString()
            "http" -> if (isLocalDevelopmentHost(parsed.host)) parsed.toString() else null
            else -> null
        }
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
