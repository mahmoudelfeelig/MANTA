package com.feelbachelor.app.core.net

import android.util.Log
import com.feelbachelor.app.BuildConfig
import com.feelbachelor.app.core.model.RemotePolicy
import com.feelbachelor.app.core.model.RemotePolicyParser
import com.feelbachelor.app.core.settings.SecureSettingsStore
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

        val endpointUrl = validateHttpsUrl(settingsStore.getEventIngestUrl(eventType))
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
                    error("Backend rejected event with status ${response.code}")
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

        val policyUrl = validateHttpsUrl(settingsStore.getPolicySyncUrl(deviceIdPseudo))
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

    private fun validateHttpsUrl(raw: String): String? {
        val parsed = raw.toHttpUrlOrNull() ?: return null
        if (parsed.scheme != "https") {
            return null
        }
        if (parsed.host.isBlank()) {
            return null
        }
        if (parsed.username.isNotBlank() || parsed.password.isNotBlank()) {
            return null
        }
        return parsed.toString()
    }
}
