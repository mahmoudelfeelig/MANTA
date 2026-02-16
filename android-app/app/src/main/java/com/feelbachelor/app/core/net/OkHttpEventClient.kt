package com.feelbachelor.app.core.net

import android.util.Log
import com.feelbachelor.app.core.settings.SecureSettingsStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
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
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        })
        .build()

    override suspend fun sendEvent(payload: String): Result<Unit> = withContext(Dispatchers.IO) {
        val config = settingsStore.readConfig()
        if (!config.exportEnabled || !config.isConfigured()) {
            return@withContext Result.failure(IllegalStateException("Export disabled or backend not configured"))
        }

        if (!config.backendUrl.startsWith("https://")) {
            return@withContext Result.failure(IllegalArgumentException("Insecure backend URL rejected"))
        }

        val request = Request.Builder()
            .url(config.backendUrl)
            .addHeader("Authorization", "Bearer ${config.apiToken}")
            .addHeader("Content-Type", "application/json")
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

    override suspend fun sendBatch(payloads: List<String>): Result<Unit> = withContext(Dispatchers.IO) {
        payloads.forEach { payload ->
            val result = sendEvent(payload)
            if (result.isFailure) {
                return@withContext result
            }
        }
        Result.success(Unit)
    }
}
