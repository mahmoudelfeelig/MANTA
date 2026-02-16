package com.feelbachelor.app.core.net

interface NetworkEventClient {
    suspend fun sendEvent(payload: String): Result<Unit>
    suspend fun sendBatch(payloads: List<String>): Result<Unit>
}
