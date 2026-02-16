package com.feelbachelor.app.core.net

import com.feelbachelor.app.core.model.RemotePolicy

interface NetworkEventClient {
    suspend fun sendEvent(eventType: String, payload: String): Result<Unit>
    suspend fun sendBatch(eventType: String, payloads: List<String>): Result<Unit>
    suspend fun fetchRemotePolicy(deviceIdPseudo: String): Result<RemotePolicy>
}
