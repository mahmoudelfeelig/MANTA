package com.manta.app.core.net

import com.manta.app.core.model.RemotePolicy

interface NetworkEventClient {
    suspend fun sendEvent(eventType: String, payload: String): Result<Unit>
    suspend fun sendBatch(eventType: String, payloads: List<String>): Result<Unit>
    suspend fun fetchRemotePolicy(deviceIdPseudo: String): Result<RemotePolicy>
    suspend fun pingBackend(): Result<String>
    suspend fun sendDeviceHeartbeat(deviceIdPseudo: String, deviceLabel: String): Result<String>
}
