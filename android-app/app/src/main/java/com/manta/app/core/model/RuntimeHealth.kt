package com.manta.app.core.model

data class RuntimeHealth(
    val linearAvailable: Boolean,
    val tfliteAvailable: Boolean,
    val remoteConfigured: Boolean,
    val activeDetectionModel: String,
    val shadowModel: String?
)
