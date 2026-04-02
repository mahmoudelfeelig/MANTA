package com.manta.app.core.model

data class PacketPipelineHealth(
    val packetsRead: Long,
    val activeFlows: Int,
    val parserFailure: Long,
    val forwardQueueDropped: Long,
    val analysisIngressDropped: Long,
    val analysisShardDropped: Long,
    val readToParseAvgMs: Double,
    val parseToShardAvgMs: Double,
    val shardToFlushAvgMs: Double,
    val flushToPersistAvgMs: Double
)

data class RuntimeHealth(
    val linearAvailable: Boolean,
    val tfliteAvailable: Boolean,
    val remoteConfigured: Boolean,
    val activeDetectionModel: String,
    val shadowModel: String?,
    val packetPipeline: PacketPipelineHealth
)
