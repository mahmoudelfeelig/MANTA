package com.manta.app.domain.flow

data class PacketMetadata(
    val timestampMillis: Long,
    val protocolCode: Int,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val bytes: Int,
    val outbound: Boolean,
    val hostHint: String? = null,
    val payloadBytes: Int = 0,
    val hopLimit: Int? = null,
    val fragmented: Boolean = false,
    val synFlag: Boolean = false,
    val rstFlag: Boolean = false,
    val ackFlag: Boolean = false,
    val finFlag: Boolean = false,
    val pshFlag: Boolean = false,
    val tcpWindowSize: Int? = null
)
