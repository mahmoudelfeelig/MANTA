package com.manta.app.domain.flow

data class PacketMetadata(
    val timestampMillis: Long,
    val protocolCode: Int,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val bytes: Int,
    val outbound: Boolean
)
