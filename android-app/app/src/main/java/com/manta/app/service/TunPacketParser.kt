package com.manta.app.service

import com.manta.app.domain.flow.PacketMetadata
import java.nio.ByteBuffer
import java.nio.ByteOrder

class TunPacketParser(
    private val localVpnPrefix: String = "10.0.0."
) {
    fun parse(packet: ByteArray, length: Int, timestampMillis: Long): PacketMetadata? {
        if (length < 20) return null
        val version = (packet[0].toInt() shr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(packet, length, timestampMillis)
            6 -> parseIpv6(packet, length, timestampMillis)
            else -> null
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int, timestampMillis: Long): PacketMetadata? {
        val buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN)
        val ihl = (buffer.get(0).toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 4) return null

        val protocol = buffer.get(9).toInt() and 0xFF

        val srcIp = ipv4String(packet, 12)
        val dstIp = ipv4String(packet, 16)

        val (srcPort, dstPort) = parsePorts(packet, ihl, protocol)
        if (srcPort < 0 || dstPort < 0) return null

        val outbound = srcIp.startsWith(localVpnPrefix)

        return PacketMetadata(
            timestampMillis = timestampMillis,
            protocolCode = protocol,
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            bytes = length,
            outbound = outbound
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int, timestampMillis: Long): PacketMetadata? {
        if (length < 40) return null
        val protocol = packet[6].toInt() and 0xFF
        val srcIp = ipv6String(packet, 8)
        val dstIp = ipv6String(packet, 24)
        val (srcPort, dstPort) = parsePorts(packet, 40, protocol)
        if (srcPort < 0 || dstPort < 0) return null

        val outbound = srcIp.startsWith("fd") || srcIp.startsWith("fe80")

        return PacketMetadata(
            timestampMillis = timestampMillis,
            protocolCode = protocol,
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            bytes = length,
            outbound = outbound
        )
    }

    private fun parsePorts(packet: ByteArray, offset: Int, protocol: Int): Pair<Int, Int> {
        if (offset + 4 > packet.size) return -1 to -1
        return when (protocol) {
            6, 17 -> {
                val srcPort = ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
                val dstPort = ((packet[offset + 2].toInt() and 0xFF) shl 8) or (packet[offset + 3].toInt() and 0xFF)
                srcPort to dstPort
            }
            else -> -1 to -1
        }
    }

    private fun ipv4String(data: ByteArray, offset: Int): String {
        return listOf(
            data[offset].toInt() and 0xFF,
            data[offset + 1].toInt() and 0xFF,
            data[offset + 2].toInt() and 0xFF,
            data[offset + 3].toInt() and 0xFF
        ).joinToString(".")
    }

    private fun ipv6String(data: ByteArray, offset: Int): String {
        val hextets = (0 until 8).map { index ->
            val byteOffset = offset + index * 2
            val value = ((data[byteOffset].toInt() and 0xFF) shl 8) or (data[byteOffset + 1].toInt() and 0xFF)
            value.toString(16)
        }
        return hextets.joinToString(":")
    }
}
