package com.manta.app.service

import com.manta.app.domain.flow.PacketMetadata
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.min

class TunPacketParser(
    private val localVpnPrefix: String = "10.0.0."
) {
    private data class TransportDetails(
        val payloadOffset: Int? = null,
        val payloadBytes: Int = 0,
        val synFlag: Boolean = false,
        val rstFlag: Boolean = false,
        val ackFlag: Boolean = false,
        val finFlag: Boolean = false,
        val pshFlag: Boolean = false,
        val tcpWindowSize: Int? = null
    )

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
        val ttl = buffer.get(8).toInt() and 0xFF
        val flagsAndOffset = buffer.getShort(6).toInt() and 0xFFFF
        val fragmentOffset = flagsAndOffset and 0x1FFF
        val moreFragments = (flagsAndOffset and 0x2000) != 0
        val fragmented = moreFragments || fragmentOffset != 0

        val srcIp = ipv4String(packet, 12)
        val dstIp = ipv4String(packet, 16)

        val (srcPort, dstPort) = parsePorts(packet, ihl, protocol)
        if (srcPort < 0 || dstPort < 0) return null

        val outbound = srcIp.startsWith(localVpnPrefix)
        val transport = parseTransportDetails(packet, ihl, protocol, length)
        val hostHint = extractHostHint(packet, ihl, protocol, dstPort, length, outbound, transport.payloadOffset)

        return PacketMetadata(
            timestampMillis = timestampMillis,
            protocolCode = protocol,
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            bytes = length,
            outbound = outbound,
            hostHint = hostHint,
            payloadBytes = transport.payloadBytes,
            hopLimit = ttl,
            fragmented = fragmented,
            synFlag = transport.synFlag,
            rstFlag = transport.rstFlag,
            ackFlag = transport.ackFlag,
            finFlag = transport.finFlag,
            pshFlag = transport.pshFlag,
            tcpWindowSize = transport.tcpWindowSize
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int, timestampMillis: Long): PacketMetadata? {
        if (length < 40) return null
        val protocol = packet[6].toInt() and 0xFF
        val hopLimit = packet[7].toInt() and 0xFF
        val srcIp = ipv6String(packet, 8)
        val dstIp = ipv6String(packet, 24)
        val (srcPort, dstPort) = parsePorts(packet, 40, protocol)
        if (srcPort < 0 || dstPort < 0) return null

        val outbound = srcIp.startsWith("fd") || srcIp.startsWith("fe80")
        val transport = parseTransportDetails(packet, 40, protocol, length)
        val hostHint = extractHostHint(packet, 40, protocol, dstPort, length, outbound, transport.payloadOffset)

        return PacketMetadata(
            timestampMillis = timestampMillis,
            protocolCode = protocol,
            srcIp = srcIp,
            srcPort = srcPort,
            dstIp = dstIp,
            dstPort = dstPort,
            bytes = length,
            outbound = outbound,
            hostHint = hostHint,
            payloadBytes = transport.payloadBytes,
            hopLimit = hopLimit,
            fragmented = false,
            synFlag = transport.synFlag,
            rstFlag = transport.rstFlag,
            ackFlag = transport.ackFlag,
            finFlag = transport.finFlag,
            pshFlag = transport.pshFlag,
            tcpWindowSize = transport.tcpWindowSize
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

    private fun parseTransportDetails(packet: ByteArray, transportOffset: Int, protocol: Int, length: Int): TransportDetails {
        if (transportOffset >= length) {
            return TransportDetails()
        }
        return when (protocol) {
            6 -> parseTcpDetails(packet, transportOffset, length)
            17 -> parseUdpDetails(transportOffset, length)
            else -> TransportDetails()
        }
    }

    private fun parseTcpDetails(packet: ByteArray, transportOffset: Int, length: Int): TransportDetails {
        val payloadOffset = tcpPayloadOffset(packet, transportOffset, length) ?: return TransportDetails()
        if (transportOffset + 15 >= length) return TransportDetails(payloadOffset = payloadOffset)
        val flags = packet[transportOffset + 13].toInt() and 0xFF
        val windowSize = (((packet[transportOffset + 14].toInt() and 0xFF) shl 8) or (packet[transportOffset + 15].toInt() and 0xFF))
        return TransportDetails(
            payloadOffset = payloadOffset,
            payloadBytes = (length - payloadOffset).coerceAtLeast(0),
            synFlag = (flags and 0x02) != 0,
            rstFlag = (flags and 0x04) != 0,
            ackFlag = (flags and 0x10) != 0,
            finFlag = (flags and 0x01) != 0,
            pshFlag = (flags and 0x08) != 0,
            tcpWindowSize = windowSize
        )
    }

    private fun parseUdpDetails(transportOffset: Int, length: Int): TransportDetails {
        val payloadOffset = transportOffset + 8
        if (payloadOffset > length) {
            return TransportDetails()
        }
        return TransportDetails(
            payloadOffset = payloadOffset,
            payloadBytes = (length - payloadOffset).coerceAtLeast(0)
        )
    }

    private fun extractHostHint(
        packet: ByteArray,
        transportOffset: Int,
        protocol: Int,
        dstPort: Int,
        length: Int,
        outbound: Boolean,
        payloadOffsetHint: Int?
    ): String? {
        if (protocol != 6 || !outbound) return null
        val payloadOffset = payloadOffsetHint ?: tcpPayloadOffset(packet, transportOffset, length) ?: return null
        val payloadLength = length - payloadOffset
        if (payloadLength <= 0) return null
        val slice = packet.copyOfRange(payloadOffset, min(length, payloadOffset + min(payloadLength, 4096)))
        val port = dstPort
        return when (port) {
            80, 8080, 8000, 8888 -> parseHttpHost(slice)
            443, 8443, 9443, 10443 -> parseTlsClientHelloSni(slice)
            else -> parseTlsClientHelloSni(slice) ?: parseHttpHost(slice)
        }
    }

    private fun tcpPayloadOffset(packet: ByteArray, transportOffset: Int, length: Int): Int? {
        if (transportOffset + 13 >= length) return null
        val tcpHeaderLength = ((packet[transportOffset + 12].toInt() ushr 4) and 0x0F) * 4
        if (tcpHeaderLength < 20) return null
        val payloadOffset = transportOffset + tcpHeaderLength
        if (payloadOffset > length) return null
        return payloadOffset
    }

    private fun parseHttpHost(payload: ByteArray): String? {
        val text = payload.toString(Charsets.ISO_8859_1)
        val requestLike = text.startsWith("GET ") ||
            text.startsWith("POST ") ||
            text.startsWith("HEAD ") ||
            text.startsWith("PUT ") ||
            text.startsWith("DELETE ") ||
            text.startsWith("OPTIONS ") ||
            text.startsWith("PATCH ")
        if (!requestLike) return null
        return text.lineSequence()
            .firstOrNull { it.startsWith("Host:", ignoreCase = true) }
            ?.substringAfter(':')
            ?.trim()
            ?.removePrefix("www.")
            ?.takeIf { it.isNotBlank() }
    }

    private fun parseTlsClientHelloSni(payload: ByteArray): String? {
        if (payload.size < 11) return null
        if ((payload[0].toInt() and 0xFF) != 22) return null
        if ((payload[5].toInt() and 0xFF) != 1) return null

        var offset = 9
        if (offset + 34 > payload.size) return null
        offset += 2 // client_version
        offset += 32 // random

        val sessionIdLength = payload.getOrNull(offset)?.toInt()?.and(0xFF) ?: return null
        offset += 1 + sessionIdLength
        if (offset + 2 > payload.size) return null

        val cipherSuitesLength = readUInt16(payload, offset) ?: return null
        offset += 2 + cipherSuitesLength
        if (offset >= payload.size) return null

        val compressionMethodsLength = payload.getOrNull(offset)?.toInt()?.and(0xFF) ?: return null
        offset += 1 + compressionMethodsLength
        if (offset + 2 > payload.size) return null

        val extensionsLength = readUInt16(payload, offset) ?: return null
        offset += 2
        val extensionsEnd = min(payload.size, offset + extensionsLength)

        while (offset + 4 <= extensionsEnd) {
            val extensionType = readUInt16(payload, offset) ?: return null
            val extensionSize = readUInt16(payload, offset + 2) ?: return null
            offset += 4
            if (offset + extensionSize > extensionsEnd) return null
            if (extensionType == 0) {
                if (offset + 5 > extensionsEnd) return null
                val serverNameListLength = readUInt16(payload, offset) ?: return null
                var nameOffset = offset + 2
                val nameEnd = min(offset + 2 + serverNameListLength, offset + extensionSize)
                while (nameOffset + 3 <= nameEnd) {
                    val nameType = payload[nameOffset].toInt() and 0xFF
                    val nameLength = readUInt16(payload, nameOffset + 1) ?: return null
                    nameOffset += 3
                    if (nameOffset + nameLength > nameEnd) return null
                    if (nameType == 0) {
                        return payload.copyOfRange(nameOffset, nameOffset + nameLength)
                            .toString(Charsets.US_ASCII)
                            .trim()
                            .removePrefix("www.")
                            .takeIf { it.isNotBlank() }
                    }
                    nameOffset += nameLength
                }
            }
            offset += extensionSize
        }
        return null
    }

    private fun readUInt16(buffer: ByteArray, offset: Int): Int? {
        if (offset + 1 >= buffer.size) return null
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
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
