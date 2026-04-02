package com.manta.app.service

import com.manta.app.core.model.ProtocolEvidence
import com.manta.app.domain.flow.PacketMetadata
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
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

    fun parse(
        packet: ByteArray,
        length: Int,
        timestampMillis: Long,
        allowCertificateParsing: Boolean = true,
        allowHttpParsing: Boolean = true
    ): PacketMetadata? {
        if (length < 20) return null
        val version = (packet[0].toInt() shr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(packet, length, timestampMillis, allowCertificateParsing, allowHttpParsing)
            6 -> parseIpv6(packet, length, timestampMillis, allowCertificateParsing, allowHttpParsing)
            else -> null
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int, timestampMillis: Long, allowCertificateParsing: Boolean, allowHttpParsing: Boolean): PacketMetadata? {
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
        val protocolEvidence = inspectProtocolEvidence(
            packet = packet,
            transportOffset = ihl,
            protocol = protocol,
            srcPort = srcPort,
            dstPort = dstPort,
            length = length,
            outbound = outbound,
            payloadOffsetHint = transport.payloadOffset,
            allowCertificateParsing = allowCertificateParsing,
            allowHttpParsing = allowHttpParsing
        )
        val hostHint = protocolEvidence.preferredHost()

        return PacketMetadata(
            timestampMillis = timestampMillis,
            ipVersion = 4,
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
            tcpWindowSize = transport.tcpWindowSize,
            protocolEvidence = protocolEvidence
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int, timestampMillis: Long, allowCertificateParsing: Boolean, allowHttpParsing: Boolean): PacketMetadata? {
        if (length < 40) return null
        val protocol = packet[6].toInt() and 0xFF
        val hopLimit = packet[7].toInt() and 0xFF
        val srcIp = ipv6String(packet, 8)
        val dstIp = ipv6String(packet, 24)
        val (srcPort, dstPort) = parsePorts(packet, 40, protocol)
        if (srcPort < 0 || dstPort < 0) return null

        val outbound = srcIp.startsWith("fd") || srcIp.startsWith("fe80")
        val transport = parseTransportDetails(packet, 40, protocol, length)
        val protocolEvidence = inspectProtocolEvidence(
            packet = packet,
            transportOffset = 40,
            protocol = protocol,
            srcPort = srcPort,
            dstPort = dstPort,
            length = length,
            outbound = outbound,
            payloadOffsetHint = transport.payloadOffset,
            allowCertificateParsing = allowCertificateParsing,
            allowHttpParsing = allowHttpParsing
        )
        val hostHint = protocolEvidence.preferredHost()

        return PacketMetadata(
            timestampMillis = timestampMillis,
            ipVersion = 6,
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
            tcpWindowSize = transport.tcpWindowSize,
            protocolEvidence = protocolEvidence
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

    private fun inspectProtocolEvidence(
        packet: ByteArray,
        transportOffset: Int,
        protocol: Int,
        srcPort: Int,
        dstPort: Int,
        length: Int,
        outbound: Boolean,
        payloadOffsetHint: Int?,
        allowCertificateParsing: Boolean,
        allowHttpParsing: Boolean
    ): ProtocolEvidence {
        val payloadOffset = payloadOffsetHint ?: when (protocol) {
            6 -> tcpPayloadOffset(packet, transportOffset, length)
            17 -> transportOffset + 8
            else -> null
        } ?: return ProtocolEvidence()
        val payloadLength = length - payloadOffset
        if (payloadLength <= 0) return ProtocolEvidence()
        val slice = packet.copyOfRange(payloadOffset, min(length, payloadOffset + min(payloadLength, 8192)))

        var evidence = ProtocolEvidence()
        if (protocol == 17 && (srcPort == 53 || dstPort == 53)) {
            evidence = evidence.merge(parseDns(slice))
        }
        if (protocol == 6 && (srcPort == 53 || dstPort == 53)) {
            evidence = evidence.merge(parseTcpDns(slice))
        }
        if (protocol == 6) {
            if (outbound) {
                if (allowHttpParsing) {
                    evidence = evidence.merge(parseHttpRequest(slice))
                }
                evidence = evidence.merge(parseTlsClientHello(slice))
            } else if (allowCertificateParsing) {
                evidence = evidence.merge(parseTlsServerEvidence(slice))
            }
        }
        if (protocol == 17 && (srcPort == 443 || dstPort == 443)) {
            evidence = evidence.merge(parseQuicInitial(slice))
        }
        return evidence
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

    private fun parseDns(payload: ByteArray): ProtocolEvidence {
        if (payload.size < 12) return ProtocolEvidence()
        val flags = readUInt16(payload, 2) ?: return ProtocolEvidence()
        val qdCount = readUInt16(payload, 4) ?: return ProtocolEvidence()
        val anCount = readUInt16(payload, 6) ?: 0
        val rcode = flags and 0x0F
        val isResponse = (flags and 0x8000) != 0
        if (qdCount <= 0) {
            return ProtocolEvidence(dnsResponseCode = if (isResponse) rcode else null)
        }
        var offset = 12
        val (name, nextOffset) = parseDnsName(payload, offset) ?: return ProtocolEvidence(dnsResponseCode = if (isResponse) rcode else null)
        offset = nextOffset
        if (offset + 4 > payload.size) {
            return ProtocolEvidence(dnsQueryName = name, dnsResponseCode = if (isResponse) rcode else null)
        }
        val qtype = readUInt16(payload, offset)
        val answerValue = if (isResponse && anCount > 0) parseDnsAnswerValue(payload, offset + 4) else null
        return ProtocolEvidence(
            dnsQueryName = name,
            dnsQueryType = dnsTypeName(qtype),
            dnsResponseCode = if (isResponse) rcode else null,
            dnsAnswerValue = answerValue
        )
    }

    private fun parseTcpDns(payload: ByteArray): ProtocolEvidence {
        if (payload.size < 4) return ProtocolEvidence()
        val messageLength = readUInt16(payload, 0) ?: return ProtocolEvidence()
        if (messageLength <= 0 || 2 + messageLength > payload.size) {
            return ProtocolEvidence()
        }
        return parseDns(payload.copyOfRange(2, 2 + messageLength))
    }

    private fun parseDnsName(buffer: ByteArray, offsetStart: Int): Pair<String, Int>? {
        var offset = offsetStart
        val labels = mutableListOf<String>()
        while (offset < buffer.size) {
            val length = buffer[offset].toInt() and 0xFF
            if (length == 0) {
                return labels.joinToString(".") to (offset + 1)
            }
            if ((length and 0xC0) != 0 || offset + 1 + length > buffer.size) {
                return null
            }
            labels += buffer.copyOfRange(offset + 1, offset + 1 + length).toString(Charsets.US_ASCII)
            offset += 1 + length
        }
        return null
    }

    private fun skipDnsName(buffer: ByteArray, offsetStart: Int): Int? {
        var offset = offsetStart
        while (offset < buffer.size) {
            val length = buffer[offset].toInt() and 0xFF
            if (length == 0) {
                return offset + 1
            }
            if ((length and 0xC0) == 0xC0) {
                return offset + 2
            }
            if (offset + 1 + length > buffer.size) {
                return null
            }
            offset += 1 + length
        }
        return null
    }

    private fun dnsTypeName(type: Int?): String? = when (type) {
        1 -> "A"
        5 -> "CNAME"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        28 -> "AAAA"
        33 -> "SRV"
        65 -> "HTTPS"
        else -> type?.toString()
    }

    private fun parseDnsAnswerValue(buffer: ByteArray, offsetStart: Int): String? {
        var offset = offsetStart
        val nextOffset = skipDnsName(buffer, offset) ?: return null
        offset = nextOffset
        if (offset + 10 > buffer.size) return null
        val type = readUInt16(buffer, offset) ?: return null
        offset += 2
        offset += 2 // class
        offset += 4 // ttl
        val rdLength = readUInt16(buffer, offset) ?: return null
        offset += 2
        if (offset + rdLength > buffer.size) return null
        return when (type) {
            1 -> if (rdLength == 4) ipv4String(buffer, offset) else null
            28 -> if (rdLength == 16) ipv6String(buffer, offset) else null
            else -> null
        }
    }

    private fun parseHttpRequest(payload: ByteArray): ProtocolEvidence {
        val text = payload.toString(Charsets.ISO_8859_1)
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        val method = listOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH")
            .firstOrNull { firstLine.startsWith("$it ") } ?: return ProtocolEvidence()
        val rawPath = firstLine.substringAfter("$method ", "").substringBefore(' ').trim()
        val path = rawPath
            .substringBefore('?')
            .replace(Regex("""[^A-Za-z0-9/_\-.]"""), "_")
            .take(256)
            .ifBlank { null }
        val host = parseHttpHost(payload)
        return ProtocolEvidence(
            httpMethod = method,
            httpHost = host,
            httpPath = path
        )
    }

    private fun parseTlsClientHello(payload: ByteArray): ProtocolEvidence {
        if (payload.size < 11) return ProtocolEvidence()
        if ((payload[0].toInt() and 0xFF) != 22) return ProtocolEvidence()
        if ((payload[5].toInt() and 0xFF) != 1) return ProtocolEvidence()

        var offset = 9
        if (offset + 34 > payload.size) return ProtocolEvidence()
        val clientVersion = readUInt16(payload, offset)
        offset += 2
        offset += 32
        val sessionIdLength = payload.getOrNull(offset)?.toInt()?.and(0xFF) ?: return ProtocolEvidence()
        offset += 1 + sessionIdLength
        val cipherSuitesLength = readUInt16(payload, offset) ?: return ProtocolEvidence()
        offset += 2
        if (offset + cipherSuitesLength > payload.size) return ProtocolEvidence()
        val ciphers = mutableListOf<Int>()
        var cipherOffset = offset
        while (cipherOffset + 1 < offset + cipherSuitesLength) {
            ciphers += readUInt16(payload, cipherOffset) ?: break
            cipherOffset += 2
        }
        offset += cipherSuitesLength
        val compressionMethodsLength = payload.getOrNull(offset)?.toInt()?.and(0xFF) ?: return ProtocolEvidence()
        offset += 1 + compressionMethodsLength
        val extensionsLength = readUInt16(payload, offset) ?: return ProtocolEvidence()
        offset += 2
        val extensionsEnd = min(payload.size, offset + extensionsLength)

        val extensions = mutableListOf<Int>()
        val supportedGroups = mutableListOf<Int>()
        val ecPointFormats = mutableListOf<Int>()
        var sni: String? = null
        var alpn: String? = null

        while (offset + 4 <= extensionsEnd) {
            val extensionType = readUInt16(payload, offset) ?: break
            val extensionSize = readUInt16(payload, offset + 2) ?: break
            offset += 4
            if (offset + extensionSize > extensionsEnd) break
            extensions += extensionType
            when (extensionType) {
                0 -> sni = parseServerNameExtension(payload, offset, extensionSize)
                10 -> supportedGroups += parseSupportedGroups(payload, offset, extensionSize)
                11 -> ecPointFormats += parseEcPointFormats(payload, offset, extensionSize)
                16 -> alpn = parseAlpnExtension(payload, offset, extensionSize)
            }
            offset += extensionSize
        }

        val ja3Source = listOf(
            clientVersion?.toString().orEmpty(),
            ciphers.joinToString("-"),
            extensions.joinToString("-"),
            supportedGroups.joinToString("-"),
            ecPointFormats.joinToString("-")
        ).joinToString(",")

        return ProtocolEvidence(
            tlsSni = sni,
            tlsAlpn = alpn,
            tlsVersion = tlsVersionName(clientVersion),
            tlsJa3Like = sha256Hex(ja3Source)
        )
    }

    private fun parseTlsServerEvidence(payload: ByteArray): ProtocolEvidence {
        if (payload.size < 11) return ProtocolEvidence()
        if ((payload[0].toInt() and 0xFF) != 22) return ProtocolEvidence()
        val handshakeType = payload.getOrNull(5)?.toInt()?.and(0xFF) ?: return ProtocolEvidence()
        if (handshakeType != 11) return ProtocolEvidence()
        val tlsVersion = readUInt16(payload, 1)
        val certificateMetadata = parseTls12CertificateMetadata(payload)
        return ProtocolEvidence(
            tlsVersion = tlsVersionName(tlsVersion),
            tlsLeafSubject = certificateMetadata?.first,
            tlsLeafIssuer = certificateMetadata?.second,
            tlsLeafSan = certificateMetadata?.third
        )
    }

    private fun parseTls12CertificateMetadata(payload: ByteArray): Triple<String?, String?, String?>? {
        if (payload.size < 15) return null
        var offset = 9
        if (offset + 6 > payload.size) return null
        val certificateListLength = readUInt24(payload, offset + 3) ?: return null
        offset += 6
        val listEnd = min(payload.size, offset + certificateListLength)
        if (offset + 3 > listEnd) return null
        val certLength = readUInt24(payload, offset) ?: return null
        offset += 3
        if (offset + certLength > listEnd) return null
        return runCatching {
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(payload.copyOfRange(offset, offset + certLength).inputStream()) as X509Certificate
            val subject = certificate.subjectX500Principal.name
            val issuer = certificate.issuerX500Principal.name
            val san = certificate.subjectAlternativeNames
                ?.mapNotNull { entry -> entry.getOrNull(1)?.toString() }
                ?.joinToString("|")
            Triple(subject, issuer, san)
        }.getOrNull()
    }

    private fun parseQuicInitial(payload: ByteArray): ProtocolEvidence {
        if (payload.size < 7) return ProtocolEvidence()
        val first = payload[0].toInt() and 0xFF
        val longHeader = (first and 0x80) != 0
        if (!longHeader) return ProtocolEvidence()
        val packetType = (first ushr 4) and 0x03
        val version = readUInt32(payload, 1)
        val versionName = version?.let { "0x${it.toString(16)}" }
        val isInitial = packetType == 0
        val http3 = true
        return ProtocolEvidence(
            quicVersion = versionName,
            quicDetected = true,
            http3Detected = isInitial && http3
        )
    }

    private fun parseServerNameExtension(buffer: ByteArray, offset: Int, size: Int): String? {
        if (offset + size > buffer.size || size < 5) return null
        val listLength = readUInt16(buffer, offset) ?: return null
        var cursor = offset + 2
        val end = min(offset + 2 + listLength, offset + size)
        while (cursor + 3 <= end) {
            val nameType = buffer[cursor].toInt() and 0xFF
            val nameLength = readUInt16(buffer, cursor + 1) ?: return null
            cursor += 3
            if (cursor + nameLength > end) return null
            if (nameType == 0) {
                return buffer.copyOfRange(cursor, cursor + nameLength)
                    .toString(Charsets.US_ASCII)
                    .trim()
                    .removePrefix("www.")
                    .takeIf { it.isNotBlank() }
            }
            cursor += nameLength
        }
        return null
    }

    private fun parseSupportedGroups(buffer: ByteArray, offset: Int, size: Int): List<Int> {
        if (offset + size > buffer.size || size < 2) return emptyList()
        val listLength = readUInt16(buffer, offset) ?: return emptyList()
        val end = min(offset + 2 + listLength, offset + size)
        val values = mutableListOf<Int>()
        var cursor = offset + 2
        while (cursor + 1 < end) {
            values += readUInt16(buffer, cursor) ?: break
            cursor += 2
        }
        return values
    }

    private fun parseEcPointFormats(buffer: ByteArray, offset: Int, size: Int): List<Int> {
        if (offset + size > buffer.size || size < 1) return emptyList()
        val listLength = buffer[offset].toInt() and 0xFF
        val end = min(offset + 1 + listLength, offset + size)
        val values = mutableListOf<Int>()
        var cursor = offset + 1
        while (cursor < end) {
            values += buffer[cursor].toInt() and 0xFF
            cursor += 1
        }
        return values
    }

    private fun parseAlpnExtension(buffer: ByteArray, offset: Int, size: Int): String? {
        if (offset + size > buffer.size || size < 3) return null
        val listLength = readUInt16(buffer, offset) ?: return null
        var cursor = offset + 2
        val end = min(offset + 2 + listLength, offset + size)
        while (cursor < end) {
            val length = buffer[cursor].toInt() and 0xFF
            cursor += 1
            if (cursor + length > end) return null
            val protocol = buffer.copyOfRange(cursor, cursor + length).toString(Charsets.US_ASCII)
            if (protocol.isNotBlank()) {
                return protocol
            }
            cursor += length
        }
        return null
    }

    private fun tlsVersionName(value: Int?): String? = when (value) {
        0x0301 -> "TLS1.0"
        0x0302 -> "TLS1.1"
        0x0303 -> "TLS1.2"
        0x0304 -> "TLS1.3"
        else -> value?.let { "0x${it.toString(16)}" }
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return buildString(digest.size * 2) {
            digest.forEach { append("%02x".format(it)) }
        }
    }

    private fun readUInt24(buffer: ByteArray, offset: Int): Int? {
        if (offset + 2 >= buffer.size) return null
        return ((buffer[offset].toInt() and 0xFF) shl 16) or
            ((buffer[offset + 1].toInt() and 0xFF) shl 8) or
            (buffer[offset + 2].toInt() and 0xFF)
    }

    private fun readUInt32(buffer: ByteArray, offset: Int): Long? {
        if (offset + 3 >= buffer.size) return null
        return ((buffer[offset].toLong() and 0xFF) shl 24) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
            (buffer[offset + 3].toLong() and 0xFF)
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
