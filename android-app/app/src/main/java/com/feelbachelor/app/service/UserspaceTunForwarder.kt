package com.feelbachelor.app.service

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

internal class UserspaceTunForwarder(
    private val vpnService: VpnService,
    tunFd: ParcelFileDescriptor,
    localVpnAddress: String,
    dispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    companion object {
        private const val TAG = "UserspaceTunForwarder"

        private const val PROTOCOL_TCP = 6
        private const val PROTOCOL_UDP = 17

        private const val TCP_FLAG_FIN = 0x01
        private const val TCP_FLAG_SYN = 0x02
        private const val TCP_FLAG_RST = 0x04
        private const val TCP_FLAG_PSH = 0x08
        private const val TCP_FLAG_ACK = 0x10

        private const val TCP_CONNECT_TIMEOUT_MS = 10_000
        private const val TCP_IDLE_TIMEOUT_MS = 180_000L
        private const val TCP_FORWARD_PAYLOAD_CHUNK = 1300

        private const val UDP_SOCKET_TIMEOUT_MS = 1_000
        private const val UDP_IDLE_TIMEOUT_MS = 90_000L

        private const val TUN_QUEUE_CAPACITY = 1_024
    }

    private val localVpnIpInt = ipv4ToInt(localVpnAddress)

    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val running = AtomicBoolean(true)

    private val tunOutput = FileOutputStream(tunFd.fileDescriptor)
    private val tunWriteLock = Any()

    private val inboundPackets = Channel<ByteArray>(
        capacity = TUN_QUEUE_CAPACITY,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    private val udpSessions = ConcurrentHashMap<UdpSessionKey, UdpSession>()
    private val tcpSessions = ConcurrentHashMap<TcpSessionKey, TcpSession>()

    init {
        scope.launch { processLoop() }
        scope.launch { cleanupLoop() }
    }

    fun forward(packet: ByteArray, length: Int) {
        if (!running.get() || length <= 0) {
            return
        }
        if (packet.size == length) {
            inboundPackets.trySend(packet)
        } else {
            inboundPackets.trySend(packet.copyOf(length))
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) {
            return
        }
        inboundPackets.close()

        udpSessions.values.forEach { session ->
            runCatching { session.socket.close() }
        }
        udpSessions.clear()

        tcpSessions.values.forEach { session ->
            runCatching { session.socket.close() }
            session.readerJob?.cancel()
        }
        tcpSessions.clear()

        runCatching { tunOutput.close() }
        scope.cancel()
    }

    private suspend fun processLoop() {
        for (packet in inboundPackets) {
            if (!running.get()) {
                break
            }
            val ipPacket = parseIpv4(packet) ?: continue

            when (ipPacket.protocol) {
                PROTOCOL_UDP -> handleUdp(ipPacket)
                PROTOCOL_TCP -> handleTcp(ipPacket)
            }
        }
    }

    private suspend fun cleanupLoop() {
        while (scope.isActive && running.get()) {
            val now = System.currentTimeMillis()

            udpSessions.entries
                .filter { now - it.value.lastSeenMs > UDP_IDLE_TIMEOUT_MS }
                .forEach { (key, session) ->
                    closeUdpSession(key, session)
                }

            tcpSessions.entries
                .filter { now - it.value.lastSeenMs > TCP_IDLE_TIMEOUT_MS }
                .forEach { (key, session) ->
                    closeTcpSession(key, session, "idle-timeout")
                }

            delay(5_000)
        }
    }

    private fun handleUdp(ipPacket: ParsedIpv4Packet) {
        val udp = parseUdp(ipPacket) ?: return
        val key = UdpSessionKey(
            clientPort = udp.sourcePort,
            serverIp = ipPacket.destinationIp,
            serverPort = udp.destinationPort
        )

        val session = udpSessions[key] ?: createUdpSession(key) ?: return
        session.lastSeenMs = System.currentTimeMillis()

        runCatching {
            val datagram = DatagramPacket(udp.payload, udp.payload.size)
            session.socket.send(datagram)
        }.onFailure { error ->
            Log.w(TAG, "UDP send failed for ${describeUdpKey(key)}: ${error.message}")
            closeUdpSession(key, session)
        }
    }

    private fun createUdpSession(key: UdpSessionKey): UdpSession? {
        val existing = udpSessions[key]
        if (existing != null) {
            return existing
        }

        val socket = DatagramSocket(null)
        return runCatching {
            socket.soTimeout = UDP_SOCKET_TIMEOUT_MS
            if (!vpnService.protect(socket)) {
                Log.w(TAG, "VpnService.protect(DatagramSocket) returned false for ${describeUdpKey(key)}")
            }
            val remote = InetSocketAddress(intToInetAddress(key.serverIp), key.serverPort)
            socket.connect(remote)

            val newSession = UdpSession(
                key = key,
                socket = socket,
                lastSeenMs = System.currentTimeMillis()
            )

            val race = udpSessions.putIfAbsent(key, newSession)
            if (race != null) {
                socket.close()
                race
            } else {
                scope.launch { readUdpResponses(newSession) }
                newSession
            }
        }.onFailure { error ->
            Log.w(TAG, "UDP session create failed for ${describeUdpKey(key)}: ${error.message}")
            runCatching { socket.close() }
        }.getOrNull()
    }

    private fun readUdpResponses(session: UdpSession) {
        val key = session.key
        val buffer = ByteArray(64 * 1024)

        while (running.get() && !session.socket.isClosed) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                session.socket.receive(packet)
                if (packet.length <= 0) {
                    continue
                }

                session.lastSeenMs = System.currentTimeMillis()

                val payload = packet.data.copyOf(packet.length)
                val response = buildUdpPacket(
                    sourceIp = key.serverIp,
                    destinationIp = localVpnIpInt,
                    sourcePort = key.serverPort,
                    destinationPort = key.clientPort,
                    payload = payload
                )
                writeToTun(response)
            } catch (_: SocketTimeoutException) {
                if (System.currentTimeMillis() - session.lastSeenMs > UDP_IDLE_TIMEOUT_MS) {
                    break
                }
            } catch (error: IOException) {
                if (running.get()) {
                    Log.w(TAG, "UDP receive failed for ${describeUdpKey(key)}: ${error.message}")
                }
                break
            }
        }

        closeUdpSession(key, session)
    }

    private fun closeUdpSession(key: UdpSessionKey, session: UdpSession) {
        if (udpSessions.remove(key, session)) {
            runCatching { session.socket.close() }
        }
    }

    private fun handleTcp(ipPacket: ParsedIpv4Packet) {
        val tcp = parseTcp(ipPacket) ?: return
        val key = TcpSessionKey(
            clientPort = tcp.sourcePort,
            serverIp = ipPacket.destinationIp,
            serverPort = tcp.destinationPort
        )

        val session = tcpSessions[key]
        if (session == null) {
            if (!tcp.hasFlag(TCP_FLAG_SYN)) {
                sendRstForUnknownSession(
                    ipPacket = ipPacket,
                    tcp = tcp
                )
                return
            }
            createTcpSession(key, ipPacket.sourceIp, tcp)
            return
        }

        session.lastSeenMs = System.currentTimeMillis()

        if (tcp.hasFlag(TCP_FLAG_RST)) {
            closeTcpSession(key, session, "client-rst")
            return
        }

        if (tcp.hasFlag(TCP_FLAG_SYN) && session.state != TcpState.CONNECTING) {
            // Client retransmitted SYN; reply with SYN/ACK again.
            val synAckSeq = previousSeq(session.forwarderNextSeq)
            sendTcpPacket(
                sourceIp = session.key.serverIp,
                destinationIp = session.clientIp,
                sourcePort = session.key.serverPort,
                destinationPort = session.key.clientPort,
                sequence = synAckSeq,
                acknowledgment = session.clientNextSeq,
                flags = TCP_FLAG_SYN or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            return
        }

        if (session.state == TcpState.CONNECTING) {
            return
        }

        if (session.state == TcpState.SYN_ACK_SENT && tcp.hasFlag(TCP_FLAG_ACK)) {
            val ackValid = tcp.acknowledgmentNumber == session.forwarderNextSeq
            if (ackValid) {
                session.state = TcpState.ESTABLISHED
            }
        }

        val consumedSequence = tcp.payload.isNotEmpty() || tcp.hasFlag(TCP_FLAG_FIN)
        if (consumedSequence) {
            val controlBytes = if (tcp.hasFlag(TCP_FLAG_FIN)) 1 else 0
            val increment = tcp.payload.size + controlBytes
            val expected = session.clientNextSeq
            if (tcp.sequenceNumber != expected) {
                sendTcpAck(session)
                return
            }
            session.clientNextSeq = nextSeq(session.clientNextSeq, increment)
        }

        if (tcp.payload.isNotEmpty()) {
            val wrote = runCatching {
                val output = session.socket.getOutputStream()
                output.write(tcp.payload)
            }.isSuccess

            if (!wrote) {
                sendTcpRst(session)
                closeTcpSession(key, session, "tcp-write-failed")
                return
            }

            if (session.state == TcpState.SYN_ACK_SENT) {
                session.state = TcpState.ESTABLISHED
            }
            sendTcpAck(session)
        }

        if (tcp.hasFlag(TCP_FLAG_FIN)) {
            session.clientClosed = true
            runCatching { session.socket.shutdownOutput() }
            sendTcpAck(session)

            if (session.remoteClosed && session.finAckedByClient) {
                closeTcpSession(key, session, "both-fin-complete")
                return
            }
        }

        if (session.finSentToClient && tcp.hasFlag(TCP_FLAG_ACK) && tcp.acknowledgmentNumber == session.forwarderNextSeq) {
            session.finAckedByClient = true
            if (session.clientClosed) {
                closeTcpSession(key, session, "remote-fin-acked")
            }
        }
    }

    private fun createTcpSession(key: TcpSessionKey, clientIp: Int, synSegment: ParsedTcpSegment) {
        val socket = Socket()
        val session = TcpSession(
            key = key,
            clientIp = clientIp,
            socket = socket,
            state = TcpState.CONNECTING,
            clientNextSeq = nextSeq(synSegment.sequenceNumber, 1),
            forwarderNextSeq = Random.nextLong(0, 0xFFFF_FFFFL),
            lastSeenMs = System.currentTimeMillis()
        )

        val race = tcpSessions.putIfAbsent(key, session)
        if (race != null) {
            runCatching { socket.close() }
            return
        }

        scope.launch {
            val connected = runCatching {
                if (!vpnService.protect(socket)) {
                    Log.w(TAG, "VpnService.protect(Socket) returned false for ${describeTcpKey(key)}")
                }
                socket.keepAlive = true
                socket.tcpNoDelay = true
                socket.connect(
                    InetSocketAddress(intToInetAddress(key.serverIp), key.serverPort),
                    TCP_CONNECT_TIMEOUT_MS
                )
            }.onFailure { error ->
                Log.w(TAG, "TCP connect failed for ${describeTcpKey(key)}: ${error.message}")
            }.isSuccess

            if (!connected) {
                sendTcpRst(session)
                closeTcpSession(key, session, "connect-failed")
                return@launch
            }

            session.state = TcpState.SYN_ACK_SENT
            sendTcpPacket(
                sourceIp = session.key.serverIp,
                destinationIp = session.clientIp,
                sourcePort = session.key.serverPort,
                destinationPort = session.key.clientPort,
                sequence = session.forwarderNextSeq,
                acknowledgment = session.clientNextSeq,
                flags = TCP_FLAG_SYN or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            session.forwarderNextSeq = nextSeq(session.forwarderNextSeq, 1)

            session.readerJob = scope.launch {
                readTcpResponses(key, session)
            }
        }
    }

    private fun readTcpResponses(key: TcpSessionKey, session: TcpSession) {
        val buffer = ByteArray(32 * 1024)

        try {
            val input = session.socket.getInputStream()
            while (running.get() && !session.socket.isClosed) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                if (read == 0) {
                    continue
                }

                session.lastSeenMs = System.currentTimeMillis()

                var offset = 0
                while (offset < read) {
                    val chunkSize = minOf(TCP_FORWARD_PAYLOAD_CHUNK, read - offset)
                    val payload = buffer.copyOfRange(offset, offset + chunkSize)
                    sendTcpPacket(
                        sourceIp = session.key.serverIp,
                        destinationIp = session.clientIp,
                        sourcePort = session.key.serverPort,
                        destinationPort = session.key.clientPort,
                        sequence = session.forwarderNextSeq,
                        acknowledgment = session.clientNextSeq,
                        flags = TCP_FLAG_ACK or TCP_FLAG_PSH,
                        payload = payload
                    )
                    session.forwarderNextSeq = nextSeq(session.forwarderNextSeq, chunkSize)
                    offset += chunkSize
                }
            }
        } catch (error: IOException) {
            if (running.get()) {
                Log.w(TAG, "TCP read failed for ${describeTcpKey(key)}: ${error.message}")
            }
        }

        session.remoteClosed = true
        if (!session.finSentToClient) {
            sendTcpPacket(
                sourceIp = session.key.serverIp,
                destinationIp = session.clientIp,
                sourcePort = session.key.serverPort,
                destinationPort = session.key.clientPort,
                sequence = session.forwarderNextSeq,
                acknowledgment = session.clientNextSeq,
                flags = TCP_FLAG_FIN or TCP_FLAG_ACK,
                payload = ByteArray(0)
            )
            session.forwarderNextSeq = nextSeq(session.forwarderNextSeq, 1)
            session.finSentToClient = true
        }

        if (session.clientClosed && session.finAckedByClient) {
            closeTcpSession(key, session, "both-fin-complete")
        }
    }

    private fun sendTcpAck(session: TcpSession) {
        sendTcpPacket(
            sourceIp = session.key.serverIp,
            destinationIp = session.clientIp,
            sourcePort = session.key.serverPort,
            destinationPort = session.key.clientPort,
            sequence = session.forwarderNextSeq,
            acknowledgment = session.clientNextSeq,
            flags = TCP_FLAG_ACK,
            payload = ByteArray(0)
        )
    }

    private fun sendTcpRst(session: TcpSession) {
        sendTcpPacket(
            sourceIp = session.key.serverIp,
            destinationIp = session.clientIp,
            sourcePort = session.key.serverPort,
            destinationPort = session.key.clientPort,
            sequence = session.forwarderNextSeq,
            acknowledgment = session.clientNextSeq,
            flags = TCP_FLAG_RST or TCP_FLAG_ACK,
            payload = ByteArray(0)
        )
    }

    private fun sendRstForUnknownSession(ipPacket: ParsedIpv4Packet, tcp: ParsedTcpSegment) {
        val ackIncrement = tcp.payload.size + if (tcp.hasFlag(TCP_FLAG_FIN) || tcp.hasFlag(TCP_FLAG_SYN)) 1 else 0
        val acknowledgment = nextSeq(tcp.sequenceNumber, ackIncrement)

        sendTcpPacket(
            sourceIp = ipPacket.destinationIp,
            destinationIp = ipPacket.sourceIp,
            sourcePort = tcp.destinationPort,
            destinationPort = tcp.sourcePort,
            sequence = 0,
            acknowledgment = acknowledgment,
            flags = TCP_FLAG_RST or TCP_FLAG_ACK,
            payload = ByteArray(0)
        )
    }

    private fun closeTcpSession(key: TcpSessionKey, session: TcpSession, reason: String) {
        if (tcpSessions.remove(key, session)) {
            runCatching { session.readerJob?.cancel() }
            runCatching { session.socket.close() }
            Log.i(TAG, "Closed TCP session ${describeTcpKey(key)} ($reason)")
        }
    }

    private fun sendTcpPacket(
        sourceIp: Int,
        destinationIp: Int,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Long,
        acknowledgment: Long,
        flags: Int,
        payload: ByteArray
    ) {
        val packet = buildTcpPacket(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            sequence = sequence,
            acknowledgment = acknowledgment,
            flags = flags,
            payload = payload
        )
        writeToTun(packet)
    }

    private fun writeToTun(packet: ByteArray) {
        if (!running.get()) {
            return
        }
        synchronized(tunWriteLock) {
            runCatching {
                tunOutput.write(packet)
            }.onFailure { error ->
                if (running.get()) {
                    Log.w(TAG, "TUN write failed: ${error.message}")
                }
            }
        }
    }

    private fun parseIpv4(packet: ByteArray): ParsedIpv4Packet? {
        if (packet.size < 20) {
            return null
        }
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) {
            return null
        }

        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (headerLength < 20 || packet.size < headerLength) {
            return null
        }

        val totalLength = readU16(packet, 2)
        val packetLength = minOf(totalLength, packet.size)
        if (packetLength < headerLength) {
            return null
        }

        val fragmentField = readU16(packet, 6)
        val fragmentOffset = fragmentField and 0x1FFF
        if (fragmentOffset != 0) {
            return null
        }

        return ParsedIpv4Packet(
            bytes = if (packetLength == packet.size) packet else packet.copyOf(packetLength),
            headerLength = headerLength,
            totalLength = packetLength,
            protocol = packet[9].toInt() and 0xFF,
            sourceIp = readIpv4Int(packet, 12),
            destinationIp = readIpv4Int(packet, 16)
        )
    }

    private fun parseUdp(ipPacket: ParsedIpv4Packet): ParsedUdpDatagram? {
        val offset = ipPacket.headerLength
        if (ipPacket.totalLength < offset + 8) {
            return null
        }
        val sourcePort = readU16(ipPacket.bytes, offset)
        val destinationPort = readU16(ipPacket.bytes, offset + 2)
        val udpLength = readU16(ipPacket.bytes, offset + 4)
        val payloadOffset = offset + 8
        val availablePayload = ipPacket.totalLength - payloadOffset
        val payloadLength = maxOf(0, minOf(availablePayload, udpLength - 8))
        val payload = if (payloadLength > 0) {
            ipPacket.bytes.copyOfRange(payloadOffset, payloadOffset + payloadLength)
        } else {
            ByteArray(0)
        }

        return ParsedUdpDatagram(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            payload = payload
        )
    }

    private fun parseTcp(ipPacket: ParsedIpv4Packet): ParsedTcpSegment? {
        val offset = ipPacket.headerLength
        if (ipPacket.totalLength < offset + 20) {
            return null
        }

        val sourcePort = readU16(ipPacket.bytes, offset)
        val destinationPort = readU16(ipPacket.bytes, offset + 2)
        val sequenceNumber = readU32(ipPacket.bytes, offset + 4)
        val acknowledgmentNumber = readU32(ipPacket.bytes, offset + 8)
        val tcpHeaderLength = ((ipPacket.bytes[offset + 12].toInt() ushr 4) and 0x0F) * 4
        if (tcpHeaderLength < 20 || ipPacket.totalLength < offset + tcpHeaderLength) {
            return null
        }

        val flags = ipPacket.bytes[offset + 13].toInt() and 0x3F
        val payloadOffset = offset + tcpHeaderLength
        val payloadLength = ipPacket.totalLength - payloadOffset
        val payload = if (payloadLength > 0) {
            ipPacket.bytes.copyOfRange(payloadOffset, payloadOffset + payloadLength)
        } else {
            ByteArray(0)
        }

        return ParsedTcpSegment(
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            sequenceNumber = sequenceNumber,
            acknowledgmentNumber = acknowledgmentNumber,
            flags = flags,
            payload = payload
        )
    }

    private fun buildUdpPacket(
        sourceIp: Int,
        destinationIp: Int,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLength = 20
        val udpHeaderLength = 8
        val totalLength = ipHeaderLength + udpHeaderLength + payload.size

        val packet = ByteArray(totalLength)

        packet[0] = 0x45
        packet[1] = 0
        writeU16(packet, 2, totalLength)
        writeU16(packet, 4, Random.nextInt(0, 0xFFFF))
        writeU16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = PROTOCOL_UDP.toByte()
        writeU16(packet, 10, 0)
        writeIpv4Int(packet, 12, sourceIp)
        writeIpv4Int(packet, 16, destinationIp)
        writeU16(packet, 10, ipChecksum(packet, 0, ipHeaderLength))

        val udpOffset = ipHeaderLength
        writeU16(packet, udpOffset, sourcePort)
        writeU16(packet, udpOffset + 2, destinationPort)
        writeU16(packet, udpOffset + 4, udpHeaderLength + payload.size)
        writeU16(packet, udpOffset + 6, 0)
        if (payload.isNotEmpty()) {
            payload.copyInto(packet, udpOffset + udpHeaderLength)
        }

        val checksum = transportChecksum(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = PROTOCOL_UDP,
            transport = packet,
            transportOffset = udpOffset,
            transportLength = udpHeaderLength + payload.size
        )
        writeU16(packet, udpOffset + 6, checksum)

        return packet
    }

    private fun buildTcpPacket(
        sourceIp: Int,
        destinationIp: Int,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Long,
        acknowledgment: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLength = 20
        val tcpHeaderLength = 20
        val totalLength = ipHeaderLength + tcpHeaderLength + payload.size

        val packet = ByteArray(totalLength)

        packet[0] = 0x45
        packet[1] = 0
        writeU16(packet, 2, totalLength)
        writeU16(packet, 4, Random.nextInt(0, 0xFFFF))
        writeU16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = PROTOCOL_TCP.toByte()
        writeU16(packet, 10, 0)
        writeIpv4Int(packet, 12, sourceIp)
        writeIpv4Int(packet, 16, destinationIp)
        writeU16(packet, 10, ipChecksum(packet, 0, ipHeaderLength))

        val tcpOffset = ipHeaderLength
        writeU16(packet, tcpOffset, sourcePort)
        writeU16(packet, tcpOffset + 2, destinationPort)
        writeU32(packet, tcpOffset + 4, sequence)
        writeU32(packet, tcpOffset + 8, acknowledgment)
        packet[tcpOffset + 12] = (tcpHeaderLength shl 2).toByte()
        packet[tcpOffset + 13] = (flags and 0x3F).toByte()
        writeU16(packet, tcpOffset + 14, 65_535)
        writeU16(packet, tcpOffset + 16, 0)
        writeU16(packet, tcpOffset + 18, 0)

        if (payload.isNotEmpty()) {
            payload.copyInto(packet, tcpOffset + tcpHeaderLength)
        }

        val checksum = transportChecksum(
            sourceIp = sourceIp,
            destinationIp = destinationIp,
            protocol = PROTOCOL_TCP,
            transport = packet,
            transportOffset = tcpOffset,
            transportLength = tcpHeaderLength + payload.size
        )
        writeU16(packet, tcpOffset + 16, checksum)

        return packet
    }

    private fun ipChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += readU16(data, i).toLong()
            i += 2
        }
        if (i < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8).toLong()
        }
        return finalizeChecksum(sum)
    }

    private fun transportChecksum(
        sourceIp: Int,
        destinationIp: Int,
        protocol: Int,
        transport: ByteArray,
        transportOffset: Int,
        transportLength: Int
    ): Int {
        var sum = 0L

        sum += (sourceIp ushr 16 and 0xFFFF).toLong()
        sum += (sourceIp and 0xFFFF).toLong()
        sum += (destinationIp ushr 16 and 0xFFFF).toLong()
        sum += (destinationIp and 0xFFFF).toLong()
        sum += protocol.toLong()
        sum += transportLength.toLong()

        var i = transportOffset
        val end = transportOffset + transportLength
        while (i + 1 < end) {
            sum += readU16(transport, i).toLong()
            i += 2
        }
        if (i < end) {
            sum += ((transport[i].toInt() and 0xFF) shl 8).toLong()
        }

        return finalizeChecksum(sum)
    }

    private fun finalizeChecksum(initialSum: Long): Int {
        var sum = initialSum
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun readU16(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private fun readU32(data: ByteArray, offset: Int): Long {
        return (
            ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
            ) and 0xFFFF_FFFFL
    }

    private fun writeU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = ((value ushr 24) and 0xFF).toByte()
        data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }

    private fun writeIpv4Int(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value ushr 24) and 0xFF).toByte()
        data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }

    private fun readIpv4Int(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
            ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or
            (data[offset + 3].toInt() and 0xFF)
    }

    private fun ipv4ToInt(ip: String): Int {
        val parts = ip.split('.')
        require(parts.size == 4) { "Invalid IPv4 address: $ip" }
        return (parts[0].toInt() shl 24) or
            (parts[1].toInt() shl 16) or
            (parts[2].toInt() shl 8) or
            parts[3].toInt()
    }

    private fun intToInetAddress(ip: Int): InetAddress {
        val bytes = byteArrayOf(
            ((ip ushr 24) and 0xFF).toByte(),
            ((ip ushr 16) and 0xFF).toByte(),
            ((ip ushr 8) and 0xFF).toByte(),
            (ip and 0xFF).toByte()
        )
        return InetAddress.getByAddress(bytes)
    }

    private fun nextSeq(current: Long, increment: Int): Long {
        return (current + increment.toLong()) and 0xFFFF_FFFFL
    }

    private fun previousSeq(current: Long): Long {
        return (current - 1L) and 0xFFFF_FFFFL
    }

    private data class ParsedIpv4Packet(
        val bytes: ByteArray,
        val headerLength: Int,
        val totalLength: Int,
        val protocol: Int,
        val sourceIp: Int,
        val destinationIp: Int
    )

    private data class ParsedUdpDatagram(
        val sourcePort: Int,
        val destinationPort: Int,
        val payload: ByteArray
    )

    private data class ParsedTcpSegment(
        val sourcePort: Int,
        val destinationPort: Int,
        val sequenceNumber: Long,
        val acknowledgmentNumber: Long,
        val flags: Int,
        val payload: ByteArray
    ) {
        fun hasFlag(flag: Int): Boolean = (flags and flag) != 0
    }

    private data class UdpSessionKey(
        val clientPort: Int,
        val serverIp: Int,
        val serverPort: Int
    )

    private data class UdpSession(
        val key: UdpSessionKey,
        val socket: DatagramSocket,
        var lastSeenMs: Long
    )

    private data class TcpSessionKey(
        val clientPort: Int,
        val serverIp: Int,
        val serverPort: Int
    )

    private data class TcpSession(
        val key: TcpSessionKey,
        val clientIp: Int,
        val socket: Socket,
        var state: TcpState,
        var clientNextSeq: Long,
        var forwarderNextSeq: Long,
        var lastSeenMs: Long,
        var remoteClosed: Boolean = false,
        var clientClosed: Boolean = false,
        var finSentToClient: Boolean = false,
        var finAckedByClient: Boolean = false,
        var readerJob: Job? = null
    )

    private enum class TcpState {
        CONNECTING,
        SYN_ACK_SENT,
        ESTABLISHED
    }

    private fun intToReadable(value: Int): String {
        return listOf(
            (value ushr 24) and 0xFF,
            (value ushr 16) and 0xFF,
            (value ushr 8) and 0xFF,
            value and 0xFF
        ).joinToString(".")
    }

    private fun describeUdpKey(key: UdpSessionKey): String {
        return "${key.clientPort}->${intToReadable(key.serverIp)}:${key.serverPort}/udp"
    }

    private fun describeTcpKey(key: TcpSessionKey): String {
        return "${key.clientPort}->${intToReadable(key.serverIp)}:${key.serverPort}/tcp"
    }
}
