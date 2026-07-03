package com.manta.app.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class TunPacketParserTest {
    @Test
    fun `extracts http host header as host hint`() {
        val parser = TunPacketParser()
        val payload = (
            "GET / HTTP/1.1\r\n" +
                "Host: badssl.com\r\n" +
                "User-Agent: test\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        val packet = buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(104, 154.toByte(), 89, 105),
            srcPort = 45000,
            dstPort = 80,
            payload = payload
        )

        val parsed = parser.parse(packet, packet.size, 1_700_000_000_000L)

        assertNotNull(parsed)
        assertEquals("badssl.com", parsed?.hostHint)
        assertEquals(64, parsed?.hopLimit)
        assertEquals(payload.size, parsed?.payloadBytes)
        assertEquals(true, parsed?.ackFlag)
        assertEquals(true, parsed?.pshFlag)
        assertEquals(4096, parsed?.tcpWindowSize)
    }

    @Test
    fun `extracts tcp header transport metrics and ipv4 fragmentation`() {
        val parser = TunPacketParser()
        val payload = "hello".toByteArray(Charsets.ISO_8859_1)
        val packet = buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 45001,
            dstPort = 443,
            payload = payload,
            ttl = 47,
            flags = 0x13,
            windowSize = 8192,
            fragmented = true
        )

        val parsed = parser.parse(packet, packet.size, 1_700_000_000_123L)

        assertNotNull(parsed)
        assertEquals(47, parsed?.hopLimit)
        assertEquals(true, parsed?.finFlag)
        assertEquals(true, parsed?.synFlag)
        assertEquals(true, parsed?.ackFlag)
        assertEquals(8192, parsed?.tcpWindowSize)
        assertEquals(true, parsed?.fragmented)
        assertEquals(payload.size, parsed?.payloadBytes)
    }

    private fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        ttl: Int = 64,
        flags: Int = 0x18,
        windowSize: Int = 4096,
        fragmented: Boolean = false
    ): ByteArray {
        val packet = ByteArray(20 + 20 + payload.size)
        packet[0] = 0x45
        packet[8] = ttl.toByte()
        packet[9] = 6
        if (fragmented) {
            packet[6] = 0x20
            packet[7] = 0x00
        }
        packet[12] = srcIp[0]
        packet[13] = srcIp[1]
        packet[14] = srcIp[2]
        packet[15] = srcIp[3]
        packet[16] = dstIp[0]
        packet[17] = dstIp[1]
        packet[18] = dstIp[2]
        packet[19] = dstIp[3]

        packet[20] = ((srcPort shr 8) and 0xFF).toByte()
        packet[21] = (srcPort and 0xFF).toByte()
        packet[22] = ((dstPort shr 8) and 0xFF).toByte()
        packet[23] = (dstPort and 0xFF).toByte()
        packet[32] = 0x50
        packet[33] = flags.toByte()
        packet[34] = ((windowSize shr 8) and 0xFF).toByte()
        packet[35] = (windowSize and 0xFF).toByte()

        payload.copyInto(packet, destinationOffset = 40)
        return packet
    }
}
