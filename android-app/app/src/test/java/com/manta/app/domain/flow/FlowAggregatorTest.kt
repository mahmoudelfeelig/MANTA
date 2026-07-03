package com.manta.app.domain.flow

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowAggregatorTest {
    @Test
    fun `flushes expired flow and computes novelty`() {
        val aggregator = FlowAggregator(flowIdleTimeoutMillis = 1)
        val now = 1_000_000L

        aggregator.ingest(
            PacketMetadata(
                timestampMillis = now,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 45000,
                dstIp = "8.8.8.8",
                dstPort = 443,
                bytes = 100,
                outbound = true
            ),
            appId = "com.example"
        )

        val flushed = aggregator.ingest(
            PacketMetadata(
                timestampMillis = now + 10,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 45000,
                dstIp = "1.1.1.1",
                dstPort = 443,
                bytes = 100,
                outbound = true
            ),
            appId = "com.example"
        )

        assertTrue(flushed.isNotEmpty())
        assertEquals(1.0, flushed.first().destinationNovelty, 0.001)
    }

    @Test
    fun `flushes long lived flow even when not idle`() {
        val aggregator = FlowAggregator(
            flowIdleTimeoutMillis = 60_000,
            flowMaxDurationMillis = 20
        )
        val start = 2_000_000L

        aggregator.ingest(
            PacketMetadata(
                timestampMillis = start,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 46000,
                dstIp = "9.9.9.9",
                dstPort = 443,
                bytes = 120,
                outbound = true
            ),
            appId = "com.example"
        )

        val flushed = aggregator.ingest(
            PacketMetadata(
                timestampMillis = start + 25,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 46000,
                dstIp = "9.9.9.9",
                dstPort = 443,
                bytes = 140,
                outbound = true
            ),
            appId = "com.example"
        )

        assertTrue(flushed.isNotEmpty())
    }

    @Test
    fun `propagates host hint into flushed flow`() {
        val aggregator = FlowAggregator(flowIdleTimeoutMillis = 1)
        val now = 3_000_000L

        aggregator.ingest(
            PacketMetadata(
                timestampMillis = now,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 47000,
                dstIp = "104.154.89.105",
                dstPort = 443,
                bytes = 180,
                outbound = true,
                hostHint = "expired.badssl.com"
            ),
            appId = "com.example.browser"
        )

        val flushed = aggregator.ingest(
            PacketMetadata(
                timestampMillis = now + 10,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 47001,
                dstIp = "1.1.1.1",
                dstPort = 443,
                bytes = 120,
                outbound = true
            ),
            appId = "com.example.browser"
        )

        assertTrue(flushed.isNotEmpty())
        assertEquals("expired.badssl.com", flushed.first().siteHint)
    }

    @Test
    fun `aggregates transport metrics into flushed flow`() {
        val aggregator = FlowAggregator(flowIdleTimeoutMillis = 1)
        val now = 4_000_000L

        aggregator.ingest(
            PacketMetadata(
                timestampMillis = now,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 48000,
                dstIp = "8.8.8.8",
                dstPort = 443,
                bytes = 160,
                outbound = true,
                payloadBytes = 120,
                hopLimit = 64,
                ackFlag = true,
                pshFlag = true,
                tcpWindowSize = 4096
            ),
            appId = "com.example.browser"
        )

        val flushed = aggregator.ingest(
            PacketMetadata(
                timestampMillis = now + 20,
                protocolCode = 6,
                srcIp = "10.0.0.2",
                srcPort = 48001,
                dstIp = "1.1.1.1",
                dstPort = 443,
                bytes = 120,
                outbound = true
            ),
            appId = "com.example.browser"
        )

        assertTrue(flushed.isNotEmpty())
        assertEquals(1.0, flushed.first().transportMetricsPresent, 0.001)
        assertEquals(1.0, flushed.first().ttlMetricsPresent, 0.001)
        assertEquals(1.0, flushed.first().ackRateTotal, 0.001)
        assertEquals(1.0, flushed.first().pshRateTotal, 0.001)
        assertEquals(4096.0, flushed.first().tcpWindowMean, 0.001)
        assertEquals(120.0, flushed.first().payloadMean, 0.001)
    }
}
