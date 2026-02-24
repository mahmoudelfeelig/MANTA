package com.feelbachelor.app.domain.flow

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
}
