package com.manta.app.domain.flow

import com.manta.app.core.model.FlowProtocol
import com.manta.app.core.model.FlowRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FeatureWindowBuilderTest {
    @Test
    fun `builds remote transport features from recent flows`() {
        val builder = FeatureWindowBuilder()
        val window = builder.build(
            appId = "com.example.browser",
            flows = listOf(
                FlowRecord(
                    id = "f1",
                    timestampStartMillis = 1_000L,
                    timestampEndMillis = 5_000L,
                    appId = "com.example.browser",
                    protocol = FlowProtocol.TCP,
                    srcIp = "10.0.0.2",
                    srcPort = 45_000,
                    dstIp = "8.8.8.8",
                    dstPort = 443,
                    bytesOut = 1_000,
                    bytesIn = 2_000,
                    packetsOut = 2,
                    packetsIn = 3,
                    durationMillis = 4_000L,
                    destinationHash = "dest-a",
                    destinationNovelty = 0.1,
                    ttlGap = 0.10,
                    ttlMetricsPresent = 1.0,
                    synRateTotal = 0.2,
                    rstRateTotal = 0.0,
                    ackRateTotal = 0.8,
                    finRateTotal = 0.1,
                    pshRateTotal = 0.2,
                    fragmentRateTotal = 0.0,
                    tcpWindowMean = 4096.0,
                    ackDelayMean = 12.0,
                    interPacketGapMean = 28.0,
                    payloadMean = 420.0,
                    loadMean = 750.0,
                    transportMetricsPresent = 1.0
                )
            ),
            windowStartMillis = 0L,
            windowEndMillis = 60_000L
        )

        assertEquals(0.10, window.ttlGap, 0.001)
        assertEquals(1.0, window.ttlMetricsPresent, 0.001)
        assertEquals(0.2, window.synRateTotal, 0.001)
        assertEquals(0.8, window.ackRateTotal, 0.001)
        assertEquals(4096.0, window.tcpWindowMean, 0.001)
        assertEquals(12.0, window.ackDelayMean, 0.001)
        assertEquals(28.0, window.interPacketGapMean, 0.001)
        assertEquals(420.0, window.payloadMean, 0.001)
        assertEquals(750.0, window.loadMean, 0.001)
        assertTrue(window.transportMetricsPresent > 0.9)
    }
}
