package com.feelbachelor.app.domain.flow

import com.feelbachelor.app.domain.detection.StatisticalAnomalyDetector
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowPipelineIntegrationTest {
    @Test
    fun `aggregated flows can be transformed into a scored feature window`() {
        val aggregator = FlowAggregator(flowIdleTimeoutMillis = 5)
        val builder = FeatureWindowBuilder()
        val detector = StatisticalAnomalyDetector()

        val start = 1_000_000L

        repeat(40) { idx ->
            aggregator.ingest(
                PacketMetadata(
                    timestampMillis = start + idx,
                    protocolCode = 6,
                    srcIp = "10.0.0.2",
                    srcPort = 40000 + (idx % 5),
                    dstIp = "8.8.8.${idx % 4 + 1}",
                    dstPort = 443,
                    bytes = 300,
                    outbound = true
                ),
                appId = "com.integration"
            )
        }

        val flows = aggregator.flushAll(start + 100)
        val window = builder.build(
            appId = "com.integration",
            flows = flows,
            windowStartMillis = start,
            windowEndMillis = start + 60_000
        )
        val score = detector.score(window)

        assertTrue(flows.isNotEmpty())
        assertTrue(score.score >= 0.0)
    }
}
