package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.FeatureWindow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LinearModelScorerTest {
    private fun sampleWindow(): FeatureWindow {
        return FeatureWindow(
            id = "w1",
            appId = "com.test",
            windowStartMillis = 1000,
            windowEndMillis = 2000,
            flowCount = 120,
            totalBytesOut = 240000,
            totalBytesIn = 6000,
            meanPacketSize = 3800.0,
            outboundRatio = 0.96,
            burstiness = 7500.0,
            noveltyScore = 1.0,
            connectionFrequencyDelta = 18.0
        )
    }

    @Test
    fun score_returns_bounded_value_and_top_features() {
        val spec = LinearModelSpec(
            featureOrder = listOf(
                "flow_count",
                "bytes_out",
                "bytes_in",
                "mean_packet_size",
                "outbound_ratio",
                "burstiness",
                "novelty",
                "conn_freq_delta"
            ),
            means = listOf(20.0, 50000.0, 90000.0, 500.0, 0.5, 1200.0, 0.1, 0.4),
            scales = listOf(25.0, 90000.0, 140000.0, 500.0, 0.25, 3000.0, 0.2, 1.1),
            weights = listOf(0.25, 0.2, -0.1, 0.1, 0.45, 0.3, 0.5, 0.3),
            bias = -0.9,
            recommendedThreshold = 0.6
        )

        val scorer = LinearModelScorer(spec)
        val result = scorer.score(sampleWindow())

        assertTrue(result.score in 0.0..1.0)
        assertEquals("linear-model", result.source)
        assertEquals(3, result.topFeatures.size)
    }

    @Test
    fun invalid_spec_returns_safe_result() {
        val invalid = LinearModelSpec(
            featureOrder = listOf("flow_count"),
            means = listOf(1.0),
            scales = listOf(),
            weights = listOf(1.0),
            bias = 0.0,
            recommendedThreshold = 0.5
        )
        val scorer = LinearModelScorer(invalid)

        val result = scorer.score(sampleWindow())
        assertEquals(0.0, result.score, 1e-9)
        assertEquals("linear-model-invalid", result.source)
    }
}
