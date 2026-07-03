package com.manta.app.domain.detection

import com.manta.app.core.model.FeatureWindow
import org.junit.Assert.assertTrue
import org.junit.Test

class StatisticalAnomalyDetectorTest {
    @Test
    fun `warmup dampens early spike scores`() {
        val detector = StatisticalAnomalyDetector()

        detector.score(
            FeatureWindow(
                id = "base-0",
                appId = "com.example",
                windowStartMillis = 0,
                windowEndMillis = 60_000,
                flowCount = 20,
                totalBytesOut = 10_000,
                totalBytesIn = 15_000,
                meanPacketSize = 250.0,
                outboundRatio = 0.4,
                burstiness = 10.0,
                noveltyScore = 0.1,
                connectionFrequencyDelta = 2.0
            )
        )

        val earlySpike = detector.score(
            FeatureWindow(
                id = "early-spike",
                appId = "com.example",
                windowStartMillis = 60_000,
                windowEndMillis = 120_000,
                flowCount = 200,
                totalBytesOut = 500_000,
                totalBytesIn = 1_000,
                meanPacketSize = 5_000.0,
                outboundRatio = 0.99,
                burstiness = 900.0,
                noveltyScore = 1.0,
                connectionFrequencyDelta = 40.0
            )
        )

        assertTrue(earlySpike.score < 0.6)
    }

    @Test
    fun `scores anomalous window higher than baseline`() {
        val detector = StatisticalAnomalyDetector()

        repeat(20) { idx ->
            detector.score(
                FeatureWindow(
                    id = "base-$idx",
                    appId = "com.example",
                    windowStartMillis = idx.toLong(),
                    windowEndMillis = idx.toLong() + 60_000,
                    flowCount = 20,
                    totalBytesOut = 10_000,
                    totalBytesIn = 15_000,
                    meanPacketSize = 250.0,
                    outboundRatio = 0.4,
                    burstiness = 10.0,
                    noveltyScore = 0.1,
                    connectionFrequencyDelta = 2.0
                )
            )
        }

        val anomalous = detector.score(
            FeatureWindow(
                id = "anomaly",
                appId = "com.example",
                windowStartMillis = 0,
                windowEndMillis = 60_000,
                flowCount = 200,
                totalBytesOut = 500_000,
                totalBytesIn = 1000,
                meanPacketSize = 5000.0,
                outboundRatio = 0.99,
                burstiness = 900.0,
                noveltyScore = 1.0,
                connectionFrequencyDelta = 40.0
            )
        )

        assertTrue(anomalous.score >= 0.6)
    }

    @Test
    fun `android risk floor prevents zero score during cold start`() {
        val detector = StatisticalAnomalyDetector()

        val riskyColdStart = detector.score(
            FeatureWindow(
                id = "cold-risk",
                appId = "com.example.browser",
                windowStartMillis = 0,
                windowEndMillis = 60_000,
                flowCount = 1,
                totalBytesOut = 900,
                totalBytesIn = 1_200,
                meanPacketSize = 300.0,
                outboundRatio = 0.5,
                burstiness = 0.1,
                noveltyScore = 0.42,
                connectionFrequencyDelta = 0.0,
                destinationRiskScore = 0.35,
                suspiciousDestinationRatio = 1.0,
                lookalikeScore = 0.40
            )
        )

        assertTrue(riskyColdStart.score > 0.0)
        assertTrue(riskyColdStart.topFeatures.contains("android_feature_risk_floor"))
        assertTrue((riskyColdStart.diagnostics["android_feature_risk_floor"] ?: 0.0) > 0.0)
    }
}
