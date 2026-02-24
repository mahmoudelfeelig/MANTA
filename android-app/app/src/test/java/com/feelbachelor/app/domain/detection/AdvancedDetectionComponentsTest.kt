package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.FeatureWindow
import com.feelbachelor.app.core.model.FlowProtocol
import com.feelbachelor.app.core.model.FlowRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdvancedDetectionComponentsTest {

    @Test
    fun periodicBeaconDetectorScoresRegularIntervalsHigher() {
        val detector = PeriodicBeaconDetector(minIntervals = 3, maxIntervals = 8)
        val base = 1_700_000_000_000L
        var score = 0.0
        repeat(6) { idx ->
            val flow = buildFlow(timestamp = base + (idx * 30_000L))
            score = detector.observe(flow)
        }
        assertTrue(score > 0.6)
    }

    @Test
    fun conceptDriftMonitorRaisesScoreAfterDistributionShift() {
        val monitor = ConceptDriftMonitor(minMatureSamples = 5, normalizer = 4.0)
        var stableScore = 0.0
        repeat(20) { idx ->
            stableScore = monitor.evaluate(buildWindow(bytesOut = 2_000L + idx, burstiness = 0.2)).score
        }

        var shiftedScore = 0.0
        repeat(6) {
            shiftedScore = monitor.evaluate(buildWindow(bytesOut = 80_000L, burstiness = 0.95)).score
        }

        assertTrue(shiftedScore > stableScore)
        assertTrue(shiftedScore > 0.35)
    }

    @Test
    fun dataQualityMonitorFlagsBrokenFlows() {
        val monitor = DataQualityMonitor()
        val broken = FlowRecord(
            id = "flow-bad",
            timestampStartMillis = 2_000L,
            timestampEndMillis = 1_000L,
            appId = "com.test",
            protocol = FlowProtocol.TCP,
            srcIp = "",
            srcPort = 1234,
            dstIp = "",
            dstPort = 443,
            bytesOut = 0,
            bytesIn = 0,
            packetsOut = 0,
            packetsIn = 0,
            durationMillis = -10L,
            destinationHash = "",
            destinationNovelty = 2.0
        )

        val result = monitor.evaluate(broken)
        assertTrue(result.score < 1.0)
        assertTrue(result.warnings.isNotEmpty())
    }

    @Test
    fun falsePositiveBudgetDowngradesSeverityWhenExceeded() {
        val manager = FalsePositiveBudgetManager()
        val decision = manager.apply(
            proposed = AlertSeverity.HIGH,
            falsePositivesInWindow = 20,
            budgetPerAppDay = 10
        )
        assertEquals(AlertSeverity.MEDIUM, decision.severity)
        assertTrue(decision.suppressionReason?.contains("false_positive_budget_exceeded") == true)
    }

    private fun buildFlow(timestamp: Long): FlowRecord {
        return FlowRecord(
            id = "flow-$timestamp",
            timestampStartMillis = timestamp - 1_000L,
            timestampEndMillis = timestamp,
            appId = "com.test",
            protocol = FlowProtocol.TCP,
            srcIp = "10.0.0.2",
            srcPort = 45_000,
            dstIp = "8.8.8.8",
            dstPort = 443,
            bytesOut = 1_000,
            bytesIn = 2_000,
            packetsOut = 2,
            packetsIn = 2,
            durationMillis = 1_000L,
            destinationHash = "dest-a",
            destinationNovelty = 0.1
        )
    }

    private fun buildWindow(bytesOut: Long, burstiness: Double): FeatureWindow {
        return FeatureWindow(
            id = "window-$bytesOut-$burstiness",
            appId = "com.test",
            windowStartMillis = 1_700_000_000_000L,
            windowEndMillis = 1_700_000_060_000L,
            flowCount = 12,
            totalBytesOut = bytesOut,
            totalBytesIn = 3_500L,
            meanPacketSize = 310.0,
            outboundRatio = 0.55,
            burstiness = burstiness,
            noveltyScore = 0.2,
            connectionFrequencyDelta = 1.4,
            periodicBeaconScore = 0.1,
            hourOfDay = 10,
            dayOfWeek = 2,
            isWeekend = false,
            dataQualityScore = 1.0,
            sampledByGuardrail = false,
            processingCostMillis = 2.0
        )
    }
}
