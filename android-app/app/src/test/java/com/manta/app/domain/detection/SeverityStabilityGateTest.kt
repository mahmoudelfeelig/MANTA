package com.manta.app.domain.detection

import com.manta.app.core.model.AlertSeverity
import org.junit.Assert.assertEquals
import org.junit.Test

class SeverityStabilityGateTest {
    @Test
    fun `requires consecutive high windows before emitting high`() {
        val gate = SeverityStabilityGate(requiredConsecutiveHigh = 3)
        val appId = "com.example"

        assertEquals(AlertSeverity.MEDIUM, gate.adjust(appId, AlertSeverity.HIGH))
        assertEquals(AlertSeverity.MEDIUM, gate.adjust(appId, AlertSeverity.HIGH))
        assertEquals(AlertSeverity.HIGH, gate.adjust(appId, AlertSeverity.HIGH))
    }

    @Test
    fun `low severity resets high streak`() {
        val gate = SeverityStabilityGate(requiredConsecutiveHigh = 2)
        val appId = "com.example.reset"

        assertEquals(AlertSeverity.MEDIUM, gate.adjust(appId, AlertSeverity.HIGH))
        assertEquals(AlertSeverity.LOW, gate.adjust(appId, AlertSeverity.LOW))
        assertEquals(AlertSeverity.MEDIUM, gate.adjust(appId, AlertSeverity.HIGH))
    }
}
