package com.manta.app.domain.detection

import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.ThresholdProfile
import org.junit.Assert.assertEquals
import org.junit.Test

class ThresholdResolverTest {
    @Test
    fun `resolves severity using configurable thresholds`() {
        val profile = ThresholdProfile(medium = 0.55, high = 0.8)

        assertEquals(AlertSeverity.LOW, ThresholdResolver.resolveSeverity(0.4, profile))
        assertEquals(AlertSeverity.MEDIUM, ThresholdResolver.resolveSeverity(0.6, profile))
        assertEquals(AlertSeverity.HIGH, ThresholdResolver.resolveSeverity(0.9, profile))
    }
}
