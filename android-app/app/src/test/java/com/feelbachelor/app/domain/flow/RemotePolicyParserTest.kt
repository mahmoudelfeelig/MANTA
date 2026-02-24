package com.feelbachelor.app.domain.flow

import com.feelbachelor.app.core.model.RemotePolicyParser
import org.junit.Assert.assertEquals
import org.junit.Test

class RemotePolicyParserTest {
    @Test
    fun `parses policy payload with app overrides`() {
        val raw = """
            {
              "status": "ok",
              "policy": {
                "policy_version": 3,
                "default_thresholds": {"medium": 0.5, "high": 0.8},
                "app_threshold_overrides": {
                  "com.test": {"medium": 0.45, "high": 0.7}
                },
                "export_enabled": true,
                "retention_days": 14
              }
            }
        """.trimIndent()

        val policy = RemotePolicyParser.parse(raw)

        assertEquals(3, policy.policyVersion)
        assertEquals(0.5, policy.defaultThresholds.medium, 0.0001)
        assertEquals(0.7, policy.appThresholdOverrides["com.test"]?.high ?: 0.0, 0.0001)
        assertEquals(14, policy.retentionDays)
    }
}
