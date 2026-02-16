package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.ThresholdProfile

object ThresholdResolver {
    fun resolveSeverity(score: Double, profile: ThresholdProfile): AlertSeverity {
        return when {
            score >= profile.high -> AlertSeverity.HIGH
            score >= profile.medium -> AlertSeverity.MEDIUM
            else -> AlertSeverity.LOW
        }
    }
}
