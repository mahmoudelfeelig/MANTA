package com.manta.app.domain.detection

import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.ThresholdProfile

object ThresholdResolver {
    fun resolveSeverity(score: Double, profile: ThresholdProfile): AlertSeverity {
        return when {
            score >= profile.high -> AlertSeverity.HIGH
            score >= profile.medium -> AlertSeverity.MEDIUM
            else -> AlertSeverity.LOW
        }
    }
}
