package com.manta.app.domain.detection

import com.manta.app.core.model.AlertSeverity

/**
 * Prevents single-window spikes from immediately escalating to HIGH severity.
 *
 * HIGH is emitted only after a configurable streak of consecutive HIGH candidates.
 */
class SeverityStabilityGate(
    private val requiredConsecutiveHigh: Int = 3
) {
    private val highStreakByApp = mutableMapOf<String, Int>()

    @Synchronized
    fun adjust(appId: String, proposedSeverity: AlertSeverity): AlertSeverity {
        return when (proposedSeverity) {
            AlertSeverity.HIGH -> {
                val streak = (highStreakByApp[appId] ?: 0) + 1
                highStreakByApp[appId] = streak
                if (streak >= requiredConsecutiveHigh) {
                    AlertSeverity.HIGH
                } else {
                    AlertSeverity.MEDIUM
                }
            }

            AlertSeverity.MEDIUM -> {
                val decayed = ((highStreakByApp[appId] ?: 0) - 1).coerceAtLeast(0)
                highStreakByApp[appId] = decayed
                AlertSeverity.MEDIUM
            }

            AlertSeverity.LOW -> {
                highStreakByApp[appId] = 0
                AlertSeverity.LOW
            }
        }
    }
}
