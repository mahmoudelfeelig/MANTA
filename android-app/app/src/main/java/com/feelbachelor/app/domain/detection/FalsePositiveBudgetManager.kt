package com.feelbachelor.app.domain.detection

import com.feelbachelor.app.core.model.AlertSeverity

data class BudgetDecision(
    val severity: AlertSeverity,
    val suppressionReason: String?
)

class FalsePositiveBudgetManager {
    fun apply(
        proposed: AlertSeverity,
        falsePositivesInWindow: Int,
        budgetPerAppDay: Int
    ): BudgetDecision {
        if (proposed == AlertSeverity.LOW) {
            return BudgetDecision(proposed, null)
        }
        if (falsePositivesInWindow < budgetPerAppDay) {
            return BudgetDecision(proposed, null)
        }

        val downgraded = when (proposed) {
            AlertSeverity.HIGH -> AlertSeverity.MEDIUM
            AlertSeverity.MEDIUM -> AlertSeverity.LOW
            AlertSeverity.LOW -> AlertSeverity.LOW
        }
        val reason = "false_positive_budget_exceeded:${falsePositivesInWindow}/$budgetPerAppDay"
        return BudgetDecision(downgraded, reason)
    }
}

