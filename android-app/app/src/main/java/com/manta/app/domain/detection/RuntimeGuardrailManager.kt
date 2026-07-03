package com.manta.app.domain.detection

import android.content.Context
import android.os.BatteryManager
import android.os.PowerManager
import kotlin.math.roundToInt

data class GuardrailDecision(
    val processDetection: Boolean,
    val sampled: Boolean,
    val sampleFactor: Int,
    val reason: String?
)

class RuntimeGuardrailManager {
    private var sequence: Long = 0
    private var emaProcessingCostMillis: Double = 0.0

    @Synchronized
    fun recordProcessingCost(costMillis: Double) {
        val bounded = costMillis.coerceAtLeast(0.0)
        emaProcessingCostMillis = if (emaProcessingCostMillis == 0.0) {
            bounded
        } else {
            0.2 * bounded + 0.8 * emaProcessingCostMillis
        }
    }

    @Synchronized
    fun decide(
        context: Context,
        pendingExportQueue: Int
    ): GuardrailDecision {
        sequence += 1
        val battery = batteryPercent(context)
        val powerSave = isPowerSave(context)
        var sampleFactor = 1
        var reason: String? = null

        if (powerSave || battery in 0..20) {
            sampleFactor = maxOf(sampleFactor, 3)
            reason = "battery_guardrail"
        }
        if (pendingExportQueue >= 400) {
            sampleFactor = maxOf(sampleFactor, 2)
            reason = "queue_backpressure"
        }
        if (emaProcessingCostMillis >= 25.0) {
            sampleFactor = maxOf(sampleFactor, 2)
            reason = "cpu_cost_guardrail"
        }

        if (sampleFactor <= 1) {
            return GuardrailDecision(
                processDetection = true,
                sampled = false,
                sampleFactor = 1,
                reason = null
            )
        }
        val process = (sequence % sampleFactor.toLong()) == 0L
        return GuardrailDecision(
            processDetection = process,
            sampled = true,
            sampleFactor = sampleFactor,
            reason = reason
        )
    }

    @Synchronized
    fun diagnostics(): Map<String, Double> = mapOf(
        "ema_processing_cost_ms" to ((emaProcessingCostMillis * 100.0).roundToInt() / 100.0)
    )

    private fun batteryPercent(context: Context): Int {
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager ?: return -1
        return bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
    }

    private fun isPowerSave(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return pm.isPowerSaveMode
    }
}

