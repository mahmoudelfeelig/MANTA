package com.manta.app.domain.detection

import com.manta.app.core.model.FlowRecord
import kotlin.math.sqrt

private data class BeaconState(
    var lastTimestampMillis: Long = -1L,
    val intervals: ArrayDeque<Long> = ArrayDeque()
)

class PeriodicBeaconDetector(
    private val minIntervals: Int = 4,
    private val maxIntervals: Int = 12
) {
    private val states = mutableMapOf<String, BeaconState>()

    @Synchronized
    fun observe(flow: FlowRecord): Double {
        val key = "${flow.appId}|${flow.destinationHash}"
        val now = flow.timestampEndMillis
        val state = states.getOrPut(key) { BeaconState() }

        if (state.lastTimestampMillis > 0) {
            val delta = now - state.lastTimestampMillis
            if (delta > 0) {
                state.intervals.addLast(delta)
                while (state.intervals.size > maxIntervals) {
                    state.intervals.removeFirst()
                }
            }
        }
        state.lastTimestampMillis = now

        if (state.intervals.size < minIntervals) {
            return 0.0
        }

        val values = state.intervals.map { it.toDouble() }
        val mean = values.average()
        if (mean <= 0.0) {
            return 0.0
        }
        val variance = values.map { (it - mean) * (it - mean) }.average()
        val std = sqrt(variance)
        val cv = (std / mean).coerceAtLeast(0.0)

        // Favor regular periodicity in practical beacon ranges (~15s to 10min).
        val regularity = (1.0 - cv).coerceIn(0.0, 1.0)
        val rangeScore = when {
            mean < 15_000.0 -> (mean / 15_000.0).coerceIn(0.0, 1.0)
            mean > 600_000.0 -> (600_000.0 / mean).coerceIn(0.0, 1.0)
            else -> 1.0
        }

        return (0.75 * regularity + 0.25 * rangeScore).coerceIn(0.0, 1.0)
    }
}

