package com.manta.app.domain.detection

import com.manta.app.core.model.FlowRecord

data class DataQualityResult(
    val score: Double,
    val warnings: List<String>
)

class DataQualityMonitor {
    private val counters = mutableMapOf<String, Int>()

    @Synchronized
    fun evaluate(flow: FlowRecord): DataQualityResult {
        val warnings = mutableListOf<String>()

        if (flow.durationMillis <= 0) {
            warnings += "duration_non_positive"
        }
        if (flow.bytesOut == 0L && flow.bytesIn == 0L) {
            warnings += "zero_bytes_flow"
        }
        if (flow.srcPort !in 0..65535 || flow.dstPort !in 0..65535) {
            warnings += "invalid_port"
        }
        if (flow.timestampEndMillis < flow.timestampStartMillis) {
            warnings += "inverted_timestamps"
        }
        if (flow.destinationHash.isBlank()) {
            warnings += "missing_destination_hash"
        }
        if (flow.destinationNovelty !in 0.0..1.0) {
            warnings += "novelty_out_of_range"
        }

        warnings.forEach { warning ->
            counters[warning] = (counters[warning] ?: 0) + 1
        }

        val score = (1.0 - (warnings.size * 0.15)).coerceIn(0.0, 1.0)
        return DataQualityResult(score = score, warnings = warnings)
    }

    @Synchronized
    fun snapshotCounters(): Map<String, Int> = counters.toMap()
}

