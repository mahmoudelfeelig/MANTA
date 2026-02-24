package com.feelbachelor.app.domain.flow

import com.feelbachelor.app.core.model.FeatureWindow
import com.feelbachelor.app.core.model.FlowRecord
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import kotlin.math.abs

class FeatureWindowBuilder {
    fun build(
        appId: String,
        flows: List<FlowRecord>,
        windowStartMillis: Long,
        windowEndMillis: Long,
        periodicBeaconScore: Double = 0.0,
        dataQualityScore: Double = 1.0,
        sampledByGuardrail: Boolean = false,
        processingCostMillis: Double = 0.0
    ): FeatureWindow {
        val flowCount = flows.size.coerceAtLeast(1)
        val totalOut = flows.sumOf { it.bytesOut }
        val totalIn = flows.sumOf { it.bytesIn }
        val packetCount = flows.sumOf { it.packetsOut + it.packetsIn }.coerceAtLeast(1)
        val avgPacketSize = (totalOut + totalIn).toDouble() / packetCount.toDouble()
        val outboundRatio = totalOut.toDouble() / (totalOut + totalIn + 1)

        val perFlowBytes = flows.map { it.bytesOut + it.bytesIn }
        val mean = perFlowBytes.average().takeIf { !it.isNaN() } ?: 0.0
        val variance = perFlowBytes
            .map { value -> abs(value - mean) }
            .average()
            .takeIf { !it.isNaN() } ?: 0.0

        val noveltyScore = flows.map { it.destinationNovelty }.average().takeIf { !it.isNaN() } ?: 0.0
        val durationSeconds = ((windowEndMillis - windowStartMillis).coerceAtLeast(1000L)) / 1000.0
        val connectionFrequencyDelta = flows.size / durationSeconds
        val zoned = Instant.ofEpochMilli(windowEndMillis).atZone(ZoneId.systemDefault())
        val hourOfDay = zoned.hour
        val dayOfWeek = zoned.dayOfWeek.value
        val isWeekend = dayOfWeek >= 6

        return FeatureWindow(
            id = UUID.randomUUID().toString(),
            appId = appId,
            windowStartMillis = windowStartMillis,
            windowEndMillis = windowEndMillis,
            flowCount = flowCount,
            totalBytesOut = totalOut,
            totalBytesIn = totalIn,
            meanPacketSize = avgPacketSize,
            outboundRatio = outboundRatio,
            burstiness = variance,
            noveltyScore = noveltyScore,
            connectionFrequencyDelta = connectionFrequencyDelta,
            periodicBeaconScore = periodicBeaconScore.coerceIn(0.0, 1.0),
            hourOfDay = hourOfDay,
            dayOfWeek = dayOfWeek,
            isWeekend = isWeekend,
            dataQualityScore = dataQualityScore.coerceIn(0.0, 1.0),
            sampledByGuardrail = sampledByGuardrail,
            processingCostMillis = processingCostMillis.coerceAtLeast(0.0)
        )
    }
}
