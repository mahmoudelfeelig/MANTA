package com.manta.app.domain.flow

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.FlowRecord
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import kotlin.math.abs
import kotlin.math.ln
import kotlin.math.pow
import kotlin.math.sqrt

class FeatureWindowBuilder {
    fun build(
        appId: String,
        flows: List<FlowRecord>,
        windowStartMillis: Long,
        windowEndMillis: Long,
        siteHint: String? = null,
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
        val bytesPerFlow = (totalOut + totalIn).toDouble() / flowCount.toDouble()
        val durationSeconds = ((windowEndMillis - windowStartMillis).coerceAtLeast(1000L)) / 1000.0
        val byteRate = (totalOut + totalIn).toDouble() / durationSeconds
        val packetRate = packetCount.toDouble() / durationSeconds

        val perFlowBytes = flows.map { it.bytesOut + it.bytesIn }
        val mean = perFlowBytes.average().takeIf { !it.isNaN() } ?: 0.0
        val variance = perFlowBytes
            .map { value -> abs(value - mean) }
            .average()
            .takeIf { !it.isNaN() } ?: 0.0
        val normalizedBurstiness = if (mean > 0.0) {
            (variance / mean).coerceIn(0.0, 4.0)
        } else {
            0.0
        }

        val noveltyScore = flows.map { it.destinationNovelty }.average().takeIf { !it.isNaN() } ?: 0.0
        val connectionFrequencyDelta = ln(1.0 + (flows.size / durationSeconds))
        val uniqueDestinations = flows.map { it.destinationHash }.distinct().size.coerceAtLeast(1)
        val destinationDiversity = (uniqueDestinations.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val totalActiveMillis = flows.sumOf { it.durationMillis }
        val activityRatio = (totalActiveMillis.toDouble() / (windowEndMillis - windowStartMillis).coerceAtLeast(1L).toDouble())
            .coerceIn(0.0, 1.0)
        val perFlowDurations = flows.map { it.durationMillis.toDouble() }
        val meanDurationMillis = perFlowDurations.average().takeIf { !it.isNaN() } ?: 0.0
        val durationVariance = perFlowDurations
            .map { value -> (value - meanDurationMillis).pow(2) }
            .average()
            .takeIf { !it.isNaN() } ?: 0.0
        val durationJitter = sqrt(durationVariance)
        val portDiversity = (flows.map { it.dstPort }.distinct().size.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val protocolDiversity = (flows.map { it.protocol.name }.distinct().size.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val totalPacketsOut = flows.sumOf { it.packetsOut }
        val totalPacketsIn = flows.sumOf { it.packetsIn }
        val packetImbalance = (abs(totalPacketsOut - totalPacketsIn).toDouble() / (packetCount.toDouble() + 1.0)).coerceIn(0.0, 1.0)
        val smallFlowRatio = (flows.count { (it.bytesOut + it.bytesIn) <= 256L }.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val highPortRatio = (flows.count { it.dstPort >= 1024 }.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val ttlGap = flows.map { it.ttlGap }.average().takeIf { !it.isNaN() } ?: 0.0
        val ttlMetricsPresent = flows.map { it.ttlMetricsPresent }.average().takeIf { !it.isNaN() } ?: 0.0
        val synRateTotal = flows.map { it.synRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val rstRateTotal = flows.map { it.rstRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val ackRateTotal = flows.map { it.ackRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val finRateTotal = flows.map { it.finRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val pshRateTotal = flows.map { it.pshRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val fragmentRateTotal = flows.map { it.fragmentRateTotal }.average().takeIf { !it.isNaN() } ?: 0.0
        val tcpWindowMean = flows.map { it.tcpWindowMean }.average().takeIf { !it.isNaN() } ?: 0.0
        val ackDelayMean = flows.map { it.ackDelayMean }.average().takeIf { !it.isNaN() } ?: 0.0
        val interPacketGapMean = flows.map { it.interPacketGapMean }.average().takeIf { !it.isNaN() } ?: 0.0
        val payloadMean = flows.map { it.payloadMean }.average().takeIf { !it.isNaN() } ?: 0.0
        val loadMean = flows.map { it.loadMean }.average().takeIf { !it.isNaN() } ?: 0.0
        val transportMetricsPresent = flows.map { it.transportMetricsPresent }.average().takeIf { !it.isNaN() } ?: 0.0
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
            burstiness = normalizedBurstiness,
            noveltyScore = noveltyScore,
            connectionFrequencyDelta = connectionFrequencyDelta,
            bytesPerFlow = bytesPerFlow,
            destinationDiversity = destinationDiversity,
            activityRatio = activityRatio,
            byteRate = byteRate,
            packetRate = packetRate,
            meanDurationMillis = meanDurationMillis,
            durationJitter = durationJitter,
            portDiversity = portDiversity,
            protocolDiversity = protocolDiversity,
            packetImbalance = packetImbalance,
            smallFlowRatio = smallFlowRatio,
            highPortRatio = highPortRatio,
            siteHint = siteHint,
            periodicBeaconScore = periodicBeaconScore.coerceIn(0.0, 1.0),
            hourOfDay = hourOfDay,
            dayOfWeek = dayOfWeek,
            isWeekend = isWeekend,
            dataQualityScore = dataQualityScore.coerceIn(0.0, 1.0),
            ttlGap = ttlGap.coerceIn(0.0, 1.0),
            ttlMetricsPresent = ttlMetricsPresent.coerceIn(0.0, 1.0),
            synRateTotal = synRateTotal.coerceAtLeast(0.0),
            rstRateTotal = rstRateTotal.coerceAtLeast(0.0),
            ackRateTotal = ackRateTotal.coerceAtLeast(0.0),
            finRateTotal = finRateTotal.coerceAtLeast(0.0),
            pshRateTotal = pshRateTotal.coerceAtLeast(0.0),
            fragmentRateTotal = fragmentRateTotal.coerceAtLeast(0.0),
            tcpWindowMean = tcpWindowMean.coerceAtLeast(0.0),
            ackDelayMean = ackDelayMean.coerceAtLeast(0.0),
            interPacketGapMean = interPacketGapMean.coerceAtLeast(0.0),
            payloadMean = payloadMean.coerceAtLeast(0.0),
            loadMean = loadMean.coerceAtLeast(0.0),
            transportMetricsPresent = transportMetricsPresent.coerceIn(0.0, 1.0),
            sampledByGuardrail = sampledByGuardrail,
            processingCostMillis = processingCostMillis.coerceAtLeast(0.0)
        )
    }
}
