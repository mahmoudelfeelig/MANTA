package com.manta.app.domain.flow

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.FlowRecord
import java.time.Instant
import java.time.ZoneId
import java.util.UUID
import kotlin.math.abs
import kotlin.math.ln
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
        var totalOut = 0L
        var totalIn = 0L
        var packetCountRaw = 0
        var totalFlowBytes = 0L
        var totalActiveMillis = 0L
        var noveltySum = 0.0
        var ttlGapSum = 0.0
        var ttlMetricsPresentSum = 0.0
        var synRateTotalSum = 0.0
        var rstRateTotalSum = 0.0
        var ackRateTotalSum = 0.0
        var finRateTotalSum = 0.0
        var pshRateTotalSum = 0.0
        var fragmentRateTotalSum = 0.0
        var tcpWindowMeanSum = 0.0
        var ackDelayMeanSum = 0.0
        var interPacketGapMeanSum = 0.0
        var payloadMeanSum = 0.0
        var loadMeanSum = 0.0
        var transportMetricsPresentSum = 0.0
        var totalPacketsOut = 0
        var totalPacketsIn = 0
        var smallFlowCount = 0
        var highPortCount = 0
        val destinations = HashSet<String>()
        val ports = HashSet<Int>()
        val protocols = HashSet<String>()

        flows.forEach { flow ->
            val flowBytes = flow.bytesOut + flow.bytesIn
            totalOut += flow.bytesOut
            totalIn += flow.bytesIn
            totalFlowBytes += flowBytes
            packetCountRaw += flow.packetsOut + flow.packetsIn
            totalPacketsOut += flow.packetsOut
            totalPacketsIn += flow.packetsIn
            totalActiveMillis += flow.durationMillis
            noveltySum += flow.destinationNovelty
            ttlGapSum += flow.ttlGap
            ttlMetricsPresentSum += flow.ttlMetricsPresent
            synRateTotalSum += flow.synRateTotal
            rstRateTotalSum += flow.rstRateTotal
            ackRateTotalSum += flow.ackRateTotal
            finRateTotalSum += flow.finRateTotal
            pshRateTotalSum += flow.pshRateTotal
            fragmentRateTotalSum += flow.fragmentRateTotal
            tcpWindowMeanSum += flow.tcpWindowMean
            ackDelayMeanSum += flow.ackDelayMean
            interPacketGapMeanSum += flow.interPacketGapMean
            payloadMeanSum += flow.payloadMean
            loadMeanSum += flow.loadMean
            transportMetricsPresentSum += flow.transportMetricsPresent
            destinations += flow.destinationHash
            ports += flow.dstPort
            protocols += flow.protocol.name
            if (flowBytes <= 256L) smallFlowCount += 1
            if (flow.dstPort >= 1024) highPortCount += 1
        }

        val packetCount = packetCountRaw.coerceAtLeast(1)
        val avgPacketSize = (totalOut + totalIn).toDouble() / packetCount.toDouble()
        val outboundRatio = totalOut.toDouble() / (totalOut + totalIn + 1)
        val bytesPerFlow = (totalOut + totalIn).toDouble() / flowCount.toDouble()
        val durationSeconds = ((windowEndMillis - windowStartMillis).coerceAtLeast(1000L)) / 1000.0
        val byteRate = (totalOut + totalIn).toDouble() / durationSeconds
        val packetRate = packetCount.toDouble() / durationSeconds

        val mean = totalFlowBytes.toDouble() / flowCount.toDouble()
        var variance = 0.0
        var durationVariance = 0.0
        val meanDurationMillis = totalActiveMillis.toDouble() / flowCount.toDouble()
        flows.forEach { flow ->
            variance += abs((flow.bytesOut + flow.bytesIn).toDouble() - mean)
            val durationDelta = flow.durationMillis.toDouble() - meanDurationMillis
            durationVariance += durationDelta * durationDelta
        }
        variance /= flowCount.toDouble()
        durationVariance /= flowCount.toDouble()
        val normalizedBurstiness = if (mean > 0.0) {
            (variance / mean).coerceIn(0.0, 4.0)
        } else {
            0.0
        }

        val noveltyScore = noveltySum / flowCount.toDouble()
        val connectionFrequencyDelta = ln(1.0 + (flows.size / durationSeconds))
        val uniqueDestinations = destinations.size.coerceAtLeast(1)
        val destinationDiversity = (uniqueDestinations.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val activityRatio = (totalActiveMillis.toDouble() / (windowEndMillis - windowStartMillis).coerceAtLeast(1L).toDouble())
            .coerceIn(0.0, 1.0)
        val durationJitter = sqrt(durationVariance)
        val portDiversity = (ports.size.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val protocolDiversity = (protocols.size.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val packetImbalance = (abs(totalPacketsOut - totalPacketsIn).toDouble() / (packetCount.toDouble() + 1.0)).coerceIn(0.0, 1.0)
        val smallFlowRatio = (smallFlowCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val highPortRatio = (highPortCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val ttlGap = ttlGapSum / flowCount.toDouble()
        val ttlMetricsPresent = ttlMetricsPresentSum / flowCount.toDouble()
        val synRateTotal = synRateTotalSum / flowCount.toDouble()
        val rstRateTotal = rstRateTotalSum / flowCount.toDouble()
        val ackRateTotal = ackRateTotalSum / flowCount.toDouble()
        val finRateTotal = finRateTotalSum / flowCount.toDouble()
        val pshRateTotal = pshRateTotalSum / flowCount.toDouble()
        val fragmentRateTotal = fragmentRateTotalSum / flowCount.toDouble()
        val tcpWindowMean = tcpWindowMeanSum / flowCount.toDouble()
        val ackDelayMean = ackDelayMeanSum / flowCount.toDouble()
        val interPacketGapMean = interPacketGapMeanSum / flowCount.toDouble()
        val payloadMean = payloadMeanSum / flowCount.toDouble()
        val loadMean = loadMeanSum / flowCount.toDouble()
        val transportMetricsPresent = transportMetricsPresentSum / flowCount.toDouble()
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
