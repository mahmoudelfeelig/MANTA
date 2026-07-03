package com.manta.app.domain.flow

import com.manta.app.core.model.FeatureWindow
import com.manta.app.core.model.FlowRecord
import java.time.Instant
import java.time.ZoneOffset
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
        var dnsFlowCount = 0
        var webFlowCount = 0
        var privateDestinationCount = 0
        var multicastDestinationCount = 0
        var destinationRiskSum = 0.0
        var lookalikeScoreSum = 0.0
        var suspiciousDestinationCount = 0
        var knownIdentityCount = 0
        var mitreTechniqueCount = 0
        var threatTagCount = 0
        var destinationSwitchCount = 0
        var previousDestination: String? = null
        val destinations = HashSet<String>()
        val destinationCounts = mutableMapOf<String, Int>()
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
            destinationCounts[flow.destinationHash] = (destinationCounts[flow.destinationHash] ?: 0) + 1
            previousDestination?.let { previous ->
                if (previous != flow.destinationHash) destinationSwitchCount += 1
            }
            previousDestination = flow.destinationHash
            ports += flow.dstPort
            protocols += flow.protocol.name
            if (flowBytes <= 256L) smallFlowCount += 1
            if (flow.dstPort >= 1024) highPortCount += 1
            if (flow.dstPort == 53 || flow.dstPort == 853) dnsFlowCount += 1
            if (flow.dstPort in setOf(80, 443, 8080, 8000, 8443)) webFlowCount += 1
            if (isPrivateDestination(flow.dstIp)) privateDestinationCount += 1
            if (isMulticastDestination(flow.dstIp)) multicastDestinationCount += 1
            val insight = flow.destinationInsight
            val suspiciousDestination = insight.lookalikeScore >= 0.55 ||
                insight.punycodePresent ||
                insight.digitSubstitutionPresent ||
                insight.suspiciousTld ||
                insight.threatTags.isNotEmpty()
            val destinationRisk = listOf(
                insight.lookalikeScore,
                if (insight.threatTags.isNotEmpty()) 0.85 else 0.0,
                if (insight.suspiciousTld) 0.65 else 0.0,
                if (insight.punycodePresent || insight.digitSubstitutionPresent) 0.55 else 0.0,
                insight.confidence * 0.35
            ).maxOrNull() ?: 0.0
            destinationRiskSum += destinationRisk.coerceIn(0.0, 1.0)
            lookalikeScoreSum += insight.lookalikeScore.coerceIn(0.0, 1.0)
            if (suspiciousDestination) suspiciousDestinationCount += 1
            if (!insight.normalizedHost.isNullOrBlank() || !insight.registrableDomain.isNullOrBlank()) knownIdentityCount += 1
            if (insight.mitreTechniques.isNotEmpty()) mitreTechniqueCount += 1
            if (insight.threatTags.isNotEmpty()) threatTagCount += 1
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
        val destinationConcentration = (destinationCounts.values.maxOrNull()?.toDouble() ?: 0.0) / flowCount.toDouble()
        val destinationTransitionRate = if (flowCount > 1) {
            destinationSwitchCount.toDouble() / (flowCount - 1).toDouble()
        } else {
            0.0
        }
        val dnsFlowRatio = (dnsFlowCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val webFlowRatio = (webFlowCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val privateDestinationRatio = (privateDestinationCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val multicastDestinationRatio = (multicastDestinationCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val destinationRiskScore = (destinationRiskSum / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val lookalikeScore = (lookalikeScoreSum / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val suspiciousDestinationRatio = (suspiciousDestinationCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val knownIdentityRatio = (knownIdentityCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val mitreTechniqueRatio = (mitreTechniqueCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
        val threatTagRatio = (threatTagCount.toDouble() / flowCount.toDouble()).coerceIn(0.0, 1.0)
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
        val zoned = Instant.ofEpochMilli(windowEndMillis).atZone(ZoneOffset.UTC)
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
            destinationConcentration = destinationConcentration.coerceIn(0.0, 1.0),
            destinationTransitionRate = destinationTransitionRate.coerceIn(0.0, 1.0),
            dnsFlowRatio = dnsFlowRatio,
            webFlowRatio = webFlowRatio,
            privateDestinationRatio = privateDestinationRatio,
            multicastDestinationRatio = multicastDestinationRatio,
            lowVolumePeriodicScore = if (byteRate <= 128.0) periodicBeaconScore.coerceIn(0.0, 1.0) else 0.0,
            destinationRiskScore = destinationRiskScore,
            lookalikeScore = lookalikeScore,
            suspiciousDestinationRatio = suspiciousDestinationRatio,
            knownIdentityRatio = knownIdentityRatio,
            mitreTechniqueRatio = mitreTechniqueRatio,
            threatTagRatio = threatTagRatio,
            sampledByGuardrail = sampledByGuardrail,
            processingCostMillis = processingCostMillis.coerceAtLeast(0.0)
        )
    }

    private fun isPrivateDestination(ip: String): Boolean {
        return ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            Regex("""^172\.(1[6-9]|2\d|3[0-1])\.""").containsMatchIn(ip) ||
            ip == "127.0.0.1" ||
            ip == "::1" ||
            ip.lowercase().startsWith("fc") ||
            ip.lowercase().startsWith("fd")
    }

    private fun isMulticastDestination(ip: String): Boolean {
        val firstOctet = ip.substringBefore(".").toIntOrNull() ?: return ip.lowercase().startsWith("ff")
        return firstOctet in 224..239
    }
}
