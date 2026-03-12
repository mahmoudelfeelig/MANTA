package com.manta.app.domain.flow

import com.manta.app.core.model.FlowProtocol
import com.manta.app.core.model.FlowRecord
import com.manta.app.core.security.CryptoUtils
import java.util.UUID
import kotlin.math.max

private data class FlowKey(
    val appId: String,
    val protocol: FlowProtocol,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int
)

private data class FlowAccumulator(
    val startMillis: Long,
    var endMillis: Long,
    var bytesOut: Long,
    var bytesIn: Long,
    var packetsOut: Int,
    var packetsIn: Int,
    var siteHint: String? = null,
    var lastPacketTimestampMillis: Long = startMillis,
    var lastPayloadTimestampMillis: Long? = null,
    var interPacketGapSumMillis: Long = 0L,
    var interPacketGapCount: Int = 0,
    var ackDelaySumMillis: Long = 0L,
    var ackDelayCount: Int = 0,
    var payloadBytesSum: Long = 0L,
    var payloadPacketCount: Int = 0,
    var ttlOutboundSum: Int = 0,
    var ttlOutboundCount: Int = 0,
    var ttlInboundSum: Int = 0,
    var ttlInboundCount: Int = 0,
    var tcpPacketCount: Int = 0,
    var synCount: Int = 0,
    var rstCount: Int = 0,
    var ackCount: Int = 0,
    var finCount: Int = 0,
    var pshCount: Int = 0,
    var fragmentCount: Int = 0,
    var tcpWindowSum: Long = 0L,
    var tcpWindowCount: Int = 0,
    var transportMetricsObserved: Boolean = false
)

class FlowAggregator(
    private val flowIdleTimeoutMillis: Long = 30_000L,
    private val flowMaxDurationMillis: Long = 20_000L
) {
    private val activeFlows = LinkedHashMap<FlowKey, FlowAccumulator>()
    private val seenDestinationsByApp = mutableMapOf<String, MutableSet<String>>()

    fun ingest(packet: PacketMetadata, appId: String): List<FlowRecord> {
        val protocol = FlowProtocol.fromCode(packet.protocolCode)
        val key = FlowKey(
            appId = appId,
            protocol = protocol,
            srcIp = packet.srcIp,
            srcPort = packet.srcPort,
            dstIp = packet.dstIp,
            dstPort = packet.dstPort
        )

        val accumulator = activeFlows[key] ?: FlowAccumulator(
            startMillis = packet.timestampMillis,
            endMillis = packet.timestampMillis,
            bytesOut = 0,
            bytesIn = 0,
            packetsOut = 0,
            packetsIn = 0,
            siteHint = packet.hostHint
        ).also { activeFlows[key] = it }

        val interPacketGap = packet.timestampMillis - accumulator.lastPacketTimestampMillis
        if (interPacketGap > 0L) {
            accumulator.interPacketGapSumMillis += interPacketGap
            accumulator.interPacketGapCount += 1
        }
        accumulator.lastPacketTimestampMillis = packet.timestampMillis
        accumulator.endMillis = packet.timestampMillis
        if (packet.outbound) {
            accumulator.bytesOut += packet.bytes
            accumulator.packetsOut += 1
        } else {
            accumulator.bytesIn += packet.bytes
            accumulator.packetsIn += 1
        }
        if (accumulator.siteHint.isNullOrBlank() && !packet.hostHint.isNullOrBlank()) {
            accumulator.siteHint = packet.hostHint
        }

        val sawPayload = packet.payloadBytes > 0
        if (sawPayload) {
            accumulator.payloadBytesSum += packet.payloadBytes.toLong()
            accumulator.payloadPacketCount += 1
            accumulator.transportMetricsObserved = true
        }
        packet.hopLimit?.let { hopLimit ->
            if (packet.outbound) {
                accumulator.ttlOutboundSum += hopLimit
                accumulator.ttlOutboundCount += 1
            } else {
                accumulator.ttlInboundSum += hopLimit
                accumulator.ttlInboundCount += 1
            }
            accumulator.transportMetricsObserved = true
        }
        if (packet.fragmented) {
            accumulator.fragmentCount += 1
            accumulator.transportMetricsObserved = true
        }
        if (packet.protocolCode == 6) {
            accumulator.tcpPacketCount += 1
            if (packet.synFlag) accumulator.synCount += 1
            if (packet.rstFlag) accumulator.rstCount += 1
            if (packet.ackFlag) {
                accumulator.ackCount += 1
                accumulator.lastPayloadTimestampMillis?.let { payloadTimestamp ->
                    val ackDelay = packet.timestampMillis - payloadTimestamp
                    if (ackDelay >= 0L) {
                        accumulator.ackDelaySumMillis += ackDelay
                        accumulator.ackDelayCount += 1
                    }
                }
            }
            if (packet.finFlag) accumulator.finCount += 1
            if (packet.pshFlag) accumulator.pshCount += 1
            packet.tcpWindowSize?.let { tcpWindowSize ->
                accumulator.tcpWindowSum += tcpWindowSize.toLong()
                accumulator.tcpWindowCount += 1
            }
            accumulator.transportMetricsObserved = true
        }
        if (sawPayload) {
            accumulator.lastPayloadTimestampMillis = packet.timestampMillis
        }

        return flushExpired(packet.timestampMillis)
    }

    fun flushAll(nowMillis: Long): List<FlowRecord> {
        return flushInternal(activeFlows.keys.toList(), nowMillis)
    }

    private fun flushExpired(nowMillis: Long): List<FlowRecord> {
        val expiredKeys = activeFlows.entries
            .filter { (_, value) ->
                val idleExpired = nowMillis - value.endMillis >= flowIdleTimeoutMillis
                val maxDurationReached = nowMillis - value.startMillis >= flowMaxDurationMillis
                idleExpired || maxDurationReached
            }
            .map { it.key }

        return flushInternal(expiredKeys, nowMillis)
    }

    private fun flushInternal(keys: List<FlowKey>, nowMillis: Long): List<FlowRecord> {
        if (keys.isEmpty()) {
            return emptyList()
        }

        return keys.mapNotNull { key ->
            val accumulator = activeFlows.remove(key) ?: return@mapNotNull null
            val destination = "${accumulator.siteHint ?: key.dstIp}:${key.dstPort}"
            val seenDestinations = seenDestinationsByApp.getOrPut(key.appId) { mutableSetOf() }
            val destinationNovelty = if (seenDestinations.contains(destination)) 0.0 else 1.0
            seenDestinations += destination
            val totalPackets = (accumulator.packetsOut + accumulator.packetsIn).coerceAtLeast(1)
            val tcpPackets = accumulator.tcpPacketCount.coerceAtLeast(1)
            val durationMillis = max(1, accumulator.endMillis - accumulator.startMillis)
            val durationSeconds = (durationMillis.toDouble() / 1000.0).coerceAtLeast(0.001)
            val outboundTtlMean = if (accumulator.ttlOutboundCount > 0) accumulator.ttlOutboundSum.toDouble() / accumulator.ttlOutboundCount.toDouble() else 0.0
            val inboundTtlMean = if (accumulator.ttlInboundCount > 0) accumulator.ttlInboundSum.toDouble() / accumulator.ttlInboundCount.toDouble() else 0.0
            val ttlGap = if (accumulator.ttlOutboundCount > 0 && accumulator.ttlInboundCount > 0) {
                (kotlin.math.abs(outboundTtlMean - inboundTtlMean) / 255.0).coerceIn(0.0, 1.0)
            } else {
                0.0
            }
            val ttlMetricsPresent = if (accumulator.ttlOutboundCount + accumulator.ttlInboundCount > 0) 1.0 else 0.0
            val transportPresent = if (accumulator.transportMetricsObserved) 1.0 else 0.0

            FlowRecord(
                id = UUID.randomUUID().toString(),
                timestampStartMillis = accumulator.startMillis,
                timestampEndMillis = max(accumulator.endMillis, nowMillis),
                appId = key.appId,
                protocol = key.protocol,
                srcIp = key.srcIp,
                srcPort = key.srcPort,
                dstIp = key.dstIp,
                dstPort = key.dstPort,
                bytesOut = accumulator.bytesOut,
                bytesIn = accumulator.bytesIn,
                packetsOut = accumulator.packetsOut,
                packetsIn = accumulator.packetsIn,
                durationMillis = max(1, accumulator.endMillis - accumulator.startMillis),
                destinationHash = CryptoUtils.sha256(destination),
                destinationNovelty = destinationNovelty,
                siteHint = accumulator.siteHint,
                ttlGap = ttlGap,
                ttlMetricsPresent = ttlMetricsPresent,
                synRateTotal = accumulator.synCount.toDouble() / tcpPackets.toDouble(),
                rstRateTotal = accumulator.rstCount.toDouble() / tcpPackets.toDouble(),
                ackRateTotal = accumulator.ackCount.toDouble() / tcpPackets.toDouble(),
                finRateTotal = accumulator.finCount.toDouble() / tcpPackets.toDouble(),
                pshRateTotal = accumulator.pshCount.toDouble() / tcpPackets.toDouble(),
                fragmentRateTotal = accumulator.fragmentCount.toDouble() / totalPackets.toDouble(),
                tcpWindowMean = if (accumulator.tcpWindowCount > 0) accumulator.tcpWindowSum.toDouble() / accumulator.tcpWindowCount.toDouble() else 0.0,
                ackDelayMean = if (accumulator.ackDelayCount > 0) accumulator.ackDelaySumMillis.toDouble() / accumulator.ackDelayCount.toDouble() else 0.0,
                interPacketGapMean = if (accumulator.interPacketGapCount > 0) accumulator.interPacketGapSumMillis.toDouble() / accumulator.interPacketGapCount.toDouble() else 0.0,
                payloadMean = if (accumulator.payloadPacketCount > 0) accumulator.payloadBytesSum.toDouble() / accumulator.payloadPacketCount.toDouble() else 0.0,
                loadMean = ((accumulator.bytesOut + accumulator.bytesIn).toDouble() / durationSeconds).coerceAtLeast(0.0),
                transportMetricsPresent = transportPresent
            )
        }
    }
}
