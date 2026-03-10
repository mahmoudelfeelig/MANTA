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
    var packetsIn: Int
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
            packetsIn = 0
        ).also { activeFlows[key] = it }

        accumulator.endMillis = packet.timestampMillis
        if (packet.outbound) {
            accumulator.bytesOut += packet.bytes
            accumulator.packetsOut += 1
        } else {
            accumulator.bytesIn += packet.bytes
            accumulator.packetsIn += 1
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
            val destination = "${key.dstIp}:${key.dstPort}"
            val seenDestinations = seenDestinationsByApp.getOrPut(key.appId) { mutableSetOf() }
            val destinationNovelty = if (seenDestinations.contains(destination)) 0.0 else 1.0
            seenDestinations += destination

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
                destinationNovelty = destinationNovelty
            )
        }
    }
}
