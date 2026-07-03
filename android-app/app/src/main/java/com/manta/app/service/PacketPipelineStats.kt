package com.manta.app.service

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

data class PacketPipelineSnapshot(
    val packetsRead: Long,
    val bytesRead: Long,
    val forwardQueueDepth: Int,
    val forwardQueueHighWatermark: Int,
    val forwardQueueDropped: Long,
    val analysisIngressDepth: Int,
    val analysisIngressHighWatermark: Int,
    val analysisIngressDropped: Long,
    val analysisShardDepths: List<Int>,
    val analysisShardHighWatermarks: List<Int>,
    val analysisShardDropped: Long,
    val parserSuccess: Long,
    val parserFailure: Long,
    val unsupportedProtocol: Long,
    val appAttributionUnknown: Long,
    val flowsCreated: Long,
    val flowsFlushed: Long,
    val activeFlows: Int,
    val dnsQueries: Long,
    val dnsResponses: Long,
    val tlsClientHello: Long,
    val tls12Certificates: Long,
    val httpRequests: Long,
    val quicInitial: Long,
    val http3Detected: Long,
    val readToParseAvgMs: Double,
    val parseToShardAvgMs: Double,
    val shardToFlushAvgMs: Double,
    val flushToPersistAvgMs: Double
) {
    fun toMap(): Map<String, Any> = mapOf(
        "packets_read" to packetsRead,
        "bytes_read" to bytesRead,
        "forward_queue_depth" to forwardQueueDepth,
        "forward_queue_high_watermark" to forwardQueueHighWatermark,
        "forward_queue_dropped" to forwardQueueDropped,
        "analysis_ingress_depth" to analysisIngressDepth,
        "analysis_ingress_high_watermark" to analysisIngressHighWatermark,
        "analysis_ingress_dropped" to analysisIngressDropped,
        "analysis_shard_depths" to analysisShardDepths,
        "analysis_shard_high_watermarks" to analysisShardHighWatermarks,
        "analysis_shard_dropped" to analysisShardDropped,
        "parser_success" to parserSuccess,
        "parser_failure" to parserFailure,
        "unsupported_protocol" to unsupportedProtocol,
        "app_attribution_unknown" to appAttributionUnknown,
        "flows_created" to flowsCreated,
        "flows_flushed" to flowsFlushed,
        "active_flows" to activeFlows,
        "dns_queries" to dnsQueries,
        "dns_responses" to dnsResponses,
        "tls_client_hello" to tlsClientHello,
        "tls12_certificates" to tls12Certificates,
        "http_requests" to httpRequests,
        "quic_initial" to quicInitial,
        "http3_detected" to http3Detected,
        "read_to_parse_avg_ms" to readToParseAvgMs,
        "parse_to_shard_avg_ms" to parseToShardAvgMs,
        "shard_to_flush_avg_ms" to shardToFlushAvgMs,
        "flush_to_persist_avg_ms" to flushToPersistAvgMs,
    )
}

class PacketPipelineStats(
    shardCount: Int
) {
    private val packetsRead = AtomicLong(0L)
    private val bytesRead = AtomicLong(0L)

    private val forwardQueueDepth = AtomicInteger(0)
    private val forwardQueueHighWatermark = AtomicInteger(0)
    private val forwardQueueDropped = AtomicLong(0L)

    private val analysisIngressDepth = AtomicInteger(0)
    private val analysisIngressHighWatermark = AtomicInteger(0)
    private val analysisIngressDropped = AtomicLong(0L)

    private val analysisShardDepths = List(shardCount.coerceAtLeast(1)) { AtomicInteger(0) }
    private val analysisShardHighWatermarks = List(shardCount.coerceAtLeast(1)) { AtomicInteger(0) }
    private val analysisShardDropped = AtomicLong(0L)

    private val parserSuccess = AtomicLong(0L)
    private val parserFailure = AtomicLong(0L)
    private val unsupportedProtocol = AtomicLong(0L)
    private val appAttributionUnknown = AtomicLong(0L)
    private val flowsCreated = AtomicLong(0L)
    private val flowsFlushed = AtomicLong(0L)
    private val activeFlows = AtomicInteger(0)

    private val dnsQueries = AtomicLong(0L)
    private val dnsResponses = AtomicLong(0L)
    private val tlsClientHello = AtomicLong(0L)
    private val tls12Certificates = AtomicLong(0L)
    private val httpRequests = AtomicLong(0L)
    private val quicInitial = AtomicLong(0L)
    private val http3Detected = AtomicLong(0L)

    private val readToParseNanosTotal = AtomicLong(0L)
    private val readToParseCount = AtomicLong(0L)
    private val parseToShardNanosTotal = AtomicLong(0L)
    private val parseToShardCount = AtomicLong(0L)
    private val shardToFlushNanosTotal = AtomicLong(0L)
    private val shardToFlushCount = AtomicLong(0L)
    private val flushToPersistNanosTotal = AtomicLong(0L)
    private val flushToPersistCount = AtomicLong(0L)

    fun recordRead(bytes: Int) {
        packetsRead.incrementAndGet()
        bytesRead.addAndGet(bytes.toLong().coerceAtLeast(0L))
    }

    fun recordForwardEnqueued() = incrementDepth(forwardQueueDepth, forwardQueueHighWatermark)

    fun recordForwardDequeued() = decrementDepth(forwardQueueDepth)

    fun recordForwardDropped() {
        forwardQueueDropped.incrementAndGet()
    }

    fun recordAnalysisIngressEnqueued() = incrementDepth(analysisIngressDepth, analysisIngressHighWatermark)

    fun recordAnalysisIngressDequeued() = decrementDepth(analysisIngressDepth)

    fun recordAnalysisIngressDropped() {
        analysisIngressDropped.incrementAndGet()
    }

    fun recordAnalysisShardEnqueued(shard: Int) = incrementDepth(analysisShardDepths[shard], analysisShardHighWatermarks[shard])

    fun recordAnalysisShardDequeued(shard: Int) = decrementDepth(analysisShardDepths[shard])

    fun recordAnalysisShardDropped() {
        analysisShardDropped.incrementAndGet()
    }

    fun recordParseSuccess() {
        parserSuccess.incrementAndGet()
    }

    fun recordParseFailure() {
        parserFailure.incrementAndGet()
    }

    fun recordUnsupportedProtocol() {
        unsupportedProtocol.incrementAndGet()
    }

    fun recordAppAttributionUnknown() {
        appAttributionUnknown.incrementAndGet()
    }

    fun recordFlowCreated(active: Int) {
        flowsCreated.incrementAndGet()
        activeFlows.set(active.coerceAtLeast(0))
    }

    fun recordFlowsFlushed(count: Int, active: Int) {
        flowsFlushed.addAndGet(count.toLong().coerceAtLeast(0L))
        activeFlows.set(active.coerceAtLeast(0))
    }

    fun recordDnsQuery() {
        dnsQueries.incrementAndGet()
    }

    fun recordDnsResponse() {
        dnsResponses.incrementAndGet()
    }

    fun recordTlsClientHello() {
        tlsClientHello.incrementAndGet()
    }

    fun recordTls12Certificate() {
        tls12Certificates.incrementAndGet()
    }

    fun recordHttpRequest() {
        httpRequests.incrementAndGet()
    }

    fun recordQuicInitial(http3: Boolean) {
        quicInitial.incrementAndGet()
        if (http3) {
            http3Detected.incrementAndGet()
        }
    }

    fun recordReadToParse(durationNanos: Long) = recordTiming(durationNanos, readToParseNanosTotal, readToParseCount)

    fun recordParseToShard(durationNanos: Long) = recordTiming(durationNanos, parseToShardNanosTotal, parseToShardCount)

    fun recordShardToFlush(durationNanos: Long) = recordTiming(durationNanos, shardToFlushNanosTotal, shardToFlushCount)

    fun recordFlushToPersist(durationNanos: Long) = recordTiming(durationNanos, flushToPersistNanosTotal, flushToPersistCount)

    fun snapshot(): PacketPipelineSnapshot {
        return PacketPipelineSnapshot(
            packetsRead = packetsRead.get(),
            bytesRead = bytesRead.get(),
            forwardQueueDepth = forwardQueueDepth.get(),
            forwardQueueHighWatermark = forwardQueueHighWatermark.get(),
            forwardQueueDropped = forwardQueueDropped.get(),
            analysisIngressDepth = analysisIngressDepth.get(),
            analysisIngressHighWatermark = analysisIngressHighWatermark.get(),
            analysisIngressDropped = analysisIngressDropped.get(),
            analysisShardDepths = analysisShardDepths.map { it.get() },
            analysisShardHighWatermarks = analysisShardHighWatermarks.map { it.get() },
            analysisShardDropped = analysisShardDropped.get(),
            parserSuccess = parserSuccess.get(),
            parserFailure = parserFailure.get(),
            unsupportedProtocol = unsupportedProtocol.get(),
            appAttributionUnknown = appAttributionUnknown.get(),
            flowsCreated = flowsCreated.get(),
            flowsFlushed = flowsFlushed.get(),
            activeFlows = activeFlows.get(),
            dnsQueries = dnsQueries.get(),
            dnsResponses = dnsResponses.get(),
            tlsClientHello = tlsClientHello.get(),
            tls12Certificates = tls12Certificates.get(),
            httpRequests = httpRequests.get(),
            quicInitial = quicInitial.get(),
            http3Detected = http3Detected.get(),
            readToParseAvgMs = averageMs(readToParseNanosTotal.get(), readToParseCount.get()),
            parseToShardAvgMs = averageMs(parseToShardNanosTotal.get(), parseToShardCount.get()),
            shardToFlushAvgMs = averageMs(shardToFlushNanosTotal.get(), shardToFlushCount.get()),
            flushToPersistAvgMs = averageMs(flushToPersistNanosTotal.get(), flushToPersistCount.get())
        )
    }

    private fun incrementDepth(depth: AtomicInteger, watermark: AtomicInteger) {
        val next = depth.incrementAndGet()
        while (true) {
            val current = watermark.get()
            if (next <= current) {
                break
            }
            if (watermark.compareAndSet(current, next)) {
                break
            }
        }
    }

    private fun decrementDepth(depth: AtomicInteger) {
        while (true) {
            val current = depth.get()
            val next = (current - 1).coerceAtLeast(0)
            if (depth.compareAndSet(current, next)) {
                break
            }
        }
    }

    private fun recordTiming(durationNanos: Long, total: AtomicLong, count: AtomicLong) {
        if (durationNanos < 0L) {
            return
        }
        total.addAndGet(durationNanos)
        count.incrementAndGet()
    }

    private fun averageMs(totalNanos: Long, count: Long): Double {
        if (count <= 0L) {
            return 0.0
        }
        return (totalNanos.toDouble() / count.toDouble()) / 1_000_000.0
    }
}
