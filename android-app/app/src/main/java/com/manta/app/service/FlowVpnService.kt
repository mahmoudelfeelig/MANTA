package com.manta.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.pm.PackageManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.manta.app.MantaApplication
import com.manta.app.R
import com.manta.app.di.AppContainer
import com.manta.app.domain.flow.AppAttributionResolver
import com.manta.app.domain.flow.FlowAggregator
import com.manta.app.domain.flow.FlowIdentity
import com.manta.app.domain.flow.PacketMetadata
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class FlowVpnService : VpnService() {
    private data class RawPacketEnvelope(
        val packetBytes: ByteArray,
        val length: Int,
        val timestampMillis: Long,
        val capturedAtNanos: Long
    )

    private data class ParsedPacketEnvelope(
        val packet: PacketMetadata,
        val capturedAtNanos: Long,
        val parsedAtNanos: Long
    )

    companion object {
        private const val TAG = "FlowVpnService"
        const val ACTION_START = "com.manta.app.action.START_VPN"
        const val ACTION_STOP = "com.manta.app.action.STOP_VPN"
        private const val CHANNEL_ID = "flow_capture_channel"
        private const val NOTIFICATION_ID = 42
        private const val ANALYSIS_INGRESS_CAPACITY = 2_048
        private const val ANALYSIS_SHARD_CAPACITY = 1_024

        fun startIntent(context: Context): Intent = Intent(context, FlowVpnService::class.java).apply {
            action = ACTION_START
        }

        fun stopIntent(context: Context): Intent = Intent(context, FlowVpnService::class.java).apply {
            action = ACTION_STOP
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)

    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetReader: TunPacketReader? = null
    private var analysisIngress: Channel<RawPacketEnvelope>? = null
    private var analysisShards: List<Channel<ParsedPacketEnvelope>> = emptyList()
    private var shardAggregators: List<FlowAggregator> = emptyList()
    private var forwarder: UserspaceTunForwarder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startCapture()
            ACTION_STOP -> stopCapture()
        }
        return Service.START_STICKY
    }

    override fun onDestroy() {
        stopCapture()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopCapture()
        super.onRevoke()
    }

    private fun startCapture() {
        if (!running.compareAndSet(false, true)) {
            return
        }

        val app = application as MantaApplication
        val packetPipelineStats = app.container.packetPipelineStats
        val config = app.container.settingsStore.readConfig()
        if (!config.captureEnabled || !config.consentAccepted) {
            running.set(false)
            stopSelf()
            return
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("MANTACapture")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .allowBypass()
            .setBlocking(true)

        runCatching {
            builder.addDisallowedApplication(packageName)
        }.onFailure { error ->
            if (error !is PackageManager.NameNotFoundException) {
                Log.w(TAG, "Failed to exclude app package from VPN routing", error)
            }
        }

        val descriptor = builder.establish()

        if (descriptor == null) {
            running.set(false)
            stopSelf()
            return
        }

        vpnInterface = descriptor
        val repository = app.container.repository
        val resolver = AppAttributionResolver(this)
        val parser = TunPacketParser()
        val analysisIngressChannel = Channel<RawPacketEnvelope>(
            capacity = ANALYSIS_INGRESS_CAPACITY,
            onBufferOverflow = BufferOverflow.SUSPEND
        )
        val shardChannels = List(AppContainer.ANALYSIS_SHARD_COUNT) {
            Channel<ParsedPacketEnvelope>(
                capacity = ANALYSIS_SHARD_CAPACITY,
                onBufferOverflow = BufferOverflow.SUSPEND
            )
        }
        val aggregators = List(AppContainer.ANALYSIS_SHARD_COUNT) { FlowAggregator() }
        val tunForwarder = UserspaceTunForwarder(
            vpnService = this,
            tunFd = descriptor,
            localVpnAddress = "10.0.0.2",
            pipelineStats = packetPipelineStats
        )
        analysisIngress = analysisIngressChannel
        analysisShards = shardChannels
        shardAggregators = aggregators
        forwarder = tunForwarder

        packetReader = TunPacketReader { packetBytes, length, timestampMillis ->
            packetPipelineStats.recordRead(length)
            tunForwarder.forward(packetBytes, length)
            val result = analysisIngressChannel.trySend(
                RawPacketEnvelope(
                    packetBytes = packetBytes,
                    length = length,
                    timestampMillis = timestampMillis,
                    capturedAtNanos = System.nanoTime()
                )
            )
            if (result.isSuccess) {
                packetPipelineStats.recordAnalysisIngressEnqueued()
            } else {
                packetPipelineStats.recordAnalysisIngressDropped()
            }
        }

        serviceScope.launch {
            for (packet in analysisIngressChannel) {
                packetPipelineStats.recordAnalysisIngressDequeued()
                val snapshot = packetPipelineStats.snapshot()
                val allowCertificateParsing = snapshot.analysisIngressDepth < (ANALYSIS_INGRESS_CAPACITY * 0.75)
                val allowHttpParsing = snapshot.analysisIngressDepth < (ANALYSIS_INGRESS_CAPACITY * 0.90)
                val parsed = parser.parse(
                    packet.packetBytes,
                    packet.length,
                    packet.timestampMillis,
                    allowCertificateParsing = allowCertificateParsing,
                    allowHttpParsing = allowHttpParsing
                )
                if (parsed == null) {
                    packetPipelineStats.recordParseFailure()
                    continue
                }
                val parsedAtNanos = System.nanoTime()
                packetPipelineStats.recordReadToParse(parsedAtNanos - packet.capturedAtNanos)
                packetPipelineStats.recordParseSuccess()
                val evidence = parsed.protocolEvidence
                if (!evidence.dnsQueryName.isNullOrBlank()) {
                    if (evidence.dnsResponseCode == null) {
                        packetPipelineStats.recordDnsQuery()
                    } else {
                        packetPipelineStats.recordDnsResponse()
                    }
                }
                if (!evidence.tlsSni.isNullOrBlank() || !evidence.tlsJa3Like.isNullOrBlank()) {
                    packetPipelineStats.recordTlsClientHello()
                }
                if (!evidence.tlsLeafSubject.isNullOrBlank()) {
                    packetPipelineStats.recordTls12Certificate()
                }
                if (!evidence.httpMethod.isNullOrBlank()) {
                    packetPipelineStats.recordHttpRequest()
                }
                if (evidence.quicDetected) {
                    packetPipelineStats.recordQuicInitial(evidence.http3Detected)
                }
                val shardIndex = analysisShardIndex(parsed, shardChannels.size)
                val shardResult = shardChannels[shardIndex].trySend(
                    ParsedPacketEnvelope(
                        packet = parsed,
                        capturedAtNanos = packet.capturedAtNanos,
                        parsedAtNanos = parsedAtNanos
                    )
                )
                if (shardResult.isSuccess) {
                    packetPipelineStats.recordParseToShard(System.nanoTime() - parsedAtNanos)
                    packetPipelineStats.recordAnalysisShardEnqueued(shardIndex)
                } else {
                    packetPipelineStats.recordAnalysisShardDropped()
                }
            }
        }

        shardChannels.forEachIndexed { index, channel ->
            serviceScope.launch {
                val aggregator = aggregators[index]
                for (parsedEnvelope in channel) {
                    packetPipelineStats.recordAnalysisShardDequeued(index)
                    val parsed = parsedEnvelope.packet
                    val appId = resolver.resolveAppId(parsed)
                    if (appId == "unknown") {
                        packetPipelineStats.recordAppAttributionUnknown()
                    }
                    val ingestResult = aggregator.ingestWithStats(parsed, appId)
                    if (ingestResult.createdNewFlow) {
                        packetPipelineStats.recordFlowCreated(ingestResult.activeFlowCount)
                    }
                    if (ingestResult.flushed.isNotEmpty()) {
                        packetPipelineStats.recordShardToFlush(System.nanoTime() - parsedEnvelope.parsedAtNanos)
                        packetPipelineStats.recordFlowsFlushed(ingestResult.flushed.size, ingestResult.activeFlowCount)
                        ingestResult.flushed.forEach { flow ->
                            val persistStart = System.nanoTime()
                            runCatching { repository.persistFlow(flow) }
                                .onFailure { error -> Log.e(TAG, "persistFlow failed", error) }
                            packetPipelineStats.recordFlushToPersist(System.nanoTime() - persistStart)
                        }
                    }
                }
            }
        }

        serviceScope.launch {
            runCatching {
                packetReader?.start(descriptor)
            }.onFailure { error ->
                if (running.get()) {
                    Log.e(TAG, "Capture loop failed", error)
                    stopCapture()
                }
            }
        }
    }

    private fun stopCapture() {
        if (!running.compareAndSet(true, false)) {
            return
        }

        packetReader?.stop()
        packetReader = null

        analysisIngress?.close()
        analysisIngress = null
        analysisShards.forEach { it.close() }
        analysisShards = emptyList()

        forwarder?.stop()
        forwarder = null

        val app = application as MantaApplication
        val repository = app.container.repository
        val packetPipelineStats = app.container.packetPipelineStats
        val pendingFlows = shardAggregators.flatMap { it.flushAll(System.currentTimeMillis()) }
        packetPipelineStats.recordFlowsFlushed(pendingFlows.size, 0)
        if (pendingFlows.isNotEmpty()) {
            serviceScope.launch {
                pendingFlows.forEach { flow ->
                    runCatching { repository.persistFlow(flow) }
                        .onFailure { error -> Log.e(TAG, "persistFlow failed during flush", error) }
                }
            }
        }
        shardAggregators = emptyList()

        vpnInterface?.close()
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setOngoing(true)
            .build()
    }

    private fun analysisShardIndex(packet: PacketMetadata, shardCount: Int): Int {
        val identity = FlowIdentity.canonical(
            ipVersion = packet.ipVersion,
            protocolCode = packet.protocolCode,
            srcIp = packet.srcIp,
            srcPort = packet.srcPort,
            dstIp = packet.dstIp,
            dstPort = packet.dstPort
        )
        return identity.shardKey().hashCode().let { if (it == Int.MIN_VALUE) 0 else kotlin.math.abs(it) } % shardCount.coerceAtLeast(1)
    }
}
