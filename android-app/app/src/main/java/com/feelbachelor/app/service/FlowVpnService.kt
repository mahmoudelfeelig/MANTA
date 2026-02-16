package com.feelbachelor.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.feelbachelor.app.FeelApplication
import com.feelbachelor.app.R
import com.feelbachelor.app.domain.flow.AppAttributionResolver
import com.feelbachelor.app.domain.flow.FlowAggregator
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class FlowVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.feelbachelor.app.action.START_VPN"
        const val ACTION_STOP = "com.feelbachelor.app.action.STOP_VPN"
        private const val CHANNEL_ID = "flow_capture_channel"
        private const val NOTIFICATION_ID = 42

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
    private var flowAggregator: FlowAggregator? = null

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

        val app = application as FeelApplication
        val config = app.container.settingsStore.readConfig()
        if (!config.captureEnabled || !config.consentAccepted) {
            running.set(false)
            stopSelf()
            return
        }

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val descriptor = Builder()
            .setSession("FeelEndpointCapture")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setBlocking(true)
            .establish()

        if (descriptor == null) {
            running.set(false)
            stopSelf()
            return
        }

        vpnInterface = descriptor
        val repository = app.container.repository
        val resolver = AppAttributionResolver(this)
        val aggregator = FlowAggregator()
        val parser = TunPacketParser()
        flowAggregator = aggregator

        packetReader = TunPacketReader(parser) { packet ->
            val appId = resolver.resolveAppId(packet)
            val flushed = aggregator.ingest(packet, appId)
            if (flushed.isNotEmpty()) {
                serviceScope.launch {
                    flushed.forEach { flow ->
                        repository.persistFlow(flow)
                    }
                }
            }
        }

        serviceScope.launch {
            packetReader?.start(descriptor)
        }
    }

    private fun stopCapture() {
        if (!running.compareAndSet(true, false)) {
            return
        }

        packetReader?.stop()
        packetReader = null

        val app = application as FeelApplication
        val repository = app.container.repository
        val pendingFlows = flowAggregator?.flushAll(System.currentTimeMillis()).orEmpty()
        if (pendingFlows.isNotEmpty()) {
            serviceScope.launch {
                pendingFlows.forEach { repository.persistFlow(it) }
            }
        }
        flowAggregator = null

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
}
