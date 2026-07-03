package com.manta.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.SystemClock
import com.manta.app.core.settings.CustomPrivacyOptions
import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.ThemeMode
import com.manta.app.service.FlowVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

class AutomationReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION_AUTOMATION = "com.manta.app.action.AUTOMATION"

        private const val EXTRA_COMMAND = "command"
        private const val CMD_CONFIGURE = "configure"
        private const val CMD_START_CAPTURE = "start_capture"
        private const val CMD_STOP_CAPTURE = "stop_capture"
        private const val CMD_FLUSH_EXPORT = "flush_export"
        private const val CMD_PING_BACKEND = "ping_backend"
        private const val CMD_SYNC_POLICY = "sync_policy"
        private const val CMD_EXPORT_SNAPSHOT = "export_snapshot"
        private const val CMD_EXPORT_FORENSICS = "export_forensics"
        private const val CMD_PURGE_LOCAL = "purge_local"
        private const val CMD_STATUS = "status"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_AUTOMATION) {
            return
        }

        val pendingResult = goAsync()
        scope.launch {
            try {
                val app = context.applicationContext as MantaApplication
                val command = intent.getStringExtra(EXTRA_COMMAND).orEmpty().trim()
                val result = when (command) {
                    CMD_CONFIGURE -> configure(app, intent)
                    CMD_START_CAPTURE -> startCapture(app, context)
                    CMD_STOP_CAPTURE -> stopCapture(app, context)
                    CMD_FLUSH_EXPORT -> flushExport(app)
                    CMD_PING_BACKEND -> pingBackend(app)
                    CMD_SYNC_POLICY -> syncPolicy(app)
                    CMD_EXPORT_SNAPSHOT -> exportSnapshot(app, intent)
                    CMD_EXPORT_FORENSICS -> exportForensics(app, intent)
                    CMD_PURGE_LOCAL -> purgeLocal(app)
                    CMD_STATUS -> status(app)
                    else -> statusPayload(
                        command = command.ifBlank { "unknown" },
                        success = false,
                        message = "Unsupported automation command"
                    )
                }
                writeStatus(context, result)
            } finally {
                pendingResult.finish()
            }
        }
    }

    private fun configure(app: MantaApplication, intent: Intent): JSONObject {
        val settings = app.container.settingsStore
        intent.getStringExtra("backend_url")?.let(settings::setBackendUrl)
        intent.getStringExtra("api_token")?.let(settings::setApiToken)
        parseOptionalBoolean(intent, "export_enabled")?.let(settings::setExportEnabled)
        parseOptionalBoolean(intent, "capture_enabled")?.let(settings::setCaptureEnabled)
        parseOptionalBoolean(intent, "consent_accepted")?.let(settings::setConsentAccepted)
        intent.getStringExtra("privacy_mode")?.let { raw ->
            runCatching { PrivacyMode.valueOf(raw.trim().uppercase()) }.getOrNull()?.let(settings::setPrivacyMode)
        }
        intent.getStringExtra("theme_mode")?.let { raw ->
            runCatching { ThemeMode.valueOf(raw.trim().uppercase()) }.getOrNull()?.let(settings::setThemeMode)
        }
        intent.getStringExtra("detection_model")?.let(settings::setDetectionModel)
        if (intent.hasExtra("shadow_model")) {
            settings.setShadowModel(intent.getStringExtra("shadow_model"))
        }

        val current = settings.readConfig().customPrivacy
        val updatedCustom = current.copy(
            includeAppId = parseOptionalBoolean(intent, "custom_include_app_id") ?: current.includeAppId,
            includeSiteHint = parseOptionalBoolean(intent, "custom_include_site_hint") ?: current.includeSiteHint,
            includeIpAddresses = parseOptionalBoolean(intent, "custom_include_ip_addresses") ?: current.includeIpAddresses,
            includeExactPorts = parseOptionalBoolean(intent, "custom_include_exact_ports") ?: current.includeExactPorts,
            includeDeviceLabel = parseOptionalBoolean(intent, "custom_include_device_label") ?: current.includeDeviceLabel,
            includeExplanations = parseOptionalBoolean(intent, "custom_include_explanations") ?: current.includeExplanations,
            includeFeatureWindow = parseOptionalBoolean(intent, "custom_include_feature_window") ?: current.includeFeatureWindow,
        )
        settings.setCustomPrivacyOptions(updatedCustom)
        return status(app).put("message", "Configuration updated")
    }

    private suspend fun flushExport(app: MantaApplication): JSONObject {
        val sent = app.container.repository.processExportQueue(app.container.eventClient)
        return status(app)
            .put("message", "Export queue flushed")
            .put("sent_count", sent)
    }

    private suspend fun pingBackend(app: MantaApplication): JSONObject {
        val result = app.container.repository.refreshBackendConnection(app.container.eventClient)
        return status(app)
            .put("message", result.getOrNull() ?: result.exceptionOrNull()?.message.orEmpty())
            .put("success", result.isSuccess)
    }

    private suspend fun syncPolicy(app: MantaApplication): JSONObject {
        val result = app.container.repository.syncRemotePolicy(app.container.eventClient)
        return status(app)
            .put("message", result.getOrNull()?.let { "Policy synced" } ?: result.exceptionOrNull()?.message.orEmpty())
            .put("success", result.isSuccess)
    }

    private suspend fun exportSnapshot(app: MantaApplication, intent: Intent): JSONObject {
        val maxRows = intent.getStringExtra("max_rows")?.toIntOrNull() ?: 20_000
        val result = app.container.repository.exportLatestFlowsCsv(maxRows)
        return status(app)
            .put("message", result.getOrNull() ?: result.exceptionOrNull()?.message.orEmpty())
            .put("success", result.isSuccess)
            .put("path", result.getOrNull())
    }

    private suspend fun exportForensics(app: MantaApplication, intent: Intent): JSONObject {
        val maxRows = intent.getStringExtra("max_rows")?.toIntOrNull() ?: 20_000
        val result = app.container.repository.exportForensicsBundle(maxRows)
        return status(app)
            .put("message", result.getOrNull() ?: result.exceptionOrNull()?.message.orEmpty())
            .put("success", result.isSuccess)
            .put("path", result.getOrNull())
    }

    private suspend fun purgeLocal(app: MantaApplication): JSONObject {
        app.container.repository.purgeAllLocalData()
        return status(app).put("message", "Local data purged")
    }

    private fun startCapture(app: MantaApplication, context: Context): JSONObject {
        val settings = app.container.settingsStore
        settings.setCaptureEnabled(true)
        settings.setConsentAccepted(true)
        val vpnPrepare = VpnService.prepare(context)
        return if (vpnPrepare != null) {
            status(app)
                .put("success", false)
                .put("message", "VPN permission must be granted once manually before automation can start capture")
        } else {
            context.startService(FlowVpnService.startIntent(context))
            SystemClock.sleep(500)
            status(app)
                .put("success", true)
                .put("message", "Capture started")
        }
    }

    private fun stopCapture(app: MantaApplication, context: Context): JSONObject {
        app.container.settingsStore.setCaptureEnabled(false)
        context.startService(FlowVpnService.stopIntent(context))
        SystemClock.sleep(500)
        return status(app)
            .put("success", true)
            .put("message", "Capture stopped")
    }

    private fun status(app: MantaApplication): JSONObject {
        val config = app.container.settingsStore.readConfig()
        return statusPayload(
            command = "status",
            success = true,
            message = "Status snapshot"
        )
            .put(
                "config",
                JSONObject()
                    .put("backend_url", config.backendUrl)
                    .put("export_enabled", config.exportEnabled)
                    .put("capture_enabled", config.captureEnabled)
                    .put("consent_accepted", config.consentAccepted)
                    .put("privacy_mode", config.privacyMode.name)
                    .put("detection_model", config.detectionModel)
                    .put("shadow_model", config.shadowModel)
                    .put("last_server_ping_status", config.lastServerPingStatus)
                    .put("last_device_heartbeat_status", config.lastDeviceHeartbeatStatus)
                    .put("custom_privacy", JSONObject(config.customPrivacy.toJson()))
            )
    }

    private fun statusPayload(command: String, success: Boolean, message: String): JSONObject {
        return JSONObject()
            .put("command", command)
            .put("success", success)
            .put("message", message)
            .put("timestamp", System.currentTimeMillis())
    }

    private fun writeStatus(context: Context, payload: JSONObject) {
        val root = File(context.getExternalFilesDir(null), "automation")
        if (!root.exists()) {
            root.mkdirs()
        }
        File(root, "automation-status.json").writeText(payload.toString(2), Charsets.UTF_8)
    }

    private fun parseOptionalBoolean(intent: Intent, key: String): Boolean? {
        if (!intent.hasExtra(key)) {
            return null
        }
        val raw = intent.getStringExtra(key) ?: return intent.getBooleanExtra(key, false)
        return raw.equals("true", ignoreCase = true) || raw == "1" || raw.equals("yes", ignoreCase = true)
    }
}
