package com.manta.app

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Canvas
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.manta.app.service.FlowVpnService
import com.manta.app.ui.MainScreen
import com.manta.app.ui.MainViewModel
import com.manta.app.ui.MainViewModelFactory
import com.manta.app.ui.theme.MantaTheme
import java.io.File
import java.io.FileOutputStream
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private val app by lazy { application as MantaApplication }

    private val viewModel: MainViewModel by viewModels {
        MainViewModelFactory(app.container)
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startCaptureService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            val config by viewModel.config.collectAsState()
            MantaTheme(themeMode = config.themeMode) {
                val alerts by viewModel.alerts.collectAsState()
                val alertsTotalCount by viewModel.alertsTotalCount.collectAsState()
                val hasMoreAlerts by viewModel.hasMoreAlerts.collectAsState()
                val isLoadingMoreAlerts by viewModel.isLoadingMoreAlerts.collectAsState()
                val statusMessage by viewModel.statusMessage.collectAsState()
                val deviceIdPseudo = viewModel.deviceIdPseudo()

                MainScreen(
                    config = config,
                    deviceIdPseudo = deviceIdPseudo,
                    alerts = alerts,
                    alertsTotalCount = alertsTotalCount,
                    hasMoreAlerts = hasMoreAlerts,
                    isLoadingMoreAlerts = isLoadingMoreAlerts,
                    statusMessage = statusMessage,
                    onSaveBackendUrl = viewModel::setBackendUrl,
                    onSaveApiToken = viewModel::setApiToken,
                    onToggleExport = viewModel::setExportEnabled,
                    onSaveThresholds = viewModel::setBaseThresholds,
                    onSaveFusionWeights = viewModel::setFusionWeights,
                    onSetFalsePositiveBudgetPerAppDay = viewModel::setFalsePositiveBudgetPerAppDay,
                    onSetDriftHighThreshold = viewModel::setDriftHighThreshold,
                    onSetAblationFlags = viewModel::setAblationFlags,
                    onSetDetectionModel = viewModel::setDetectionModel,
                    onSetShadowModel = viewModel::setShadowModel,
                    onSetThemeMode = viewModel::setThemeMode,
                    onSetDebugModeEnabled = viewModel::setDebugModeEnabled,
                    onSetPrivacyMode = viewModel::setPrivacyMode,
                    onSetCustomPrivacyOptions = viewModel::setCustomPrivacyOptions,
                    onSyncPolicy = viewModel::syncPolicy,
                    onPingBackend = viewModel::pingBackend,
                    onAcceptConsent = viewModel::acceptConsent,
                    onExportDataset = viewModel::exportDatasetSnapshot,
                    onExportForensics = viewModel::exportForensicsBundle,
                    onCaptureEvidence = ::captureEvidenceSnapshot,
                    onFlushExportQueue = viewModel::flushExportQueueNow,
                    onLoadMoreAlerts = viewModel::loadMoreAlerts,
                    onStartCapture = ::requestOrStartCapture,
                    onStopCapture = ::stopCaptureService,
                    onClearAlerts = viewModel::clearAllAlerts,
                    onPurgeData = viewModel::purgeLocalData,
                    onMarkAlertDangerous = viewModel::markAlertDangerous,
                    onMarkAlertFalsePositive = viewModel::markAlertFalsePositive,
                    onDismissAlertNeutral = viewModel::dismissAlertNeutral,
                    currentAppProfile = viewModel::appProfile,
                    onSetAppProfile = viewModel::setAppProfile
                )
            }
        }
    }

    private fun requestOrStartCapture() {
        if (!viewModel.hasConsent()) {
            Toast.makeText(this, "Consent is required before capture.", Toast.LENGTH_SHORT).show()
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startCaptureService()
        }
    }

    private fun startCaptureService() {
        viewModel.setCaptureEnabled(true)
        startService(FlowVpnService.startIntent(this))
    }

    private fun stopCaptureService() {
        viewModel.setCaptureEnabled(false)
        startService(FlowVpnService.stopIntent(this))
    }

    private fun captureEvidenceSnapshot() {
        val rootView = window.decorView.rootView
        if (rootView.width <= 0 || rootView.height <= 0) {
            viewModel.publishStatus("Evidence capture failed: screen size unavailable.")
            return
        }

        val exportRoot = File(getExternalFilesDir(null), "exports")
        if (!exportRoot.exists()) {
            exportRoot.mkdirs()
        }
        val timestamp = System.currentTimeMillis()
        val evidenceDir = File(exportRoot, "evidence-$timestamp")
        evidenceDir.mkdirs()

        val screenshotFile = File(evidenceDir, "screenshot.png")
        val bitmap = Bitmap.createBitmap(rootView.width, rootView.height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        rootView.draw(canvas)
        FileOutputStream(screenshotFile).use { output ->
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
        }

        val config = viewModel.config.value
        val alerts = viewModel.alerts.value
        val stateFile = File(evidenceDir, "ui-state.json")
        val statePayload = JSONObject()
            .put("captured_at", timestamp)
            .put("device_policy_id", viewModel.deviceIdPseudo())
            .put("status_message", viewModel.statusMessage.value)
                .put("config", JSONObject()
                    .put("backend_url", config.backendUrl)
                    .put("export_enabled", config.exportEnabled)
                    .put("privacy_mode", config.privacyMode.name.lowercase())
                    .put("debug_mode_enabled", config.debugModeEnabled)
                    .put("detection_model", config.detectionModel)
                    .put("shadow_model", config.shadowModel)
                    .put("threshold_low", config.lowThreshold)
                    .put("threshold_medium", config.mediumThreshold)
                    .put("threshold_high", config.highThreshold)
                .put("fusion_weights", JSONObject()
                    .put("statistical", config.fusionWeights.statistical)
                    .put("multivariate", config.fusionWeights.multivariate)
                    .put("sequence", config.fusionWeights.sequence)
                    .put("linear", config.fusionWeights.linear)
                    .put("tflite", config.fusionWeights.tflite)
                    .put("remote", config.fusionWeights.remote)
                    .put("beacon", config.fusionWeights.beacon)
                    .put("drift", config.fusionWeights.drift)
                    .put("reputation", config.fusionWeights.reputation)
                    .put("data_quality_penalty", config.fusionWeights.dataQualityPenalty)
                    .put("response_anomaly", config.fusionWeights.responseAnomalyBlend)
                    .put("response_context", config.fusionWeights.responseContextBlend)
                )
            )
            .put("alerts", alerts.take(50).map { alert ->
                JSONObject()
                    .put("id", alert.id)
                    .put("app_id", alert.appId)
                    .put("severity", alert.severity.name)
                    .put("score", alert.anomalyScore)
                    .put("source_model", alert.sourceModel)
                    .put("triage_status", alert.triageStatus.name)
                    .put("explanation", alert.explanation)
            })
        stateFile.writeText(statePayload.toString(2), Charsets.UTF_8)

        viewModel.publishStatus("Evidence snapshot captured: ${evidenceDir.absolutePath}")
    }
}
