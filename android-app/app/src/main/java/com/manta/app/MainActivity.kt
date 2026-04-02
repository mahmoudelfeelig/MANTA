package com.manta.app

import android.app.Activity
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
                val runtimeHealth by viewModel.runtimeHealth.collectAsState()
                val deviceIdPseudo = viewModel.deviceIdPseudo()

                MainScreen(
                    config = config,
                    deviceIdPseudo = deviceIdPseudo,
                    alerts = alerts,
                    alertsTotalCount = alertsTotalCount,
                    hasMoreAlerts = hasMoreAlerts,
                    isLoadingMoreAlerts = isLoadingMoreAlerts,
                    statusMessage = statusMessage,
                    runtimeHealth = runtimeHealth,
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
                    onSetTestModeEnabled = viewModel::setTestModeEnabled,
                    onSetPrivacyMode = viewModel::setPrivacyMode,
                    onSetCustomPrivacyOptions = viewModel::setCustomPrivacyOptions,
                    onSaveProtectedBrandsCsv = viewModel::setProtectedBrandsCsv,
                    onSyncPolicy = viewModel::syncPolicy,
                    onPingBackend = viewModel::pingBackend,
                    onAcceptConsent = viewModel::acceptConsent,
                    onExportDataset = viewModel::exportDatasetSnapshot,
                    onExportAlerts = viewModel::exportAlertsJson,
                    onExportForensics = viewModel::exportForensicsBundle,
                    onFlushExportQueue = viewModel::flushExportQueueNow,
                    onLoadMoreAlerts = viewModel::loadMoreAlerts,
                    onStartCapture = ::requestOrStartCapture,
                    onStopCapture = ::stopCaptureService,
                    onClearAlerts = viewModel::clearAllAlerts,
                    onPurgeData = viewModel::purgeLocalData,
                    onMarkAlertDangerous = viewModel::markAlertDangerous,
                    onMarkAlertFalsePositive = viewModel::markAlertFalsePositive,
                    onDismissAlertNeutral = viewModel::dismissAlertNeutral,
                    currentAppThresholdProfile = viewModel::thresholdProfile,
                    currentAppProfile = viewModel::appProfile,
                    onSetAppThresholdOverride = { appId, low, medium, high ->
                        viewModel.setAppThresholdOverride(appId, low, medium, high)
                    },
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
}
