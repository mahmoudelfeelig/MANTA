package com.feelbachelor.app

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
import com.feelbachelor.app.service.FlowVpnService
import com.feelbachelor.app.ui.MainScreen
import com.feelbachelor.app.ui.MainViewModel
import com.feelbachelor.app.ui.MainViewModelFactory

class MainActivity : ComponentActivity() {
    private val app by lazy { application as FeelApplication }

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
            val alerts by viewModel.alerts.collectAsState()
            val statusMessage by viewModel.statusMessage.collectAsState()

            MainScreen(
                config = config,
                alerts = alerts,
                statusMessage = statusMessage,
                onSaveBackendUrl = viewModel::setBackendUrl,
                onSaveApiToken = viewModel::setApiToken,
                onToggleExport = viewModel::setExportEnabled,
                onSaveThresholds = viewModel::setBaseThresholds,
                onSyncPolicy = viewModel::syncPolicy,
                onAcceptConsent = viewModel::acceptConsent,
                onExportDataset = viewModel::exportDatasetSnapshot,
                onStartCapture = ::requestOrStartCapture,
                onStopCapture = ::stopCaptureService,
                onPurgeData = viewModel::purgeLocalData,
                onUpdateTriage = { alertId, status -> viewModel.updateAlertTriage(alertId, status) }
            )
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
