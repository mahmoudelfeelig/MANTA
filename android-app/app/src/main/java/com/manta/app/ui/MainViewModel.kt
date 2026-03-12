package com.manta.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.manta.app.core.model.AnomalyAlert
import com.manta.app.core.model.RuntimeHealth
import com.manta.app.core.model.TriageStatus
import com.manta.app.core.model.ThresholdProfile
import com.manta.app.core.settings.AppProfile
import com.manta.app.core.settings.CustomPrivacyOptions
import com.manta.app.core.settings.EndpointConfig
import com.manta.app.core.settings.FusionWeights
import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.ThemeMode
import com.manta.app.di.AppContainer
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MainViewModel(
    private val container: AppContainer
) : ViewModel() {
    val config: StateFlow<EndpointConfig> = container.settingsStore.configFlow()

    private val _alerts = MutableStateFlow<List<AnomalyAlert>>(emptyList())
    val alerts: StateFlow<List<AnomalyAlert>> = _alerts
    private val _alertsTotalCount = MutableStateFlow(0)
    val alertsTotalCount: StateFlow<Int> = _alertsTotalCount
    private val _hasMoreAlerts = MutableStateFlow(false)
    val hasMoreAlerts: StateFlow<Boolean> = _hasMoreAlerts
    private val _isLoadingMoreAlerts = MutableStateFlow(false)
    val isLoadingMoreAlerts: StateFlow<Boolean> = _isLoadingMoreAlerts
    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage
    private val _runtimeHealth = MutableStateFlow(container.runtimeHealth())
    val runtimeHealth: StateFlow<RuntimeHealth> = _runtimeHealth
    init {
        viewModelScope.launch {
            while (true) {
                refreshAlerts(isLoadMore = false)
                _runtimeHealth.value = container.runtimeHealth()
                delay(5_000)
            }
        }
        viewModelScope.launch {
            delay(1_500)
            while (true) {
                refreshBackendConnection(showStatus = false)
                delay(2 * 60 * 1000L)
            }
        }
    }

    fun setBackendUrl(url: String) {
        container.settingsStore.setBackendUrl(url)
    }

    fun setApiToken(token: String) {
        container.settingsStore.setApiToken(token)
    }

    fun setExportEnabled(enabled: Boolean) {
        val wasEnabled = container.settingsStore.readConfig().exportEnabled
        container.settingsStore.setExportEnabled(enabled)
        viewModelScope.launch {
            if (!enabled) {
                _statusMessage.value = "Backend export disabled."
                return@launch
            }

            val backfilled = if (!wasEnabled) {
                container.repository.backfillRecentExports()
            } else {
                0
            }
            val sent = runCatching {
                container.repository.processExportQueue(container.eventClient)
            }.getOrDefault(0)
            val connectivity = runCatching { refreshBackendConnection(showStatus = false) }.getOrNull()
            val connectivitySuffix = connectivity?.getOrNull()?.let { " $it" }
                ?: connectivity?.exceptionOrNull()?.message?.let { " Backend check failed: $it" }
                ?: ""
            _statusMessage.value = buildString {
                append("Backend export enabled.")
                if (backfilled > 0) {
                    append(" Backfilled $backfilled recent local item(s).")
                }
                append(" Sent $sent queued event(s).")
                append(connectivitySuffix)
            }
        }
    }

    fun setCaptureEnabled(enabled: Boolean) {
        container.settingsStore.setCaptureEnabled(enabled)
    }

    fun setDetectionModel(model: String) {
        container.settingsStore.setDetectionModel(model)
    }

    fun setShadowModel(model: String?) {
        container.settingsStore.setShadowModel(model)
    }

    fun setThemeMode(mode: ThemeMode) {
        container.settingsStore.setThemeMode(mode)
        _statusMessage.value = "Theme set to ${mode.name.lowercase()}."
    }

    fun setDebugModeEnabled(enabled: Boolean) {
        container.settingsStore.setDebugModeEnabled(enabled)
        _runtimeHealth.value = container.runtimeHealth()
        _statusMessage.value = if (enabled) {
            "Debug mode enabled. Extra local diagnostics are now visible."
        } else {
            "Debug mode disabled."
        }
    }

    fun setTestModeEnabled(enabled: Boolean) {
        container.settingsStore.setTestModeEnabled(enabled)
        _runtimeHealth.value = container.runtimeHealth()
        _statusMessage.value = if (enabled) {
            "Test mode enabled. Browser-risk validation uses lower alert thresholds."
        } else {
            "Test mode disabled."
        }
    }

    fun setPrivacyMode(mode: PrivacyMode) {
        container.settingsStore.setPrivacyMode(mode)
        viewModelScope.launch {
            if (mode != PrivacyMode.OFF) {
                container.repository.clearPendingExports()
                _statusMessage.value = "Privacy mode set to ${mode.name.lowercase()}. Pending exports cleared; future backend export follows the selected anonymization policy."
            } else {
                _statusMessage.value = "Privacy mode disabled."
            }
        }
    }

    fun setCustomPrivacyOptions(options: CustomPrivacyOptions) {
        container.settingsStore.setCustomPrivacyOptions(options)
        _statusMessage.value = "Custom privacy options updated."
    }

    fun hasConsent(): Boolean = container.settingsStore.readConfig().consentAccepted

    fun acceptConsent() {
        container.settingsStore.setConsentAccepted(true)
        _statusMessage.value = "Consent saved. Capture can now be started."
    }

    fun setBaseThresholds(low: Double, medium: Double, high: Double) {
        container.settingsStore.setBaseThresholds(low, ThresholdProfile(medium, high))
    }

    fun setFusionWeights(weights: FusionWeights) {
        container.settingsStore.setFusionWeights(weights)
        val updated = container.settingsStore.readConfig().fusionWeights
        _statusMessage.value =
            "Fusion weights saved: stat ${"%.3f".format(updated.statistical)}, multi ${"%.3f".format(updated.multivariate)}, seq ${"%.3f".format(updated.sequence)}, linear ${"%.3f".format(updated.linear)}, TFLite ${"%.3f".format(updated.tflite)}, remote ${"%.3f".format(updated.remote)}."
    }

    fun setFalsePositiveBudgetPerAppDay(value: Int) {
        container.settingsStore.setFalsePositiveBudgetPerAppDay(value)
        _statusMessage.value = "False-positive budget set to ${container.settingsStore.readConfig().falsePositiveBudgetPerAppDay} alert(s) per app/day."
    }

    fun setDriftHighThreshold(value: Double) {
        container.settingsStore.setDriftHighThreshold(value)
        _statusMessage.value = "Drift contribution threshold set to ${"%.3f".format(container.settingsStore.readConfig().driftHighThreshold)}."
    }

    fun setAblationFlags(volume: Boolean, timing: Boolean, destination: Boolean) {
        container.settingsStore.setAblationFlags(volume = volume, timing = timing, destination = destination)
        _statusMessage.value = "Feature-group disabling updated. Volume=${volume}, timing=${timing}, destination=${destination}."
    }

    fun setAppProfile(appId: String, profile: AppProfile) {
        container.settingsStore.setAppProfile(appId, profile)
        _statusMessage.value = "Profile for $appId set to ${profile.name.lowercase()}."
    }

    fun appProfile(appId: String): AppProfile = container.settingsStore.getAppProfile(appId)

    fun syncPolicy() {
        viewModelScope.launch {
            val result = container.repository.syncRemotePolicy(container.eventClient)
            _statusMessage.value = result.fold(
                onSuccess = {
                    val updated = container.settingsStore.readConfig()
                    "Policy synced. Version ${updated.policyVersion}, export ${if (updated.exportEnabled) "enabled" else "disabled"}."
                },
                onFailure = { error ->
                    container.settingsStore.recordPolicySync(status = "failed", diffSummary = error.message)
                    "Policy sync failed: ${error.message}"
                }
            )
        }
    }

    fun pingBackend() {
        viewModelScope.launch {
            refreshBackendConnection(showStatus = true)
        }
    }

    fun flushExportQueueNow() {
        viewModelScope.launch {
            val backfilled = container.repository.backfillRecentExports()
            val sent = container.repository.processExportQueue(container.eventClient)
            val connectivity = runCatching { refreshBackendConnection(showStatus = false) }.getOrNull()
            val suffix = connectivity?.getOrNull()?.let { " $it" }
                ?: connectivity?.exceptionOrNull()?.message?.let { " Backend check failed: $it" }
                ?: ""
            _statusMessage.value = buildString {
                append("Manual export flush processed $sent event(s).")
                if (backfilled > 0) {
                    append(" Backfilled $backfilled recent local item(s).")
                }
                append(suffix)
            }
        }
    }

    fun updateAlertTriage(alertId: String, status: TriageStatus, note: String = "") {
        viewModelScope.launch {
            container.repository.updateAlertTriage(alertId = alertId, status = status, note = note)
            refreshAlerts(isLoadMore = false)
        }
    }

    fun markAlertDangerous(alertId: String) {
        viewModelScope.launch {
            container.repository.updateAlertTriage(
                alertId = alertId,
                status = TriageStatus.RESOLVED,
                note = "Marked dangerous"
            )
            container.repository.removeAlert(alertId)
            _statusMessage.value = "Alert marked dangerous and removed from the active list."
            refreshAlerts(isLoadMore = false)
        }
    }

    fun markAlertFalsePositive(alertId: String) {
        viewModelScope.launch {
            container.repository.updateAlertTriage(
                alertId = alertId,
                status = TriageStatus.FALSE_POSITIVE,
                note = "Marked false positive"
            )
            container.repository.removeAlert(alertId)
            _statusMessage.value = "Alert marked false positive and removed from the active list."
            refreshAlerts(isLoadMore = false)
        }
    }

    fun dismissAlertNeutral(alertId: String) {
        viewModelScope.launch {
            container.repository.removeAlert(alertId)
            _statusMessage.value = "Alert dismissed without affecting feedback."
            refreshAlerts(isLoadMore = false)
        }
    }

    fun removeAlert(alertId: String) {
        viewModelScope.launch {
            container.repository.removeAlert(alertId)
            _statusMessage.value = "Alert removed locally."
            refreshAlerts(isLoadMore = false)
        }
    }

    fun clearAllAlerts() {
        viewModelScope.launch {
            container.repository.clearAllAlerts()
            _alerts.value = emptyList()
            _alertsTotalCount.value = 0
            _hasMoreAlerts.value = false
            _statusMessage.value = "All local alerts cleared."
        }
    }

    fun purgeLocalData() {
        viewModelScope.launch {
            container.repository.purgeAllLocalData()
            _alerts.value = emptyList()
            _alertsTotalCount.value = 0
            _hasMoreAlerts.value = false
            _statusMessage.value = "Local data purged."
        }
    }

    fun loadMoreAlerts() {
        viewModelScope.launch {
            refreshAlerts(isLoadMore = false)
        }
    }

    fun exportDatasetSnapshot(maxRows: Int = 20_000) {
        viewModelScope.launch {
            val result = container.repository.exportLatestFlowsCsv(maxRows = maxRows)
            _statusMessage.value = result.fold(
                onSuccess = { path -> "Dataset snapshot exported: $path" },
                onFailure = { error -> "Export failed: ${error.message}" }
            )
        }
    }

    fun exportAlertsJson(maxRows: Int = 25_000) {
        viewModelScope.launch {
            val result = container.repository.exportLatestAlertsJson(maxRows = maxRows)
            _statusMessage.value = result.fold(
                onSuccess = { path -> "Alerts export written: $path" },
                onFailure = { error -> "Alerts export failed: ${error.message}" }
            )
        }
    }

    fun exportForensicsBundle(maxRows: Int = 20_000) {
        viewModelScope.launch {
            val result = container.repository.exportForensicsBundle(maxRows = maxRows)
            _statusMessage.value = result.fold(
                onSuccess = { path -> "Forensics bundle exported: $path" },
                onFailure = { error -> "Forensics export failed: ${error.message}" }
            )
        }
    }

    fun deviceIdPseudo(): String = container.settingsStore.getPseudonymousDeviceId()

    fun publishStatus(message: String) {
        _statusMessage.value = message
    }

    private suspend fun refreshBackendConnection(showStatus: Boolean): Result<String> {
        val config = container.settingsStore.readConfig()
        if (config.backendUrl.isBlank()) {
            if (showStatus) {
                _statusMessage.value = "Set a backend URL first."
            }
            return Result.failure(IllegalStateException("Backend URL is not configured"))
        }
        val result = container.repository.refreshBackendConnection(container.eventClient)
        if (showStatus) {
            _statusMessage.value = result.fold(
                onSuccess = { it },
                onFailure = { error -> "Server check failed: ${error.message}" }
            )
        }
        return result
    }

    private suspend fun refreshAlerts(isLoadMore: Boolean) {
        if (_isLoadingMoreAlerts.value) {
            return
        }

        if (isLoadMore) {
            _isLoadingMoreAlerts.value = true
        }
        runCatching {
            val total = container.repository.alertCount()
            val latest = container.repository.latestAlerts(limit = total.coerceIn(20, 250))
            _alerts.value = latest
            _alertsTotalCount.value = total
            _hasMoreAlerts.value = total > latest.size
        }.onFailure { error ->
            _statusMessage.value = "Alert refresh failed: ${error.message}"
        }
        if (isLoadMore) {
            _isLoadingMoreAlerts.value = false
        }
    }
}

class MainViewModelFactory(
    private val container: AppContainer
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            return MainViewModel(container) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
    }
}
