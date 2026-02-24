package com.feelbachelor.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.TriageStatus
import com.feelbachelor.app.core.model.ThresholdProfile
import com.feelbachelor.app.core.settings.EndpointConfig
import com.feelbachelor.app.di.AppContainer
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class MainViewModel(
    private val container: AppContainer
) : ViewModel() {
    companion object {
        private const val ALERT_PAGE_SIZE = 50
    }

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
    private var alertsLimit = ALERT_PAGE_SIZE

    init {
        viewModelScope.launch {
            while (true) {
                refreshAlerts(isLoadMore = false)
                delay(5_000)
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
        container.settingsStore.setExportEnabled(enabled)
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

    fun hasConsent(): Boolean = container.settingsStore.readConfig().consentAccepted

    fun acceptConsent() {
        container.settingsStore.setConsentAccepted(true)
        _statusMessage.value = "Consent saved. Capture can now be started."
    }

    fun setBaseThresholds(medium: Double, high: Double) {
        container.settingsStore.setBaseThresholds(ThresholdProfile(medium, high))
    }

    fun syncPolicy() {
        viewModelScope.launch {
            container.repository.syncRemotePolicy(container.eventClient)
        }
    }

    fun updateAlertTriage(alertId: String, status: TriageStatus, note: String = "") {
        viewModelScope.launch {
            container.repository.updateAlertTriage(alertId = alertId, status = status, note = note)
            refreshAlerts(isLoadMore = false)
        }
    }

    fun purgeLocalData() {
        viewModelScope.launch {
            container.repository.purgeAllLocalData()
            alertsLimit = ALERT_PAGE_SIZE
            _alerts.value = emptyList()
            _alertsTotalCount.value = 0
            _hasMoreAlerts.value = false
            _statusMessage.value = "Local data purged."
        }
    }

    fun loadMoreAlerts() {
        if (_isLoadingMoreAlerts.value || !_hasMoreAlerts.value) {
            return
        }
        viewModelScope.launch {
            alertsLimit += ALERT_PAGE_SIZE
            refreshAlerts(isLoadMore = true)
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

    fun exportForensicsBundle(maxRows: Int = 20_000) {
        viewModelScope.launch {
            val result = container.repository.exportForensicsBundle(maxRows = maxRows)
            _statusMessage.value = result.fold(
                onSuccess = { path -> "Forensics bundle exported: $path" },
                onFailure = { error -> "Forensics export failed: ${error.message}" }
            )
        }
    }

    private suspend fun refreshAlerts(isLoadMore: Boolean) {
        if (_isLoadingMoreAlerts.value) {
            return
        }

        if (isLoadMore) {
            _isLoadingMoreAlerts.value = true
        }
        runCatching {
            val latest = container.repository.latestAlerts(limit = alertsLimit)
            val total = container.repository.alertCount()
            _alerts.value = latest
            _alertsTotalCount.value = total
            _hasMoreAlerts.value = latest.size < total
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
