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
    val config: StateFlow<EndpointConfig> = container.settingsStore.configFlow()

    private val _alerts = MutableStateFlow<List<AnomalyAlert>>(emptyList())
    val alerts: StateFlow<List<AnomalyAlert>> = _alerts

    init {
        viewModelScope.launch {
            while (true) {
                _alerts.value = container.repository.latestAlerts(limit = 50)
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
            _alerts.value = container.repository.latestAlerts(limit = 50)
        }
    }

    fun purgeLocalData() {
        viewModelScope.launch {
            container.repository.purgeAllLocalData()
            _alerts.value = emptyList()
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
