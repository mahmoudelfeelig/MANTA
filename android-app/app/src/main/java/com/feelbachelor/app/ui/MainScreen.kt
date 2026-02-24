package com.feelbachelor.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.feelbachelor.app.core.model.AlertSeverity
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.TriageStatus
import com.feelbachelor.app.core.settings.EndpointConfig
import com.feelbachelor.app.domain.detection.AnomalyEngine
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.flow.distinctUntilChanged

private const val ALL_MODELS_KEY = "__all_models__"

private val KNOWN_MODEL_FILTERS = listOf(
    AnomalyEngine.MODE_ENSEMBLE,
    AnomalyEngine.MODE_STATISTICAL,
    AnomalyEngine.MODE_LINEAR,
    AnomalyEngine.MODE_TFLITE
)

private enum class MainTab(val label: String) {
    HOME("Home"),
    ALERTS("Alerts"),
    SETTINGS("Settings")
}

private enum class SeverityFilter(val label: String) {
    ALL("All"),
    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low")
}

private enum class TriageFilter(val label: String) {
    ALL("All"),
    OPEN("Open"),
    INVESTIGATING("Investigating"),
    RESOLVED("Resolved"),
    FALSE_POSITIVE("False +")
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
fun MainScreen(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    alertsTotalCount: Int,
    hasMoreAlerts: Boolean,
    isLoadingMoreAlerts: Boolean,
    statusMessage: String?,
    onSaveBackendUrl: (String) -> Unit,
    onSaveApiToken: (String) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSaveThresholds: (Double, Double) -> Unit,
    onSetDetectionModel: (String) -> Unit,
    onSetShadowModel: (String?) -> Unit,
    onSyncPolicy: () -> Unit,
    onAcceptConsent: () -> Unit,
    onExportDataset: () -> Unit,
    onExportForensics: () -> Unit,
    onLoadMoreAlerts: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onPurgeData: () -> Unit,
    onUpdateTriage: (String, TriageStatus) -> Unit
) {
    var backendUrl by rememberSaveable(config.backendUrl) { mutableStateOf(config.backendUrl) }
    var apiToken by rememberSaveable(config.apiToken) { mutableStateOf(config.apiToken) }
    var mediumThreshold by rememberSaveable(config.mediumThreshold) { mutableStateOf(config.mediumThreshold.toString()) }
    var highThreshold by rememberSaveable(config.highThreshold) { mutableStateOf(config.highThreshold.toString()) }
    var selectedTab by rememberSaveable { mutableStateOf(MainTab.HOME) }
    var severityFilter by rememberSaveable { mutableStateOf(SeverityFilter.ALL) }
    var triageFilter by rememberSaveable { mutableStateOf(TriageFilter.ALL) }
    var selectedModelFilter by rememberSaveable { mutableStateOf(ALL_MODELS_KEY) }
    var searchQuery by rememberSaveable { mutableStateOf("") }

    val modelFilters = remember(alerts) {
        buildList {
            add(ALL_MODELS_KEY)
            addAll(KNOWN_MODEL_FILTERS)
            addAll(alerts.map { it.sourceModel }.distinct().sorted())
        }.distinct()
    }

    val filteredAlerts = remember(alerts, severityFilter, triageFilter, selectedModelFilter, searchQuery) {
        alerts.filter { alert ->
            val severityMatches = when (severityFilter) {
                SeverityFilter.ALL -> true
                SeverityFilter.HIGH -> alert.severity == AlertSeverity.HIGH
                SeverityFilter.MEDIUM -> alert.severity == AlertSeverity.MEDIUM
                SeverityFilter.LOW -> alert.severity == AlertSeverity.LOW
            }
            val triageMatches = when (triageFilter) {
                TriageFilter.ALL -> true
                TriageFilter.OPEN -> alert.triageStatus == TriageStatus.OPEN
                TriageFilter.INVESTIGATING -> alert.triageStatus == TriageStatus.INVESTIGATING
                TriageFilter.RESOLVED -> alert.triageStatus == TriageStatus.RESOLVED
                TriageFilter.FALSE_POSITIVE -> alert.triageStatus == TriageStatus.FALSE_POSITIVE
            }
            val modelMatches = selectedModelFilter == ALL_MODELS_KEY || alert.sourceModel == selectedModelFilter
            val query = searchQuery.trim().lowercase()
            val searchMatches = if (query.isBlank()) {
                true
            } else {
                alert.appId.lowercase().contains(query) ||
                    displayAppName(alert.appId).lowercase().contains(query) ||
                    modelDisplayName(alert.sourceModel).lowercase().contains(query) ||
                    alert.explanation.lowercase().contains(query) ||
                    alert.topFeatures.any { it.lowercase().contains(query) }
            }
            severityMatches && triageMatches && modelMatches && searchMatches
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Feel Endpoint", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Policy v${config.policyVersion} • Retention ${config.retentionDays} days",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                MainTab.values().forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = {
                            val icon = when (tab) {
                                MainTab.HOME -> Icons.Filled.Home
                                MainTab.ALERTS -> Icons.Filled.Notifications
                                MainTab.SETTINGS -> Icons.Filled.Settings
                            }
                            Icon(imageVector = icon, contentDescription = tab.label)
                        },
                        label = { Text(tab.label) }
                    )
                }
            }
        },
        containerColor = MaterialTheme.colorScheme.background
    ) { contentPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(contentPadding)
        ) {
            when (selectedTab) {
                MainTab.HOME -> HomeView(
                    config = config,
                    alerts = alerts,
                    statusMessage = statusMessage,
                    onAcceptConsent = onAcceptConsent,
                    onStartCapture = onStartCapture,
                    onStopCapture = onStopCapture,
                    onSyncPolicy = onSyncPolicy,
                    onExportDataset = onExportDataset,
                    onExportForensics = onExportForensics,
                    onPurgeData = onPurgeData
                )

                MainTab.ALERTS -> AlertsView(
                    alerts = filteredAlerts,
                    allAlertsCount = alertsTotalCount,
                    hasMoreAlerts = hasMoreAlerts,
                    isLoadingMoreAlerts = isLoadingMoreAlerts,
                    statusMessage = statusMessage,
                    searchQuery = searchQuery,
                    onSearchQueryChange = { searchQuery = it },
                    severityFilter = severityFilter,
                    onSeverityFilterChange = { severityFilter = it },
                    triageFilter = triageFilter,
                    onTriageFilterChange = { triageFilter = it },
                    modelFilters = modelFilters,
                    selectedModelFilter = selectedModelFilter,
                    onModelFilterChange = { selectedModelFilter = it },
                    onLoadMoreAlerts = onLoadMoreAlerts,
                    onUpdateTriage = onUpdateTriage
                )

                MainTab.SETTINGS -> SettingsView(
                    config = config,
                    statusMessage = statusMessage,
                    backendUrl = backendUrl,
                    onBackendUrlChange = { backendUrl = it },
                    onSaveBackendUrl = { onSaveBackendUrl(backendUrl) },
                    apiToken = apiToken,
                    onApiTokenChange = { apiToken = it },
                    onSaveApiToken = { onSaveApiToken(apiToken) },
                    mediumThreshold = mediumThreshold,
                    onMediumThresholdChange = { mediumThreshold = it },
                    highThreshold = highThreshold,
                    onHighThresholdChange = { highThreshold = it },
                    onSaveThresholds = {
                        val medium = mediumThreshold.toDoubleOrNull() ?: config.mediumThreshold
                        val high = highThreshold.toDoubleOrNull() ?: config.highThreshold
                        onSaveThresholds(medium, high)
                    },
                    onSetDetectionModel = onSetDetectionModel,
                    onSetShadowModel = onSetShadowModel,
                    onToggleExport = onToggleExport,
                    onSyncPolicy = onSyncPolicy,
                    onExportDataset = onExportDataset,
                    onExportForensics = onExportForensics,
                    onPurgeData = onPurgeData
                )
            }
        }
    }
}

@Composable
private fun HomeView(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    statusMessage: String?,
    onAcceptConsent: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onSyncPolicy: () -> Unit,
    onExportDataset: () -> Unit,
    onExportForensics: () -> Unit,
    onPurgeData: () -> Unit
) {
    val highCount = alerts.count { it.severity == AlertSeverity.HIGH }
    val mediumCount = alerts.count { it.severity == AlertSeverity.MEDIUM }
    val openCount = alerts.count { it.triageStatus == TriageStatus.OPEN }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Capture", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (config.captureEnabled) "Capture is currently active."
                    else "Capture is currently stopped.",
                    style = MaterialTheme.typography.bodyMedium
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onStartCapture,
                        enabled = config.consentAccepted && !config.captureEnabled
                    ) {
                        Text("Start capture")
                    }
                    OutlinedButton(
                        onClick = onStopCapture,
                        enabled = config.captureEnabled
                    ) {
                        Text("Stop capture")
                    }
                }
            }
        }

        if (!config.consentAccepted) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)
            ) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("Consent required", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Only metadata is collected via VPNService. Packet payload is never inspected. " +
                            "You can disable export at any time in Settings."
                    )
                    Button(onClick = onAcceptConsent) {
                        Text("I understand and consent")
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text("Alert overview", style = MaterialTheme.typography.titleMedium)
                Text("Total alerts: ${alerts.size}")
                Text("Open triage: $openCount")
                Text("High severity: $highCount")
                Text("Medium severity: $mediumCount")
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Export: ${if (config.exportEnabled) "Enabled" else "Disabled"}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Quick actions", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onSyncPolicy, modifier = Modifier.weight(1f)) {
                        Text("Sync policy")
                    }
                    OutlinedButton(onClick = onExportDataset, modifier = Modifier.weight(1f)) {
                        Text("Export snapshot")
                    }
                }
                OutlinedButton(onClick = onExportForensics, modifier = Modifier.fillMaxWidth()) {
                    Text("Export forensics bundle")
                }
                OutlinedButton(onClick = onPurgeData, modifier = Modifier.fillMaxWidth()) {
                    Text("Purge local data")
                }
            }
        }

        if (!statusMessage.isNullOrBlank()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Text(
                    text = statusMessage,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun AlertsView(
    alerts: List<AnomalyAlert>,
    allAlertsCount: Int,
    hasMoreAlerts: Boolean,
    isLoadingMoreAlerts: Boolean,
    statusMessage: String?,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    severityFilter: SeverityFilter,
    onSeverityFilterChange: (SeverityFilter) -> Unit,
    triageFilter: TriageFilter,
    onTriageFilterChange: (TriageFilter) -> Unit,
    modelFilters: List<String>,
    selectedModelFilter: String,
    onModelFilterChange: (String) -> Unit,
    onLoadMoreAlerts: () -> Unit,
    onUpdateTriage: (String, TriageStatus) -> Unit
) {
    var filtersExpanded by rememberSaveable { mutableStateOf(false) }
    val listState = rememberLazyListState()

    val activeFilterCount = (
        (if (severityFilter != SeverityFilter.ALL) 1 else 0) +
            (if (triageFilter != TriageFilter.ALL) 1 else 0) +
            (if (selectedModelFilter != ALL_MODELS_KEY) 1 else 0) +
            (if (searchQuery.isNotBlank()) 1 else 0)
        )

    LaunchedEffect(listState, hasMoreAlerts, isLoadingMoreAlerts, alerts.size) {
        snapshotFlow {
            val lastVisible = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: -1
            lastVisible to listState.layoutInfo.totalItemsCount
        }
            .distinctUntilChanged()
            .collect { (lastVisible, totalItems) ->
                if (
                    hasMoreAlerts &&
                    !isLoadingMoreAlerts &&
                    totalItems > 0 &&
                    alerts.size >= 10 &&
                    lastVisible >= totalItems - 4
                ) {
                    onLoadMoreAlerts()
                }
            }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Filters", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (activeFilterCount > 0) "$activeFilterCount active" else "No active filters",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }

                    OutlinedButton(onClick = { filtersExpanded = !filtersExpanded }) {
                        Text(if (filtersExpanded) "Hide" else "Show")
                    }
                }

                if (activeFilterCount > 0) {
                    OutlinedButton(
                        onClick = {
                            onSearchQueryChange("")
                            onSeverityFilterChange(SeverityFilter.ALL)
                            onTriageFilterChange(TriageFilter.ALL)
                            onModelFilterChange(ALL_MODELS_KEY)
                        }
                    ) {
                        Text("Reset filters")
                    }
                }

                AnimatedVisibility(visible = filtersExpanded) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = onSearchQueryChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Search app / model / explanation") }
                        )

                        Text("Severity", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(SeverityFilter.values().toList()) { filter ->
                                FilterChip(
                                    selected = filter == severityFilter,
                                    onClick = { onSeverityFilterChange(filter) },
                                    label = { Text(filter.label) }
                                )
                            }
                        }

                        Text("Triage", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(TriageFilter.values().toList()) { filter ->
                                FilterChip(
                                    selected = filter == triageFilter,
                                    onClick = { onTriageFilterChange(filter) },
                                    label = { Text(filter.label) }
                                )
                            }
                        }

                        Text("Model", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(modelFilters) { model ->
                                val label = if (model == ALL_MODELS_KEY) "All" else modelDisplayName(model)
                                FilterChip(
                                    selected = model == selectedModelFilter,
                                    onClick = { onModelFilterChange(model) },
                                    label = { Text(label) }
                                )
                            }
                        }
                    }
                }

                Text(
                    "Showing ${alerts.size} filtered alerts • $allAlertsCount total stored",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (!statusMessage.isNullOrBlank()) {
            Text(
                text = statusMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp)
            )
        }

        if (alerts.isEmpty()) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("No alerts match the current filters.")
                    if (hasMoreAlerts) {
                        OutlinedButton(onClick = onLoadMoreAlerts, enabled = !isLoadingMoreAlerts) {
                            if (isLoadingMoreAlerts) {
                                Text("Loading older alerts...")
                            } else {
                                Text("Load older alerts")
                            }
                        }
                    }
                }
            }
            return
        }

        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            contentPadding = PaddingValues(bottom = 12.dp)
        ) {
            items(items = alerts, key = { it.id }) { alert ->
                AlertCard(
                    alert = alert,
                    onUpdateTriage = { status -> onUpdateTriage(alert.id, status) }
                )
            }

            if (isLoadingMoreAlerts) {
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(modifier = Modifier.height(20.dp), strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Loading more alerts...")
                    }
                }
            } else if (hasMoreAlerts) {
                item {
                    OutlinedButton(
                        onClick = onLoadMoreAlerts,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp)
                    ) {
                        Text("Load more")
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsView(
    config: EndpointConfig,
    statusMessage: String?,
    backendUrl: String,
    onBackendUrlChange: (String) -> Unit,
    onSaveBackendUrl: () -> Unit,
    apiToken: String,
    onApiTokenChange: (String) -> Unit,
    onSaveApiToken: () -> Unit,
    mediumThreshold: String,
    onMediumThresholdChange: (String) -> Unit,
    highThreshold: String,
    onHighThresholdChange: (String) -> Unit,
    onSaveThresholds: () -> Unit,
    onSetDetectionModel: (String) -> Unit,
    onSetShadowModel: (String?) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSyncPolicy: () -> Unit,
    onExportDataset: () -> Unit,
    onExportForensics: () -> Unit,
    onPurgeData: () -> Unit
) {
    var isTokenVisible by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Backend connection", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = backendUrl,
                    onValueChange = onBackendUrlChange,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Backend Base URL (HTTPS)") }
                )
                Button(onClick = onSaveBackendUrl) {
                    Text("Save backend URL")
                }
                OutlinedTextField(
                    value = apiToken,
                    onValueChange = onApiTokenChange,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = if (isTokenVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { isTokenVisible = !isTokenVisible }) {
                            Icon(
                                imageVector = if (isTokenVisible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (isTokenVisible) "Hide token" else "Show token"
                            )
                        }
                    },
                    label = { Text("API token") }
                )
                Button(onClick = onSaveApiToken) {
                    Text("Save API token")
                }
                Text(
                    if (config.isConfigured()) "Backend config looks complete."
                    else "Backend URL and token are both required.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Detection settings", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Active model",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(KNOWN_MODEL_FILTERS) { model ->
                        FilterChip(
                            selected = config.detectionModel == model,
                            onClick = { onSetDetectionModel(model) },
                            label = { Text(modelDisplayName(model)) }
                        )
                    }
                }

                Text(
                    "Shadow model",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    item {
                        FilterChip(
                            selected = config.shadowModel.isNullOrBlank(),
                            onClick = { onSetShadowModel(null) },
                            label = { Text("Disabled") }
                        )
                    }
                    items(KNOWN_MODEL_FILTERS) { model ->
                        FilterChip(
                            selected = config.shadowModel == model,
                            onClick = { onSetShadowModel(model) },
                            label = { Text(modelDisplayName(model)) }
                        )
                    }
                }

                Text("Thresholds", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = mediumThreshold,
                        onValueChange = onMediumThresholdChange,
                        label = { Text("Medium") },
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = highThreshold,
                        onValueChange = onHighThresholdChange,
                        label = { Text("High") },
                        modifier = Modifier.weight(1f)
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onSaveThresholds, modifier = Modifier.weight(1f)) {
                        Text("Save thresholds")
                    }
                    OutlinedButton(onClick = onSyncPolicy, modifier = Modifier.weight(1f)) {
                        Text("Sync policy")
                    }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Data and export", style = MaterialTheme.typography.titleMedium)
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("Export to backend")
                        Text(
                            "Requires HTTPS backend",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(checked = config.exportEnabled, onCheckedChange = onToggleExport)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onExportDataset, modifier = Modifier.weight(1f)) {
                        Text("Export snapshot")
                    }
                    OutlinedButton(onClick = onExportForensics, modifier = Modifier.weight(1f)) {
                        Text("Forensics bundle")
                    }
                }
                OutlinedButton(onClick = onPurgeData, modifier = Modifier.fillMaxWidth()) {
                    Text("Purge data")
                }
            }
        }

        if (!statusMessage.isNullOrBlank()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Text(
                    text = statusMessage,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun AlertCard(
    alert: AnomalyAlert,
    onUpdateTriage: (TriageStatus) -> Unit
) {
    val container = severityColor(alert.severity)
    val accent = severityAccent(alert.severity)
    val appLabel = displayAppName(alert.appId)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = container),
        border = BorderStroke(1.dp, accent)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(appLabel, style = MaterialTheme.typography.titleMedium)
                    if (appLabel != alert.appId) {
                        Text(
                            "Identifier: ${alert.appId}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Text(
                    text = alert.severity.name,
                    color = accent,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
            }

            Text(
                "Score ${"%.3f".format(alert.anomalyScore)} • ${formatTimestamp(alert.createdAtMillis)}",
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                "Model: ${modelDisplayName(alert.sourceModel)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Confidence ${"%.0f".format(alert.confidence * 100)}% • Uncertainty ${"%.0f".format(alert.uncertainty * 100)}%",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (alert.occurrenceCount > 1) {
                Text(
                    "Recurring incident: ${alert.occurrenceCount} occurrences since ${formatTimestamp(alert.firstSeenMillis)}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            if (alert.beaconScore > 0.0 || alert.driftScore > 0.0) {
                Text(
                    "Beacon ${"%.2f".format(alert.beaconScore)} • Drift ${"%.2f".format(alert.driftScore)}",
                    style = MaterialTheme.typography.bodySmall
                )
            }

            if (alert.topFeatures.isNotEmpty()) {
                Text("Top contributors", style = MaterialTheme.typography.labelLarge)
                alert.topFeatures.take(3).forEach { feature ->
                    Text(
                        "• ${featureDisplayName(feature)}: ${featureExplanation(feature)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            Text(
                "Why this was flagged: ${alert.explanation}",
                style = MaterialTheme.typography.bodySmall
            )
            if (alert.dataQualityWarnings.isNotEmpty()) {
                Text(
                    "Data quality notes: ${alert.dataQualityWarnings.joinToString()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (!alert.suppressionReason.isNullOrBlank()) {
                Text(
                    "Suppression reason: ${alert.suppressionReason}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Text(
                "Triage: ${alert.triageStatus.label()}",
                style = MaterialTheme.typography.labelLarge
            )

            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(TriageStatus.values().toList()) { status ->
                    FilterChip(
                        selected = status == alert.triageStatus,
                        onClick = { onUpdateTriage(status) },
                        label = { Text(status.label()) }
                    )
                }
            }
        }
    }
}

private fun severityColor(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.HIGH -> Color(0xFFFFE9E9)
    AlertSeverity.MEDIUM -> Color(0xFFFFF4DE)
    AlertSeverity.LOW -> Color(0xFFEAF4FF)
}

private fun severityAccent(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.HIGH -> Color(0xFFD32F2F)
    AlertSeverity.MEDIUM -> Color(0xFFF57C00)
    AlertSeverity.LOW -> Color(0xFF1976D2)
}

private fun displayAppName(appId: String): String {
    return when {
        appId.startsWith("uid:") -> {
            val uid = appId.removePrefix("uid:").ifBlank { "unknown" }
            "Unknown app (UID $uid)"
        }

        appId.equals("unknown", ignoreCase = true) -> "Unknown app"
        else -> appId
    }
}

private fun modelDisplayName(model: String): String = when (model) {
    AnomalyEngine.MODE_ENSEMBLE -> "Fusion ensemble"
    AnomalyEngine.MODE_STATISTICAL -> "Statistical"
    AnomalyEngine.MODE_LINEAR -> "Linear model"
    AnomalyEngine.MODE_TFLITE -> "TFLite model"
    else -> model
}

private fun featureDisplayName(feature: String): String = when (feature) {
    "flow_count" -> "Connection volume"
    "bytes_out", "total_bytes_out" -> "Outgoing data"
    "bytes_in", "total_bytes_in" -> "Incoming data"
    "mean_packet_size" -> "Average packet size"
    "outbound_ratio" -> "Outbound ratio"
    "burstiness" -> "Burstiness"
    "novelty", "novelty_score" -> "Destination novelty"
    "conn_freq_delta", "connection_frequency_delta" -> "Connection frequency shift"
    else -> feature.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
}

private fun featureExplanation(feature: String): String = when (feature) {
    "flow_count" -> "Unusually high/low number of connections in this window"
    "bytes_out", "total_bytes_out" -> "Outgoing transfer volume differs from normal"
    "bytes_in", "total_bytes_in" -> "Incoming transfer volume differs from normal"
    "mean_packet_size" -> "Packet sizes are atypical for this app"
    "outbound_ratio" -> "Direction of traffic changed from normal behavior"
    "burstiness" -> "Traffic is more spiky than normal"
    "novelty", "novelty_score" -> "App contacted new or uncommon destinations"
    "conn_freq_delta", "connection_frequency_delta" -> "Connection frequency changed sharply"
    else -> "Contribution changed from the app's baseline"
}

private fun TriageStatus.label(): String = when (this) {
    TriageStatus.OPEN -> "Open"
    TriageStatus.INVESTIGATING -> "Investigating"
    TriageStatus.RESOLVED -> "Resolved"
    TriageStatus.FALSE_POSITIVE -> "False +"
}

private val timestampFormatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

private fun formatTimestamp(millis: Long): String {
    return Instant.ofEpochMilli(millis)
        .atZone(ZoneId.systemDefault())
        .format(timestampFormatter)
}
