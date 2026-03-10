package com.manta.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import android.content.pm.PackageManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.AnomalyAlert
import com.manta.app.core.model.TriageStatus
import com.manta.app.core.settings.AppProfile
import com.manta.app.core.settings.CustomPrivacyOptions
import com.manta.app.core.security.CryptoUtils
import com.manta.app.core.settings.EndpointConfig
import com.manta.app.core.settings.FusionWeights
import com.manta.app.core.settings.PrivacyMode
import com.manta.app.core.settings.ThemeMode
import com.manta.app.domain.detection.AnomalyEngine
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.delay

private const val ALL_MODELS_KEY = "__all_models__"

private val KNOWN_MODEL_FILTERS = listOf(
    AnomalyEngine.MODE_ENSEMBLE,
    AnomalyEngine.MODE_STATISTICAL,
    AnomalyEngine.MODE_MULTIVARIATE,
    AnomalyEngine.MODE_SEQUENCE,
    AnomalyEngine.MODE_LINEAR,
    AnomalyEngine.MODE_TFLITE,
    AnomalyEngine.MODE_REMOTE
)

private val BROWSER_APP_IDS = setOf(
    "com.android.chrome",
    "org.mozilla.firefox",
    "org.mozilla.firefox_beta",
    "org.mozilla.fenix",
    "com.microsoft.emmx",
    "com.brave.browser",
    "com.opera.browser",
    "com.opera.mini.native",
    "com.sec.android.app.sbrowser",
    "com.duckduckgo.mobile.android",
    "com.vivaldi.browser",
    "com.kiwibrowser.browser"
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

private const val ALL_SHADOWS_KEY = "__all_shadows__"
private const val DISABLED_SHADOW_KEY = "__disabled_shadow__"

private data class PendingUndoAction(
    val alertId: String,
    val appLabel: String,
    val action: AlertAction
)

@Composable
@OptIn(ExperimentalMaterial3Api::class)
fun MainScreen(
    config: EndpointConfig,
    deviceIdPseudo: String,
    alerts: List<AnomalyAlert>,
    alertsTotalCount: Int,
    hasMoreAlerts: Boolean,
    isLoadingMoreAlerts: Boolean,
    statusMessage: String?,
    onSaveBackendUrl: (String) -> Unit,
    onSaveApiToken: (String) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSaveThresholds: (Double, Double, Double) -> Unit,
    onSaveFusionWeights: (FusionWeights) -> Unit,
    onSetFalsePositiveBudgetPerAppDay: (Int) -> Unit,
    onSetDriftHighThreshold: (Double) -> Unit,
    onSetAblationFlags: (Boolean, Boolean, Boolean) -> Unit,
    onSetDetectionModel: (String) -> Unit,
    onSetShadowModel: (String?) -> Unit,
    onSetThemeMode: (ThemeMode) -> Unit,
    onSetDebugModeEnabled: (Boolean) -> Unit,
    onSetPrivacyMode: (PrivacyMode) -> Unit,
    onSetCustomPrivacyOptions: (CustomPrivacyOptions) -> Unit,
    onSyncPolicy: () -> Unit,
    onPingBackend: () -> Unit,
    onAcceptConsent: () -> Unit,
    onExportDataset: () -> Unit,
    onExportForensics: () -> Unit,
    onCaptureEvidence: () -> Unit,
    onFlushExportQueue: () -> Unit,
    onLoadMoreAlerts: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onClearAlerts: () -> Unit,
    onPurgeData: () -> Unit,
    onMarkAlertDangerous: (String) -> Unit,
    onMarkAlertFalsePositive: (String) -> Unit,
    onDismissAlertNeutral: (String) -> Unit,
    currentAppProfile: (String) -> AppProfile,
    onSetAppProfile: (String, AppProfile) -> Unit
) {
    var backendUrl by rememberSaveable(config.backendUrl) { mutableStateOf(config.backendUrl) }
    var apiToken by rememberSaveable(config.apiToken) { mutableStateOf(config.apiToken) }
    var lowThreshold by rememberSaveable(config.lowThreshold) { mutableStateOf(formatDecimal(config.lowThreshold)) }
    var mediumThreshold by rememberSaveable(config.mediumThreshold) { mutableStateOf(formatDecimal(config.mediumThreshold)) }
    var highThreshold by rememberSaveable(config.highThreshold) { mutableStateOf(formatDecimal(config.highThreshold)) }
    var fusionStatisticalWeight by rememberSaveable(config.fusionWeights.statistical) { mutableStateOf(formatDecimal(config.fusionWeights.statistical)) }
    var fusionMultivariateWeight by rememberSaveable(config.fusionWeights.multivariate) { mutableStateOf(formatDecimal(config.fusionWeights.multivariate)) }
    var fusionSequenceWeight by rememberSaveable(config.fusionWeights.sequence) { mutableStateOf(formatDecimal(config.fusionWeights.sequence)) }
    var fusionLinearWeight by rememberSaveable(config.fusionWeights.linear) { mutableStateOf(formatDecimal(config.fusionWeights.linear)) }
    var fusionTfliteWeight by rememberSaveable(config.fusionWeights.tflite) { mutableStateOf(formatDecimal(config.fusionWeights.tflite)) }
    var fusionRemoteWeight by rememberSaveable(config.fusionWeights.remote) { mutableStateOf(formatDecimal(config.fusionWeights.remote)) }
    var fusionBeaconWeight by rememberSaveable(config.fusionWeights.beacon) { mutableStateOf(formatDecimal(config.fusionWeights.beacon)) }
    var fusionDriftWeight by rememberSaveable(config.fusionWeights.drift) { mutableStateOf(formatDecimal(config.fusionWeights.drift)) }
    var fusionReputationWeight by rememberSaveable(config.fusionWeights.reputation) { mutableStateOf(formatDecimal(config.fusionWeights.reputation)) }
    var fusionDataQualityPenaltyWeight by rememberSaveable(config.fusionWeights.dataQualityPenalty) { mutableStateOf(formatDecimal(config.fusionWeights.dataQualityPenalty)) }
    var responseAnomalyBlendWeight by rememberSaveable(config.fusionWeights.responseAnomalyBlend) { mutableStateOf(formatDecimal(config.fusionWeights.responseAnomalyBlend)) }
    var responseContextBlendWeight by rememberSaveable(config.fusionWeights.responseContextBlend) { mutableStateOf(formatDecimal(config.fusionWeights.responseContextBlend)) }
    var falsePositiveBudget by rememberSaveable(config.falsePositiveBudgetPerAppDay) { mutableStateOf(config.falsePositiveBudgetPerAppDay.toString()) }
    var driftHighThreshold by rememberSaveable(config.driftHighThreshold) { mutableStateOf(formatDecimal(config.driftHighThreshold)) }
    var selectedTab by rememberSaveable { mutableStateOf(MainTab.HOME) }
    var severityFilter by rememberSaveable { mutableStateOf(SeverityFilter.ALL) }
    var selectedModelFilter by rememberSaveable { mutableStateOf(ALL_MODELS_KEY) }
    var selectedShadowFilter by rememberSaveable { mutableStateOf(ALL_SHADOWS_KEY) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var modelInfoDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var alertsPage by rememberSaveable { mutableStateOf(1) }
    var hiddenAlertIds by rememberSaveable { mutableStateOf(setOf<String>()) }
    var pendingUndo by rememberSaveable { mutableStateOf<PendingUndoAction?>(null) }

    LaunchedEffect(
        config.backendUrl,
        config.apiToken,
        config.lowThreshold,
        config.mediumThreshold,
        config.highThreshold,
        config.falsePositiveBudgetPerAppDay,
        config.driftHighThreshold,
        config.fusionWeights.statistical,
        config.fusionWeights.multivariate,
        config.fusionWeights.sequence,
        config.fusionWeights.linear,
        config.fusionWeights.tflite,
        config.fusionWeights.remote,
        config.fusionWeights.beacon,
        config.fusionWeights.drift,
        config.fusionWeights.reputation,
        config.fusionWeights.dataQualityPenalty,
        config.fusionWeights.responseAnomalyBlend,
        config.fusionWeights.responseContextBlend
    ) {
        backendUrl = config.backendUrl
        apiToken = config.apiToken
        lowThreshold = formatDecimal(config.lowThreshold)
        mediumThreshold = formatDecimal(config.mediumThreshold)
        highThreshold = formatDecimal(config.highThreshold)
        falsePositiveBudget = config.falsePositiveBudgetPerAppDay.toString()
        driftHighThreshold = formatDecimal(config.driftHighThreshold)
        fusionStatisticalWeight = formatDecimal(config.fusionWeights.statistical)
        fusionMultivariateWeight = formatDecimal(config.fusionWeights.multivariate)
        fusionSequenceWeight = formatDecimal(config.fusionWeights.sequence)
        fusionLinearWeight = formatDecimal(config.fusionWeights.linear)
        fusionTfliteWeight = formatDecimal(config.fusionWeights.tflite)
        fusionRemoteWeight = formatDecimal(config.fusionWeights.remote)
        fusionBeaconWeight = formatDecimal(config.fusionWeights.beacon)
        fusionDriftWeight = formatDecimal(config.fusionWeights.drift)
        fusionReputationWeight = formatDecimal(config.fusionWeights.reputation)
        fusionDataQualityPenaltyWeight = formatDecimal(config.fusionWeights.dataQualityPenalty)
        responseAnomalyBlendWeight = formatDecimal(config.fusionWeights.responseAnomalyBlend)
        responseContextBlendWeight = formatDecimal(config.fusionWeights.responseContextBlend)
    }

    val visibleAlerts = remember(alerts, hiddenAlertIds) {
        alerts.filterNot { it.id in hiddenAlertIds }
    }

    val modelFilters = remember(visibleAlerts, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            listOf(ALL_MODELS_KEY) + KNOWN_MODEL_FILTERS
        } else {
            buildList {
                add(ALL_MODELS_KEY)
                addAll(KNOWN_MODEL_FILTERS)
                addAll(visibleAlerts.map { it.sourceModel }.distinct().sorted())
            }.distinct()
        }
    }

    val shadowFilters = remember(visibleAlerts, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            listOf(ALL_SHADOWS_KEY, DISABLED_SHADOW_KEY) + KNOWN_MODEL_FILTERS
        } else {
            buildList {
                add(ALL_SHADOWS_KEY)
                add(DISABLED_SHADOW_KEY)
                addAll(KNOWN_MODEL_FILTERS)
                addAll(visibleAlerts.mapNotNull { it.shadowModel }.distinct().sorted())
            }.distinct()
        }
    }

    val severityScopedAlerts = remember(visibleAlerts, selectedModelFilter, selectedShadowFilter, searchQuery, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            emptyList()
        } else {
            visibleAlerts.filter { alert ->
                val modelMatches = selectedModelFilter == ALL_MODELS_KEY || alert.sourceModel == selectedModelFilter
                val shadowMatches = when (selectedShadowFilter) {
                    ALL_SHADOWS_KEY -> true
                    DISABLED_SHADOW_KEY -> alert.shadowModel.isNullOrBlank()
                    else -> alert.shadowModel == selectedShadowFilter
                }
                val query = searchQuery.trim().lowercase()
                val searchMatches = if (query.isBlank()) {
                    true
                } else {
                    alert.appId.lowercase().contains(query) ||
                        displayAppName(alert.appId).lowercase().contains(query) ||
                        modelDisplayName(alert.sourceModel).lowercase().contains(query) ||
                        modelDisplayName(alert.shadowModel.orEmpty()).lowercase().contains(query) ||
                        (alert.siteHint?.lowercase()?.contains(query) == true) ||
                        alert.explanation.lowercase().contains(query) ||
                        alert.topFeatures.any { it.lowercase().contains(query) }
                }
                modelMatches && shadowMatches && searchMatches
            }
        }
    }

    val severityCounts = remember(severityScopedAlerts) {
        mapOf(
            SeverityFilter.ALL to severityScopedAlerts.size,
            SeverityFilter.HIGH to severityScopedAlerts.count { it.severity == AlertSeverity.HIGH },
            SeverityFilter.MEDIUM to severityScopedAlerts.count { it.severity == AlertSeverity.MEDIUM },
            SeverityFilter.LOW to severityScopedAlerts.count { it.severity == AlertSeverity.LOW }
        )
    }

    val filteredAlerts = remember(severityScopedAlerts, severityFilter) {
        severityScopedAlerts.filter { alert ->
            val severityMatches = when (severityFilter) {
                SeverityFilter.ALL -> true
                SeverityFilter.HIGH -> alert.severity == AlertSeverity.HIGH
                SeverityFilter.MEDIUM -> alert.severity == AlertSeverity.MEDIUM
                SeverityFilter.LOW -> alert.severity == AlertSeverity.LOW
            }
            severityMatches
        }
    }

    val totalAlertPages = remember(filteredAlerts) { maxOf(1, (filteredAlerts.size + 19) / 20) }
    val currentAlertsPage = alertsPage.coerceIn(1, totalAlertPages)
    val pagedAlerts = remember(filteredAlerts, currentAlertsPage) {
        filteredAlerts.drop((currentAlertsPage - 1) * 20).take(20)
    }

    LaunchedEffect(severityFilter, selectedModelFilter, selectedShadowFilter, searchQuery, visibleAlerts.size) {
        alertsPage = 1
    }

    LaunchedEffect(alerts) {
        val currentIds = alerts.map { it.id }.toSet()
        hiddenAlertIds = hiddenAlertIds.intersect(currentIds)
        if (pendingUndo != null && pendingUndo?.alertId !in currentIds) {
            pendingUndo = null
        }
    }

    LaunchedEffect(pendingUndo) {
        val pending = pendingUndo ?: return@LaunchedEffect
        delay(4500)
        if (pendingUndo == pending) {
            when (pending.action) {
                AlertAction.DANGEROUS -> onMarkAlertDangerous(pending.alertId)
                AlertAction.FALSE_POSITIVE -> onMarkAlertFalsePositive(pending.alertId)
                AlertAction.NEUTRAL -> onDismissAlertNeutral(pending.alertId)
            }
            pendingUndo = null
        }
    }

    fun queueUndoAction(alert: AnomalyAlert, action: AlertAction) {
        val previous = pendingUndo
        if (previous != null && previous.alertId != alert.id) {
            when (previous.action) {
                AlertAction.DANGEROUS -> onMarkAlertDangerous(previous.alertId)
                AlertAction.FALSE_POSITIVE -> onMarkAlertFalsePositive(previous.alertId)
                AlertAction.NEUTRAL -> onDismissAlertNeutral(previous.alertId)
            }
        }
        hiddenAlertIds = hiddenAlertIds + alert.id
        pendingUndo = PendingUndoAction(
            alertId = alert.id,
            appLabel = displayAppName(alert.appId),
            action = action
        )
    }

    fun undoPendingAction() {
        val pending = pendingUndo ?: return
        hiddenAlertIds = hiddenAlertIds - pending.alertId
        pendingUndo = null
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("MANTA Endpoint", style = MaterialTheme.typography.titleLarge)
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
                    onStopCapture = onStopCapture
                )

                MainTab.ALERTS -> AlertsView(
                    alerts = pagedAlerts,
                    allFilteredAlerts = filteredAlerts,
                    allAlertsCount = alertsTotalCount,
                    statusMessage = statusMessage,
                    searchQuery = searchQuery,
                    onSearchQueryChange = { searchQuery = it },
                    severityFilter = severityFilter,
                    onSeverityFilterChange = { severityFilter = it },
                    severityCounts = severityCounts,
                    modelFilters = modelFilters,
                    selectedModelFilter = selectedModelFilter,
                    onModelFilterChange = { selectedModelFilter = it },
                    shadowFilters = shadowFilters,
                    selectedShadowFilter = selectedShadowFilter,
                    onShadowFilterChange = { selectedShadowFilter = it },
                    onShowModelInfo = { modelInfoDialog = it },
                    currentPage = currentAlertsPage,
                    totalPages = totalAlertPages,
                    onPreviousPage = { alertsPage = (currentAlertsPage - 1).coerceAtLeast(1) },
                    onNextPage = { alertsPage = (currentAlertsPage + 1).coerceAtMost(totalAlertPages) },
                    onMarkDangerous = { alertId ->
                        visibleAlerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.DANGEROUS) }
                    },
                    onMarkFalsePositive = { alertId ->
                        visibleAlerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.FALSE_POSITIVE) }
                    },
                    onDismissNeutral = { alertId ->
                        visibleAlerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.NEUTRAL) }
                    },
                    onClearAlerts = onClearAlerts,
                    debugModeEnabled = config.debugModeEnabled,
                    privacyModeEnabled = config.privacyModeEnabled,
                    currentAppProfile = currentAppProfile,
                    onSetAppProfile = onSetAppProfile,
                    pendingUndo = pendingUndo,
                    onUndoPendingAction = ::undoPendingAction
                )

                MainTab.SETTINGS -> SettingsView(
                    config = config,
                    deviceIdPseudo = deviceIdPseudo,
                    statusMessage = statusMessage,
                    backendUrl = backendUrl,
                    onBackendUrlChange = { backendUrl = it },
                    onSaveBackendUrl = { onSaveBackendUrl(backendUrl) },
                    apiToken = apiToken,
                    onApiTokenChange = { apiToken = it },
                    onSaveApiToken = { onSaveApiToken(apiToken) },
                    lowThreshold = lowThreshold,
                    onLowThresholdChange = { lowThreshold = it },
                    mediumThreshold = mediumThreshold,
                    onMediumThresholdChange = { mediumThreshold = it },
                    highThreshold = highThreshold,
                    onHighThresholdChange = { highThreshold = it },
                    onSaveThresholds = {
                        val low = lowThreshold.toDoubleOrNull() ?: config.lowThreshold
                        val medium = mediumThreshold.toDoubleOrNull() ?: config.mediumThreshold
                        val high = highThreshold.toDoubleOrNull() ?: config.highThreshold
                        onSaveThresholds(low, medium, high)
                    },
                    fusionStatisticalWeight = fusionStatisticalWeight,
                    onFusionStatisticalWeightChange = { fusionStatisticalWeight = it },
                    fusionMultivariateWeight = fusionMultivariateWeight,
                    onFusionMultivariateWeightChange = { fusionMultivariateWeight = it },
                    fusionSequenceWeight = fusionSequenceWeight,
                    onFusionSequenceWeightChange = { fusionSequenceWeight = it },
                    fusionLinearWeight = fusionLinearWeight,
                    onFusionLinearWeightChange = { fusionLinearWeight = it },
                    fusionTfliteWeight = fusionTfliteWeight,
                    onFusionTfliteWeightChange = { fusionTfliteWeight = it },
                    fusionRemoteWeight = fusionRemoteWeight,
                    onFusionRemoteWeightChange = { fusionRemoteWeight = it },
                    fusionBeaconWeight = fusionBeaconWeight,
                    onFusionBeaconWeightChange = { fusionBeaconWeight = it },
                    fusionDriftWeight = fusionDriftWeight,
                    onFusionDriftWeightChange = { fusionDriftWeight = it },
                    fusionReputationWeight = fusionReputationWeight,
                    onFusionReputationWeightChange = { fusionReputationWeight = it },
                    fusionDataQualityPenaltyWeight = fusionDataQualityPenaltyWeight,
                    onFusionDataQualityPenaltyWeightChange = { fusionDataQualityPenaltyWeight = it },
                    responseAnomalyBlendWeight = responseAnomalyBlendWeight,
                    onResponseAnomalyBlendWeightChange = { responseAnomalyBlendWeight = it },
                    responseContextBlendWeight = responseContextBlendWeight,
                    onResponseContextBlendWeightChange = { responseContextBlendWeight = it },
                    falsePositiveBudget = falsePositiveBudget,
                    onFalsePositiveBudgetChange = { falsePositiveBudget = it },
                    driftHighThreshold = driftHighThreshold,
                    onDriftHighThresholdChange = { driftHighThreshold = it },
                    onSaveFusionWeights = {
                        onSaveFusionWeights(
                            FusionWeights(
                                statistical = fusionStatisticalWeight.toDoubleOrNull() ?: config.fusionWeights.statistical,
                                multivariate = fusionMultivariateWeight.toDoubleOrNull() ?: config.fusionWeights.multivariate,
                                sequence = fusionSequenceWeight.toDoubleOrNull() ?: config.fusionWeights.sequence,
                                linear = fusionLinearWeight.toDoubleOrNull() ?: config.fusionWeights.linear,
                                tflite = fusionTfliteWeight.toDoubleOrNull() ?: config.fusionWeights.tflite,
                                remote = fusionRemoteWeight.toDoubleOrNull() ?: config.fusionWeights.remote,
                                beacon = fusionBeaconWeight.toDoubleOrNull() ?: config.fusionWeights.beacon,
                                drift = fusionDriftWeight.toDoubleOrNull() ?: config.fusionWeights.drift,
                                reputation = fusionReputationWeight.toDoubleOrNull() ?: config.fusionWeights.reputation,
                                dataQualityPenalty = fusionDataQualityPenaltyWeight.toDoubleOrNull() ?: config.fusionWeights.dataQualityPenalty,
                                responseAnomalyBlend = responseAnomalyBlendWeight.toDoubleOrNull() ?: config.fusionWeights.responseAnomalyBlend,
                                responseContextBlend = responseContextBlendWeight.toDoubleOrNull() ?: config.fusionWeights.responseContextBlend
                            )
                        )
                    },
                    onSaveGuardrails = {
                        onSetFalsePositiveBudgetPerAppDay(
                            falsePositiveBudget.toIntOrNull() ?: config.falsePositiveBudgetPerAppDay
                        )
                        onSetDriftHighThreshold(
                            driftHighThreshold.toDoubleOrNull() ?: config.driftHighThreshold
                        )
                    },
                    onSetAblationFlags = onSetAblationFlags,
                    onSetDetectionModel = onSetDetectionModel,
                    onSetShadowModel = onSetShadowModel,
                    onShowModelInfo = { modelInfoDialog = it },
                    onSetThemeMode = onSetThemeMode,
                    onSetDebugModeEnabled = onSetDebugModeEnabled,
                    onSetPrivacyMode = onSetPrivacyMode,
                    onSetCustomPrivacyOptions = onSetCustomPrivacyOptions,
                    onToggleExport = onToggleExport,
                    onSyncPolicy = onSyncPolicy,
                    onPingBackend = onPingBackend,
                    onExportDataset = onExportDataset,
                    onExportForensics = onExportForensics,
                    onCaptureEvidence = onCaptureEvidence,
                    onFlushExportQueue = onFlushExportQueue,
                    onPurgeData = onPurgeData
                )
            }
        }
    }

    if (modelInfoDialog != null) {
        ModelInfoDialog(
            model = modelInfoDialog.orEmpty(),
            onDismiss = { modelInfoDialog = null }
        )
    }
}

@Composable
private fun HomeView(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    statusMessage: String?,
    onAcceptConsent: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit
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
                    "Export: ${if (config.isEffectiveExportEnabled()) "Enabled" else "Disabled"}",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
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
    allFilteredAlerts: List<AnomalyAlert>,
    allAlertsCount: Int,
    statusMessage: String?,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    severityFilter: SeverityFilter,
    onSeverityFilterChange: (SeverityFilter) -> Unit,
    severityCounts: Map<SeverityFilter, Int>,
    modelFilters: List<String>,
    selectedModelFilter: String,
    onModelFilterChange: (String) -> Unit,
    shadowFilters: List<String>,
    selectedShadowFilter: String,
    onShadowFilterChange: (String) -> Unit,
    onShowModelInfo: (String) -> Unit,
    currentPage: Int,
    totalPages: Int,
    onPreviousPage: () -> Unit,
    onNextPage: () -> Unit,
    onMarkDangerous: (String) -> Unit,
    onMarkFalsePositive: (String) -> Unit,
    onDismissNeutral: (String) -> Unit,
    onClearAlerts: () -> Unit,
    debugModeEnabled: Boolean,
    privacyModeEnabled: Boolean,
    currentAppProfile: (String) -> AppProfile,
    onSetAppProfile: (String, AppProfile) -> Unit,
    pendingUndo: PendingUndoAction?,
    onUndoPendingAction: () -> Unit
) {
    var filtersExpanded by rememberSaveable { mutableStateOf(false) }
    val activeFilterCount = (
        (if (severityFilter != SeverityFilter.ALL) 1 else 0) +
            (if (selectedModelFilter != ALL_MODELS_KEY) 1 else 0) +
            (if (selectedShadowFilter != ALL_SHADOWS_KEY) 1 else 0) +
            (if (searchQuery.isNotBlank()) 1 else 0)
        )

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(bottom = 12.dp)
    ) {
        item {
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
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = {
                                    onSearchQueryChange("")
                                    onSeverityFilterChange(SeverityFilter.ALL)
                                    onModelFilterChange(ALL_MODELS_KEY)
                                    onShadowFilterChange(ALL_SHADOWS_KEY)
                                }
                            ) {
                                Text("Reset filters")
                            }
                            if (allAlertsCount > 0) {
                                OutlinedButton(onClick = onClearAlerts) {
                                    Text("Clear all alerts")
                                }
                            }
                        }
                    } else if (allAlertsCount > 0) {
                        OutlinedButton(onClick = onClearAlerts) {
                            Text("Clear all alerts")
                        }
                    }

                    AnimatedVisibility(visible = filtersExpanded) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = searchQuery,
                                onValueChange = onSearchQueryChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Search app / model / explanation / site") }
                            )

                            Text("Severity", style = MaterialTheme.typography.labelLarge)
                            LazyRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                items(SeverityFilter.values().toList()) { filter ->
                                    FilterChip(
                                        selected = filter == severityFilter,
                                        onClick = { onSeverityFilterChange(filter) },
                                        label = { Text("${filter.label} (${severityCounts[filter] ?: 0})") }
                                    )
                                }
                            }

                            Text("Model", style = MaterialTheme.typography.labelLarge)
                            LazyRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                items(modelFilters) { model ->
                                    val label = if (model == ALL_MODELS_KEY) "All" else modelDisplayName(model)
                                    ModelInfoChip(
                                        label = label,
                                        selected = model == selectedModelFilter,
                                        onClick = { onModelFilterChange(model) },
                                        onLongPress = { if (model != ALL_MODELS_KEY) onShowModelInfo(model) }
                                    )
                                }
                            }

                            Text("Shadow", style = MaterialTheme.typography.labelLarge)
                            LazyRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                items(shadowFilters) { model ->
                                    val label = when (model) {
                                        ALL_SHADOWS_KEY -> "All"
                                        DISABLED_SHADOW_KEY -> "Disabled"
                                        else -> modelDisplayName(model)
                                    }
                                    ModelInfoChip(
                                        label = label,
                                        selected = model == selectedShadowFilter,
                                        onClick = { onShadowFilterChange(model) },
                                        onLongPress = {
                                            if (model != ALL_SHADOWS_KEY && model != DISABLED_SHADOW_KEY) onShowModelInfo(model)
                                        }
                                    )
                                }
                            }
                        }
                    }

                    Text(
                        "Showing ${alerts.size} alerts on this page • ${allFilteredAlerts.size} match the filters • $allAlertsCount total stored",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        if (!statusMessage.isNullOrBlank()) {
            item {
                Text(
                    text = statusMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 4.dp)
                )
            }
        }

        if (pendingUndo != null) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = when (pendingUndo.action) {
                                AlertAction.DANGEROUS -> "${pendingUndo.appLabel} marked dangerous."
                                AlertAction.FALSE_POSITIVE -> "${pendingUndo.appLabel} marked false positive."
                                AlertAction.NEUTRAL -> "${pendingUndo.appLabel} dismissed."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedButton(onClick = onUndoPendingAction) {
                            Text("Undo")
                        }
                    }
                }
            }
        }

        if (allFilteredAlerts.isEmpty()) {
            item {
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
                    }
                }
            }
        } else {
            items(items = alerts, key = { it.id }) { alert ->
                AlertCard(
                    alert = alert,
                    debugModeEnabled = debugModeEnabled,
                    privacyModeEnabled = privacyModeEnabled,
                    onMarkDangerous = { onMarkDangerous(alert.id) },
                    onMarkFalsePositive = { onMarkFalsePositive(alert.id) },
                    onDismissNeutral = { onDismissNeutral(alert.id) },
                    onShowInfo = { onShowModelInfo(it) },
                    currentProfile = currentAppProfile(alert.appId),
                    onSetAppProfile = { profile -> onSetAppProfile(alert.appId, profile) }
                )
            }
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "Page $currentPage of $totalPages",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = onPreviousPage, enabled = currentPage > 1) {
                                Text("Previous")
                            }
                            Button(onClick = onNextPage, enabled = currentPage < totalPages) {
                                Text("Next")
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsView(
    config: EndpointConfig,
    deviceIdPseudo: String,
    statusMessage: String?,
    backendUrl: String,
    onBackendUrlChange: (String) -> Unit,
    onSaveBackendUrl: () -> Unit,
    apiToken: String,
    onApiTokenChange: (String) -> Unit,
    onSaveApiToken: () -> Unit,
    lowThreshold: String,
    onLowThresholdChange: (String) -> Unit,
    mediumThreshold: String,
    onMediumThresholdChange: (String) -> Unit,
    highThreshold: String,
    onHighThresholdChange: (String) -> Unit,
    onSaveThresholds: () -> Unit,
    fusionStatisticalWeight: String,
    onFusionStatisticalWeightChange: (String) -> Unit,
    fusionMultivariateWeight: String,
    onFusionMultivariateWeightChange: (String) -> Unit,
    fusionSequenceWeight: String,
    onFusionSequenceWeightChange: (String) -> Unit,
    fusionLinearWeight: String,
    onFusionLinearWeightChange: (String) -> Unit,
    fusionTfliteWeight: String,
    onFusionTfliteWeightChange: (String) -> Unit,
    fusionRemoteWeight: String,
    onFusionRemoteWeightChange: (String) -> Unit,
    fusionBeaconWeight: String,
    onFusionBeaconWeightChange: (String) -> Unit,
    fusionDriftWeight: String,
    onFusionDriftWeightChange: (String) -> Unit,
    fusionReputationWeight: String,
    onFusionReputationWeightChange: (String) -> Unit,
    fusionDataQualityPenaltyWeight: String,
    onFusionDataQualityPenaltyWeightChange: (String) -> Unit,
    responseAnomalyBlendWeight: String,
    onResponseAnomalyBlendWeightChange: (String) -> Unit,
    responseContextBlendWeight: String,
    onResponseContextBlendWeightChange: (String) -> Unit,
    falsePositiveBudget: String,
    onFalsePositiveBudgetChange: (String) -> Unit,
    driftHighThreshold: String,
    onDriftHighThresholdChange: (String) -> Unit,
    onSaveFusionWeights: () -> Unit,
    onSaveGuardrails: () -> Unit,
    onSetAblationFlags: (Boolean, Boolean, Boolean) -> Unit,
    onSetDetectionModel: (String) -> Unit,
    onSetShadowModel: (String?) -> Unit,
    onShowModelInfo: (String) -> Unit,
    onSetThemeMode: (ThemeMode) -> Unit,
    onSetDebugModeEnabled: (Boolean) -> Unit,
    onSetPrivacyMode: (PrivacyMode) -> Unit,
    onSetCustomPrivacyOptions: (CustomPrivacyOptions) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSyncPolicy: () -> Unit,
    onPingBackend: () -> Unit,
    onExportDataset: () -> Unit,
    onExportForensics: () -> Unit,
    onCaptureEvidence: () -> Unit,
    onFlushExportQueue: () -> Unit,
    onPurgeData: () -> Unit
) {
    var isTokenVisible by rememberSaveable { mutableStateOf(false) }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(vertical = 16.dp, bottom = 24.dp)
    ) {
        item {
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
                        label = { Text("Backend Base URL (HTTPS or local HTTP)") }
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
                    Text(
                        "Device policy ID: $deviceIdPseudo",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Use this ID when setting or debugging remote policy on the backend.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(Icons.Filled.Palette, contentDescription = null)
                        Text("Appearance", style = MaterialTheme.typography.titleMedium)
                    }
                    Text(
                        "Choose how the app looks. System follows Android; light and dark force a mode locally.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        items(ThemeMode.values().toList()) { themeMode ->
                            FilterChip(
                                selected = config.themeMode == themeMode,
                                onClick = { onSetThemeMode(themeMode) },
                                label = { Text(themeMode.label()) }
                            )
                        }
                    }
                }
            }
        }

        item {
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

                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        items(KNOWN_MODEL_FILTERS) { model ->
                            ModelInfoChip(
                                label = modelDisplayName(model),
                                selected = config.detectionModel == model,
                                onClick = { onSetDetectionModel(model) },
                                onLongPress = { onShowModelInfo(model) }
                            )
                        }
                    }
                    Text(
                        "Long-press a model chip to see how it behaves and when to use it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Text(
                        "Shadow model",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "A shadow model runs alongside the active model for comparison and diagnostics. It does not decide alert severity on its own.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        item {
                            ModelInfoChip(
                                label = "Disabled",
                                selected = config.shadowModel.isNullOrBlank(),
                                onClick = { onSetShadowModel(null) },
                                onLongPress = { }
                            )
                        }
                        items(KNOWN_MODEL_FILTERS) { model ->
                            ModelInfoChip(
                                label = modelDisplayName(model),
                                selected = config.shadowModel == model,
                                onClick = { onSetShadowModel(model) },
                                onLongPress = { onShowModelInfo(model) }
                            )
                        }
                    }
                    Text(
                        "Backend retraining changes Remote assisted directly and the Remote contribution inside Fusion ensemble. Statistical, Multivariate, Sequence, Linear, and TFLite are not live-retrained here; they only react indirectly through thresholds and policy.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Text("Model blend weights", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "These weights control how much each scorer contributes inside the fusion ensemble. The six model weights are normalized automatically as one group.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = fusionStatisticalWeight,
                            onValueChange = onFusionStatisticalWeightChange,
                            label = { Text("Stat") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionMultivariateWeight,
                            onValueChange = onFusionMultivariateWeightChange,
                            label = { Text("Multi") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionSequenceWeight,
                            onValueChange = onFusionSequenceWeightChange,
                            label = { Text("Seq") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = fusionLinearWeight,
                            onValueChange = onFusionLinearWeightChange,
                            label = { Text("Linear") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionTfliteWeight,
                            onValueChange = onFusionTfliteWeightChange,
                            label = { Text("TFLite") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionRemoteWeight,
                            onValueChange = onFusionRemoteWeightChange,
                            label = { Text("Remote") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Text("Post-processing weights", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "These weights adjust the fused score after the model outputs are combined. Beacon, drift, reputation, and data-quality operate before the final response blend. Response anomaly/context decide how much the anomaly and context channels matter in the final score.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        items(listOf("signal:beacon", "signal:drift", "signal:reputation", "signal:data_quality", "signal:response_anomaly", "signal:response_context")) { infoKey ->
                            ModelInfoChip(
                                label = infoDisplayName(infoKey),
                                selected = false,
                                onClick = {},
                                onLongPress = { onShowModelInfo(infoKey) }
                            )
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = fusionBeaconWeight,
                            onValueChange = onFusionBeaconWeightChange,
                            label = { Text("Beacon") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionDriftWeight,
                            onValueChange = onFusionDriftWeightChange,
                            label = { Text("Drift") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = fusionReputationWeight,
                            onValueChange = onFusionReputationWeightChange,
                            label = { Text("Reputation") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = fusionDataQualityPenaltyWeight,
                            onValueChange = onFusionDataQualityPenaltyWeightChange,
                            label = { Text("DQ penalty") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = responseAnomalyBlendWeight,
                            onValueChange = onResponseAnomalyBlendWeightChange,
                            label = { Text("Resp anomaly") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = responseContextBlendWeight,
                            onValueChange = onResponseContextBlendWeightChange,
                            label = { Text("Resp context") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    OutlinedButton(onClick = onSaveFusionWeights, modifier = Modifier.fillMaxWidth()) {
                        Text("Save all fusion weights")
                    }
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("Thresholds and guardrails", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Low is the minimum score shown as an alert. Medium and High control severity bands. Guardrails reduce noisy alerting when the model is uncertain, drift is weak, or false positives pile up.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = lowThreshold,
                            onValueChange = onLowThresholdChange,
                            label = { Text("Low") },
                            modifier = Modifier.weight(1f)
                        )
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
                    Button(onClick = onSaveThresholds, modifier = Modifier.fillMaxWidth()) {
                        Text("Save thresholds")
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = falsePositiveBudget,
                            onValueChange = onFalsePositiveBudgetChange,
                            label = { Text("FP budget/day") },
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = driftHighThreshold,
                            onValueChange = onDriftHighThresholdChange,
                            label = { Text("Drift gate") },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    OutlinedButton(onClick = onSaveGuardrails, modifier = Modifier.fillMaxWidth()) {
                        Text("Save guardrails")
                    }
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("Data and export", style = MaterialTheme.typography.titleMedium)
                    Text("Export to backend")
                    Text(
                        if (config.privacyModeEnabled) {
                            "Privacy mode anonymizes backend export. Enabling export also backfills recent local flows and alerts so they appear in the dashboard."
                        } else {
                            "HTTPS recommended. Local HTTP is allowed for development backends. Enabling export also backfills recent local flows and alerts so they appear in the dashboard."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Switch(
                            checked = config.exportEnabled,
                            onCheckedChange = onToggleExport,
                            enabled = true
                        )
                    }
                    OutlinedButton(onClick = onPurgeData, modifier = Modifier.fillMaxWidth()) {
                        Text("Delete data")
                    }
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("Backend connectivity", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Server status: ${config.lastServerPingStatus ?: "unknown"} • ${formatOptionalTimestamp(config.lastServerPingEpoch)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Server detail: ${config.lastServerPingDetail ?: "none"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Device presence: ${config.lastDeviceHeartbeatStatus ?: "unknown"} • ${formatOptionalTimestamp(config.lastDeviceHeartbeatEpoch)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Device detail: ${config.lastDeviceHeartbeatDetail ?: "none"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Last successful export: ${formatOptionalTimestamp(config.lastExportSuccessEpoch)}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Last export batch size: ${config.lastExportSentCount}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(
                        "Last export error: ${config.lastExportError ?: "none"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Last policy sync: ${formatOptionalTimestamp(config.lastPolicySyncEpoch)} • ${config.lastPolicySyncStatus ?: "never"}",
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (!config.lastPolicyDiffSummary.isNullOrBlank()) {
                        Text(
                            "Last applied policy diff: ${config.lastPolicyDiffSummary}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onPingBackend, modifier = Modifier.weight(1f)) {
                            Text("Ping server")
                        }
                        OutlinedButton(onClick = onSyncPolicy, modifier = Modifier.weight(1f)) {
                            Text("Sync policy")
                        }
                    }
                    OutlinedButton(onClick = onFlushExportQueue, modifier = Modifier.fillMaxWidth()) {
                        Text("Send queued events now")
                    }
                    Text(
                        "Device presence refreshes automatically while the app is open and on the background heartbeat schedule.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("Privacy and debug", style = MaterialTheme.typography.titleMedium)

                    Text("Privacy mode", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "Choose how much destination and app detail is retained locally and exported to the backend.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        items(PrivacyMode.values().toList()) { mode ->
                            FilterChip(
                                selected = config.privacyMode == mode,
                                onClick = { onSetPrivacyMode(mode) },
                                label = { Text(mode.label()) }
                            )
                        }
                    }
                    Text(
                        privacyModeDescription(config.privacyMode),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    if (config.privacyMode == PrivacyMode.CUSTOM) {
                        val custom = config.customPrivacy
                        Text("Custom export controls", style = MaterialTheme.typography.labelLarge)
                        Text(
                            "Choose exactly which sensitive fields stay visible when using the custom privacy tier.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        CustomPrivacyToggleRow(
                            label = "Include app identifier",
                            description = "Export the real app/package name instead of a salted hash.",
                            checked = custom.includeAppId,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeAppId = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include site hint",
                            description = "Export resolved destination/domain hints when available.",
                            checked = custom.includeSiteHint,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeSiteHint = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include IP addresses",
                            description = "Export raw IP addresses instead of hashed IP values.",
                            checked = custom.includeIpAddresses,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeIpAddresses = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include exact ports",
                            description = "Keep exact ports instead of coarse service/ephemeral port buckets.",
                            checked = custom.includeExactPorts,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeExactPorts = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include device label",
                            description = "Export the human-friendly device label along with the pseudonymous device ID.",
                            checked = custom.includeDeviceLabel,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeDeviceLabel = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include explanations",
                            description = "Export top features, contributions, and narrative explanation fields.",
                            checked = custom.includeExplanations,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeExplanations = it)) }
                        )
                        CustomPrivacyToggleRow(
                            label = "Include feature window",
                            description = "Export the detailed feature-window summary with alert events.",
                            checked = custom.includeFeatureWindow,
                            onCheckedChange = { onSetCustomPrivacyOptions(custom.copy(includeFeatureWindow = it)) }
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Debug mode")
                            Text(
                                "Shows raw identifiers, destination details, model diagnostics, and debug actions.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = config.debugModeEnabled,
                            onCheckedChange = onSetDebugModeEnabled
                        )
                    }

                    if (config.debugModeEnabled) {
                        OutlinedButton(onClick = onFlushExportQueue, modifier = Modifier.fillMaxWidth()) {
                            Text("Flush export queue now")
                        }
                    }
                }
            }
        }

        if (!statusMessage.isNullOrBlank()) {
            item {
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
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
private fun ModelInfoChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    onLongPress: () -> Unit
) {
    val shape = RoundedCornerShape(18.dp)
    val containerColor = if (selected) {
        MaterialTheme.colorScheme.primaryContainer
    } else {
        MaterialTheme.colorScheme.surfaceVariant
    }
    val contentColor = if (selected) {
        MaterialTheme.colorScheme.onPrimaryContainer
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    val borderColor = if (selected) {
        MaterialTheme.colorScheme.primary
    } else {
        MaterialTheme.colorScheme.outline.copy(alpha = 0.5f)
    }

    Box(
        modifier = Modifier
            .defaultMinSize(minHeight = 40.dp)
            .border(width = 1.dp, color = borderColor, shape = shape)
            .background(color = containerColor, shape = shape)
            .combinedClickable(
                onClick = onClick,
                onLongClick = onLongPress
            )
            .padding(horizontal = 14.dp, vertical = 9.dp)
    ) {
        Text(
            text = label,
            color = contentColor,
            style = MaterialTheme.typography.labelLarge
        )
    }
}

@Composable
private fun ModelInfoDialog(
    model: String,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Filled.Info, contentDescription = null) },
        title = { Text(infoDisplayName(model)) },
        text = { Text(infoDescription(model)) },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}

private enum class AlertAction {
    DANGEROUS,
    FALSE_POSITIVE,
    NEUTRAL
}

@Composable
@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
private fun AlertCard(
    alert: AnomalyAlert,
    debugModeEnabled: Boolean,
    privacyModeEnabled: Boolean,
    onMarkDangerous: () -> Unit,
    onMarkFalsePositive: () -> Unit,
    onDismissNeutral: () -> Unit,
    onShowInfo: (String) -> Unit,
    currentProfile: AppProfile,
    onSetAppProfile: (AppProfile) -> Unit
) {
    val packageManager = LocalContext.current.packageManager
    val container = alertContainerColor(alert.severity)
    val contentColor = alertContentColor(alert.severity)
    val accent = alertAccentColor(alert.severity)
    val appLabel = remember(alert.appId) {
        resolveInstalledAppLabel(alert.appId, packageManager) ?: displayAppName(alert.appId)
    }
    val destinationSummary = formatDestinationSummary(alert = alert, privacyModeEnabled = privacyModeEnabled)
    val normalizedContributors = remember(alert.featureContributions, alert.responseScore) {
        normalizeContributors(alert.featureContributions, alert.responseScore)
    }
    val suppressionTokens = remember(alert.suppressionReason) {
        parseSuppressionTokens(alert.suppressionReason)
    }
    val cardShape = RoundedCornerShape(18.dp)
    var detailsOpen by rememberSaveable(alert.id) { mutableStateOf(false) }
    var exitAction by rememberSaveable(alert.id) { mutableStateOf<AlertAction?>(null) }
    var isVisible by rememberSaveable(alert.id) { mutableStateOf(true) }
    val dismissState = rememberSwipeToDismissBoxState(
        positionalThreshold = { distance -> distance * 0.35f },
        confirmValueChange = { value ->
            exitAction = when (value) {
                SwipeToDismissBoxValue.StartToEnd -> AlertAction.FALSE_POSITIVE
                SwipeToDismissBoxValue.EndToStart -> AlertAction.DANGEROUS
                SwipeToDismissBoxValue.Settled -> null
            }
            exitAction != null
        }
    )
    val dismissDirection = dismissState.dismissDirection
    val swipeTargetColor = when (dismissDirection) {
        SwipeToDismissBoxValue.StartToEnd -> Color(0xFF2E7D32)
        SwipeToDismissBoxValue.EndToStart -> Color(0xFFB3261E)
        SwipeToDismissBoxValue.Settled -> MaterialTheme.colorScheme.surfaceVariant
    }
    val swipeBackgroundColor by animateColorAsState(targetValue = swipeTargetColor, label = "alertSwipeBackground")

    LaunchedEffect(exitAction) {
        when (exitAction) {
            AlertAction.DANGEROUS -> {
                isVisible = false
                delay(220)
                onMarkDangerous()
            }

            AlertAction.FALSE_POSITIVE -> {
                isVisible = false
                delay(220)
                onMarkFalsePositive()
            }

            AlertAction.NEUTRAL -> {
                isVisible = false
                delay(220)
                onDismissNeutral()
            }

            null -> Unit
        }
    }

    AnimatedVisibility(
        visible = isVisible,
        exit = fadeOut() + shrinkVertically()
    ) {
        SwipeToDismissBox(
            state = dismissState,
            backgroundContent = {
                val label = when (dismissDirection) {
                    SwipeToDismissBoxValue.StartToEnd -> "False positive"
                    SwipeToDismissBoxValue.EndToStart -> "Dangerous"
                    SwipeToDismissBoxValue.Settled -> "Swipe right = false positive • left = dangerous"
                }
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .clip(cardShape)
                        .background(swipeBackgroundColor)
                        .padding(horizontal = 18.dp, vertical = 22.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        label,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = if (dismissDirection == SwipeToDismissBoxValue.EndToStart) {
                            Color.White
                        } else {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        }
                    )
                }
            }
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(cardShape)
                    .combinedClickable(
                        onClick = {},
                        onLongClick = { detailsOpen = true }
                    ),
                shape = cardShape,
                colors = CardDefaults.cardColors(
                    containerColor = container,
                    contentColor = contentColor
                ),
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
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp), modifier = Modifier.weight(1f)) {
                            Text(appLabel, style = MaterialTheme.typography.titleMedium)
                            Text(
                                formatTimestamp(alert.createdAtMillis),
                                style = MaterialTheme.typography.bodySmall,
                                color = contentColor.copy(alpha = 0.78f)
                            )
                        }
                        Text(
                            text = alert.severity.name,
                            color = accent,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        item {
                            ModelInfoChip(
                                label = modelDisplayName(alert.sourceModel),
                                selected = true,
                                onClick = {},
                                onLongPress = { onShowInfo(alert.sourceModel) }
                            )
                        }
                        if (!alert.shadowModel.isNullOrBlank()) {
                            item {
                                ModelInfoChip(
                                    label = "Shadow ${modelDisplayName(alert.shadowModel.orEmpty())}",
                                    selected = false,
                                    onClick = {},
                                    onLongPress = { onShowInfo(alert.shadowModel.orEmpty()) }
                                )
                            }
                        }
                    }

                    Text(
                        "Response ${"%.3f".format(alert.responseScore)} • Anomaly ${"%.3f".format(alert.baseAnomalyScore)} • Context ${"%.3f".format(alert.contextScore)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor.copy(alpha = 0.82f)
                    )
                    Text(
                        "Confidence ${"%.0f".format(alert.confidence * 100)}% • Uncertainty ${"%.0f".format(alert.uncertainty * 100)}%",
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor.copy(alpha = 0.78f)
                    )
                    if (!destinationSummary.isNullOrBlank()) {
                        Text(
                            destinationSummary,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    if (alert.occurrenceCount > 1) {
                        Text(
                            "Recurring incident: ${alert.occurrenceCount} occurrences since ${formatTimestamp(alert.firstSeenMillis)}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }

                    if (normalizedContributors.isNotEmpty()) {
                        Text("Top contributors", style = MaterialTheme.typography.labelLarge)
                        Text(
                            "Each score is normalized to this alert's response score.",
                            style = MaterialTheme.typography.bodySmall,
                            color = contentColor.copy(alpha = 0.78f)
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            normalizedContributors.forEach { (feature, contribution) ->
                                ModelInfoChip(
                                    label = "${featureDisplayName(feature)} ${formatDecimal(contribution)}",
                                    selected = false,
                                    onClick = {},
                                    onLongPress = { onShowInfo("feature:$feature") }
                                )
                            }
                        }
                    }

                    val badgeKeys = buildList {
                        if (alert.beaconScore > 0.0) add("signal:beacon")
                        if (alert.driftScore > 0.0) add("signal:drift")
                        if (suppressionTokens.isNotEmpty()) add("suppression:general")
                        suppressionTokens.forEach { add("suppression:$it") }
                    }
                    if (badgeKeys.isNotEmpty()) {
                        Text("Signals and guardrails", style = MaterialTheme.typography.labelLarge)
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            badgeKeys.forEach { key ->
                                ModelInfoChip(
                                    label = infoDisplayName(key),
                                    selected = false,
                                    onClick = {},
                                    onLongPress = { onShowInfo(key) }
                                )
                            }
                        }
                    }

                    if (alert.dataQualityWarnings.isNotEmpty()) {
                        Text(
                            "Data quality notes: ${alert.dataQualityWarnings.joinToString()}",
                            style = MaterialTheme.typography.bodySmall,
                            color = contentColor.copy(alpha = 0.78f)
                        )
                    }

                    if (debugModeEnabled) {
                        Text("Debug details", style = MaterialTheme.typography.labelLarge, color = accent)
                        Text(
                            "Alert ${alert.id.take(8)} • Window ${alert.featureWindowId.take(8)}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            "First seen ${formatTimestamp(alert.firstSeenMillis)} • Last seen ${formatTimestamp(alert.lastSeenMillis)}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            "Correlation ${alert.correlationKey.ifBlank { "none" }}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        if (!privacyModeEnabled) {
                            val networkTarget = buildString {
                                append("Target ")
                                append(alert.destinationIp ?: "unknown-ip")
                                alert.destinationPort?.let { append(":$it") }
                                if (!alert.destinationHash.isNullOrBlank()) {
                                    append(" • hash ${alert.destinationHash.take(12)}")
                                }
                            }
                            Text(networkTarget, style = MaterialTheme.typography.bodySmall)
                        }
                        if (alert.triageNote.isNotBlank()) {
                            Text("Triage note: ${alert.triageNote}", style = MaterialTheme.typography.bodySmall)
                        }
                    }

                    Text(
                        "App profile",
                        style = MaterialTheme.typography.labelLarge
                    )
                    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        items(AppProfile.values().toList()) { profile ->
                            ModelInfoChip(
                                label = profile.label(),
                                selected = profile == currentProfile,
                                onClick = { onSetAppProfile(profile) },
                                onLongPress = { onShowInfo("profile:${profile.name.lowercase()}") }
                            )
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { exitAction = AlertAction.DANGEROUS },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Dangerous")
                        }
                        OutlinedButton(
                            onClick = { exitAction = AlertAction.FALSE_POSITIVE },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                "False positive",
                                maxLines = 1,
                                softWrap = false,
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                        OutlinedButton(
                            onClick = { exitAction = AlertAction.NEUTRAL },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Neutral")
                        }
                    }
                }
            }
        }
    }

    if (detailsOpen) {
        AlertDialog(
            onDismissRequest = { detailsOpen = false },
            title = { Text(appLabel) },
            text = {
                Text(
                    buildString {
                        appendLine("App name: $appLabel")
                        appendLine("Package: ${alert.appId}")
                        appendLine()
                        appendLine("Severity: ${alert.severity.name}")
                        appendLine("Response score: ${"%.3f".format(alert.responseScore)}")
                        appendLine("  Final user-facing score after post-processing and blending.")
                        appendLine("Anomaly score: ${"%.3f".format(alert.baseAnomalyScore)}")
                        appendLine("  Detector-driven score before reputation/context blending.")
                        appendLine("Context score: ${"%.3f".format(alert.contextScore)}")
                        appendLine("  Destination/risk/context contribution added after the anomaly channel.")
                        appendLine("Model: ${modelDisplayName(alert.sourceModel)}")
                        appendLine("Confidence: ${"%.0f".format(alert.confidence * 100)}%")
                        appendLine("  Higher means the models agree more and the signal looks more stable.")
                        appendLine("Uncertainty: ${"%.0f".format(alert.uncertainty * 100)}%")
                        appendLine("  Higher means the signal is noisier or the models disagree more.")
                        appendLine("Created: ${formatTimestamp(alert.createdAtMillis)}")
                        if (!alert.shadowModel.isNullOrBlank()) {
                            appendLine("Shadow model: ${modelDisplayName(alert.shadowModel.orEmpty())} (${alert.shadowScore?.let { "%.3f".format(it) } ?: "n/a"})")
                        }
                        if (!destinationSummary.isNullOrBlank()) appendLine(destinationSummary)
                        if (!alert.suppressionReason.isNullOrBlank()) {
                            appendLine("Suppression / guardrail: ${alert.suppressionReason}")
                        }
                        appendLine()
                        appendLine(alert.explanation)
                    }
                )
            },
            confirmButton = {
                TextButton(onClick = { detailsOpen = false }) {
                    Text("Close")
                }
            }
        )
    }
}

@Composable
private fun alertContainerColor(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.HIGH -> MaterialTheme.colorScheme.errorContainer
    AlertSeverity.MEDIUM -> MaterialTheme.colorScheme.tertiaryContainer
    AlertSeverity.LOW -> MaterialTheme.colorScheme.secondaryContainer
}

@Composable
private fun alertContentColor(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.HIGH -> MaterialTheme.colorScheme.onErrorContainer
    AlertSeverity.MEDIUM -> MaterialTheme.colorScheme.onTertiaryContainer
    AlertSeverity.LOW -> MaterialTheme.colorScheme.onSecondaryContainer
}

@Composable
private fun alertAccentColor(severity: AlertSeverity): Color = when (severity) {
    AlertSeverity.HIGH -> MaterialTheme.colorScheme.error
    AlertSeverity.MEDIUM -> MaterialTheme.colorScheme.tertiary
    AlertSeverity.LOW -> MaterialTheme.colorScheme.secondary
}

private fun displayAppName(appId: String): String {
    return when {
        appId.startsWith("uid:") -> {
            val uid = appId.removePrefix("uid:").ifBlank { "unknown" }
            "Unknown app (UID $uid)"
        }

        appId.equals("unknown", ignoreCase = true) -> "Unknown app"
        appId == "com.android.chrome" -> "Google Chrome"
        appId == "org.mozilla.firefox" || appId == "org.mozilla.fenix" -> "Mozilla Firefox"
        appId == "com.microsoft.emmx" -> "Microsoft Edge"
        appId == "com.brave.browser" -> "Brave"
        appId == "com.sec.android.app.sbrowser" -> "Samsung Internet"
        appId == "com.duckduckgo.mobile.android" -> "DuckDuckGo Browser"
        else -> humanizePackageName(appId)
    }
}

private fun resolveInstalledAppLabel(packageName: String, packageManager: PackageManager?): String? {
    if (packageManager == null || packageName.isBlank() || packageName.startsWith("uid:") || !packageName.contains('.')) {
        return null
    }
    return runCatching {
        val appInfo = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(appInfo)?.toString()?.trim()
    }.getOrNull()?.takeIf { it.isNotBlank() }
}

private fun humanizePackageName(appId: String): String {
    if (!appId.contains('.')) {
        return appId
    }
    val segment = appId
        .split('.')
        .lastOrNull { part -> part.isNotBlank() && part !in setOf("android", "app", "mobile", "release", "debug") }
        ?: return appId
    return segment
        .replace('_', ' ')
        .replace('-', ' ')
        .replaceFirstChar { it.uppercaseChar() }
}

private fun modelDisplayName(model: String): String = when (model) {
    AnomalyEngine.MODE_ENSEMBLE -> "Fusion ensemble"
    AnomalyEngine.MODE_STATISTICAL -> "Statistical"
    AnomalyEngine.MODE_MULTIVARIATE -> "Multivariate"
    AnomalyEngine.MODE_SEQUENCE -> "Sequence"
    AnomalyEngine.MODE_LINEAR -> "Linear model"
    AnomalyEngine.MODE_TFLITE -> "TFLite model"
    AnomalyEngine.MODE_REMOTE -> "Remote assisted"
    else -> model
}

private fun infoDisplayName(key: String): String = when (key) {
    "signal:beacon" -> "Beacon"
    "signal:drift" -> "Drift"
    "signal:reputation" -> "Reputation"
    "signal:data_quality" -> "DQ penalty"
    "signal:response_anomaly" -> "Resp anomaly"
    "signal:response_context" -> "Resp context"
    "disable:volume" -> "Volume"
    "disable:timing" -> "Timing"
    "disable:destination" -> "Destination"
    else -> when {
        key.startsWith("feature:") -> featureDisplayName(key.removePrefix("feature:"))
        key.startsWith("profile:") -> profileDisplayName(key.removePrefix("profile:"))
        key.startsWith("suppression:") -> suppressionDisplayName(key.removePrefix("suppression:"))
        else -> modelDisplayName(key)
    }
}

private fun modelDescription(model: String): String = when (model) {
    AnomalyEngine.MODE_ENSEMBLE ->
        "Combines the statistical, multivariate, sequence, linear, TFLite, and remote scorers when available. It is the most balanced default and smooths short-lived spikes."
    AnomalyEngine.MODE_STATISTICAL ->
        "A lightweight baseline based on deviations in traffic features. Fastest and easiest to reason about, but usually less adaptive."
    AnomalyEngine.MODE_MULTIVARIATE ->
        "Uses a covariance-aware multivariate anomaly model with shrinkage, so correlated feature shifts are scored jointly instead of as independent spikes."
    AnomalyEngine.MODE_SEQUENCE ->
        "Uses transition rarity and temporal state shifts between windows to detect unusual behavior orderings, not just unusual magnitudes."
    AnomalyEngine.MODE_LINEAR ->
        "Uses the bundled exported linear model. It is deterministic, efficient, and easier to interpret than the TFLite path."
    AnomalyEngine.MODE_TFLITE ->
        "Uses the bundled one-class reconstruction TFLite model when present, otherwise falls back to linear/statistical scoring. Best for richer learned behavior when the model is available."
    AnomalyEngine.MODE_REMOTE ->
        "Sends a compact feature window to the backend for server-side inference. Best used when the phone is connected to the backend and you want heavier off-device analysis."
    else -> "No description available for this model."
}

private fun signalDescription(key: String): String = when (key) {
    "signal:beacon" ->
        "Raises the final fused score when traffic looks periodic, callback-like, or beaconing."
    "signal:drift" ->
        "Raises the final fused score when current behavior differs from the app's established baseline over time."
    "signal:reputation" ->
        "Raises the final fused score when destination heuristics suggest phishing, plaintext web, telemetry, or unusual ports."
    "signal:data_quality" ->
        "Subtracts from the final fused score when capture quality is poor, incomplete, or noisy."
    "signal:response_anomaly" ->
        "Controls how much the anomaly channel dominates the final response score after beacon, drift, and data-quality adjustments are applied."
    "signal:response_context" ->
        "Controls how much contextual and reputation evidence influences the final response score after the anomaly channel is computed."
    else -> "No description available."
}

private fun disableGroupDescription(key: String): String = when (key) {
    "disable:volume" ->
        "Disables byte and flow-intensity signals such as total bytes, mean packet size, bytes per flow, and volume-heavy burst scoring."
    "disable:timing" ->
        "Disables timing-heavy signals such as burstiness, connection frequency changes, and periodic beacon timing cues."
    "disable:destination" ->
        "Disables destination-context signals such as destination novelty, diversity, site-risk hints, and reputation-like destination context."
    else -> "No description available."
}

private fun infoDescription(key: String): String = when {
    key.startsWith("feature:") -> featureExplanation(key.removePrefix("feature:"))
    key.startsWith("profile:") -> profileDescription(key.removePrefix("profile:"))
    key.startsWith("signal:") -> signalDescription(key)
    key.startsWith("disable:") -> disableGroupDescription(key)
    key.startsWith("suppression:") -> suppressionDescription(key.removePrefix("suppression:"))
    else -> modelDescription(key)
}

private fun parseSuppressionTokens(raw: String?): List<String> =
    raw.orEmpty().split(',').map { it.trim() }.filter { it.isNotBlank() }

private fun normalizeContributors(contributions: Map<String, Double>, responseScore: Double): List<Pair<String, Double>> {
    val positive = contributions.entries.filter { it.value > 0.0 }
    val total = positive.sumOf { it.value }
    if (total <= 1e-9) {
        return positive.map { it.key to 0.0 }
    }
    return positive
        .sortedByDescending { it.value }
        .map { entry -> entry.key to ((entry.value / total) * responseScore).coerceIn(0.0, 1.0) }
}

private fun suppressionDisplayName(raw: String): String = when {
    raw == "general" -> "Suppression"
    raw == "battery_guardrail" -> "Battery guardrail"
    raw == "queue_backpressure" -> "Queue backpressure"
    raw == "cpu_cost_guardrail" -> "CPU guardrail"
    raw.startsWith("low_confidence") -> "Low confidence"
    raw.startsWith("profile_suppression") -> "Profile suppression"
    else -> raw.replace('_', ' ')
}

private fun suppressionDescription(raw: String): String = when {
    raw == "general" ->
        "One or more guardrails, profiles, or confidence checks changed how this alert was presented before it reached the UI."
    raw == "battery_guardrail" ->
        "Detection was sampled more conservatively because the device battery was low or power saver mode was active."
    raw == "queue_backpressure" ->
        "Detection was sampled more conservatively because the export queue was backing up and the app reduced extra work."
    raw == "cpu_cost_guardrail" ->
        "Detection was sampled more conservatively because recent per-window processing cost was too high for the device budget."
    raw.startsWith("low_confidence") ->
        "The final severity was reduced because the model confidence was weak and the result looked unstable."
    raw.startsWith("profile_suppression") ->
        "The active app profile intentionally softened the alert because this app is configured as trusted, browser-like, high-churn, or system-noisy."
    else -> "This badge marks a suppression or runtime guardrail reason that changed how the alert was presented."
}

private fun profileDisplayName(raw: String): String = when (raw.lowercase()) {
    "default" -> AppProfile.DEFAULT.label()
    "trusted" -> AppProfile.TRUSTED.label()
    "high_churn" -> AppProfile.HIGH_CHURN.label()
    "browser" -> AppProfile.BROWSER.label()
    "system" -> AppProfile.SYSTEM.label()
    else -> raw.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
}

private fun profileDescription(raw: String): String = when (raw.lowercase()) {
    "default" ->
        "Uses the normal thresholds and suppression rules for the app without adding any special bias."
    "trusted" ->
        "Raises thresholds for apps you trust so short-lived spikes are less likely to become user-facing alerts."
    "high_churn" ->
        "Softens alerting for apps that naturally generate noisy or constantly shifting traffic patterns."
    "browser" ->
        "Allows normal browsing bursts while still keeping danger-host and plaintext-web signals more prominent."
    "system" ->
        "Uses the strongest suppression and highest thresholds for OS or background components that are often noisy."
    else -> "No description available."
}

private fun ThemeMode.label(): String = when (this) {
    ThemeMode.SYSTEM -> "System"
    ThemeMode.LIGHT -> "Light"
    ThemeMode.DARK -> "Dark"
}

private fun PrivacyMode.label(): String = when (this) {
    PrivacyMode.OFF -> "Off"
    PrivacyMode.STRICT -> "Strict"
    PrivacyMode.BALANCED -> "Balanced"
    PrivacyMode.RESEARCH -> "Research"
    PrivacyMode.CUSTOM -> "Custom"
}

private fun privacyModeDescription(mode: PrivacyMode): String = when (mode) {
    PrivacyMode.OFF ->
        "Exports normal app identifiers and destination context."
    PrivacyMode.STRICT ->
        "Hashes app and IP identifiers, removes site hints, and minimizes evidence fields."
    PrivacyMode.BALANCED ->
        "Hashes app and IP identifiers while preserving operational metadata such as ports and feature summaries."
    PrivacyMode.RESEARCH ->
        "Keeps app identifiers and selected context for experiments while still hashing raw IP addresses."
    PrivacyMode.CUSTOM ->
        "Lets you choose field-by-field export visibility while keeping the rest of the privacy pipeline intact."
}

@Composable
private fun CustomPrivacyToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label)
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

private fun AppProfile.label(): String = when (this) {
    AppProfile.DEFAULT -> "Default"
    AppProfile.TRUSTED -> "Trusted"
    AppProfile.HIGH_CHURN -> "High churn"
    AppProfile.BROWSER -> "Browser"
    AppProfile.SYSTEM -> "System"
}

private fun formatDecimal(value: Double): String = "%.3f".format(value)

private fun formatDestinationSummary(alert: AnomalyAlert, privacyModeEnabled: Boolean): String? {
    return when {
        privacyModeEnabled -> "Destination hidden by privacy mode"
        !alert.siteHint.isNullOrBlank() && alert.destinationPort != null ->
            "Site ${alert.siteHint} • port ${alert.destinationPort}"
        !alert.siteHint.isNullOrBlank() ->
            "Site ${alert.siteHint}"
        isBrowserPackage(alert.appId) ->
            "Browser destination detected, but site name is unavailable from metadata-only capture"
        alert.destinationIp != null && alert.destinationPort != null ->
            "Network target ${alert.destinationIp}:${alert.destinationPort}"
        else -> null
    }
}

private fun isBrowserPackage(appId: String): Boolean = appId in BROWSER_APP_IDS

private fun buildFlowPreviewText(deviceIdPseudo: String, config: EndpointConfig): String {
    val appId = when (config.privacyMode) {
        PrivacyMode.OFF -> "com.android.chrome"
        PrivacyMode.STRICT, PrivacyMode.BALANCED -> "sha256(app_id)"
        PrivacyMode.RESEARCH -> "com.android.chrome"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeAppId) "com.android.chrome" else "sha256(app_id)"
    }
    val srcIp = when (config.privacyMode) {
        PrivacyMode.OFF, PrivacyMode.RESEARCH -> "10.0.0.2"
        PrivacyMode.STRICT, PrivacyMode.BALANCED -> "sha256(src_ip)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeIpAddresses) "10.0.0.2" else "sha256(src_ip)"
    }
    val dstIp = when (config.privacyMode) {
        PrivacyMode.OFF, PrivacyMode.RESEARCH -> "93.184.216.34"
        PrivacyMode.STRICT, PrivacyMode.BALANCED -> "sha256(dst_ip)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeIpAddresses) "93.184.216.34" else "sha256(dst_ip)"
    }
    val dstPort = when (config.privacyMode) {
        PrivacyMode.STRICT -> "443 (coarse, minimal context)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeExactPorts) "443" else "443 (service bucket)"
        else -> "443"
    }
    val explain = when (config.privacyMode) {
        PrivacyMode.OFF -> "[novelty_score, destination_diversity, periodic_beacon_score]"
        PrivacyMode.STRICT -> "[feature_window only, no site hint, minimal endpoint context]"
        PrivacyMode.BALANCED -> "[feature_window, ports, protocol, hashed identifiers]"
        PrivacyMode.RESEARCH -> "[feature_window, ports, protocol, selected research context]"
        PrivacyMode.CUSTOM ->
            if (config.customPrivacy.includeFeatureWindow) {
                "[custom window export enabled]"
            } else {
                "[custom minimal export, no feature_window]"
            }
    }
    return """
        device_id_pseudo=$deviceIdPseudo
        app_id=$appId
        protocol=TCP
        src_ip=$srcIp
        dst_ip=$dstIp
        dst_port=$dstPort
        dst_host_hash=${CryptoUtils.sha256("93.184.216.34:443").take(16)}...
        explain_top_features=$explain
    """.trimIndent()
}

private fun buildAlertPreviewText(deviceIdPseudo: String, config: EndpointConfig): String {
    val appId = when (config.privacyMode) {
        PrivacyMode.OFF -> "com.android.chrome"
        PrivacyMode.STRICT, PrivacyMode.BALANCED -> "sha256(app_id)"
        PrivacyMode.RESEARCH -> "com.android.chrome"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeAppId) "com.android.chrome" else "sha256(app_id)"
    }
    val siteHint = when (config.privacyMode) {
        PrivacyMode.OFF -> "google.com"
        PrivacyMode.STRICT -> "removed"
        PrivacyMode.BALANCED -> "removed"
        PrivacyMode.RESEARCH -> "google.com"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeSiteHint) "google.com" else "removed"
    }
    val destinationContext = when (config.privacyMode) {
        PrivacyMode.STRICT -> "minimal risk context only"
        PrivacyMode.BALANCED -> "risk summary retained"
        PrivacyMode.OFF, PrivacyMode.RESEARCH -> "site and risk context retained"
        PrivacyMode.CUSTOM ->
            if (config.customPrivacy.includeFeatureWindow) "custom feature window retained" else "feature window removed"
    }
    return """
        device_id_pseudo=$deviceIdPseudo
        app_id=$appId
        source_model=${config.detectionModel}
        severity=MEDIUM
        top_features=[novelty, destination_diversity]
        site_hint=$siteHint
        destination_context=$destinationContext
        confidence=0.68
        uncertainty=0.32
    """.trimIndent()
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
    "bytes_per_flow" -> "Bytes per flow"
    "destination_diversity" -> "Destination diversity"
    "activity_ratio" -> "Activity ratio"
    "periodic_beacon", "periodic_beacon_score" -> "Beacon regularity"
    "byte_rate" -> "Byte rate"
    "packet_rate" -> "Packet rate"
    "mean_duration_ms" -> "Average flow duration"
    "duration_jitter" -> "Duration jitter"
    "port_diversity" -> "Port diversity"
    "protocol_diversity" -> "Protocol diversity"
    "packet_imbalance" -> "Packet imbalance"
    "small_flow_ratio" -> "Small-flow ratio"
    "high_port_ratio" -> "High-port ratio"
    "ttl_gap_norm", "ttl_gap" -> "TTL gap"
    "syn_rate_total" -> "SYN rate"
    "rst_rate_total" -> "RST rate"
    "ack_rate_total" -> "ACK rate"
    "fin_rate_total" -> "FIN rate"
    "psh_rate_total" -> "PSH rate"
    "fragment_rate_total" -> "Fragment rate"
    "tcp_window_mean_log", "tcp_window_mean" -> "TCP window size"
    "ack_delay_mean_log", "ack_delay_mean" -> "ACK delay"
    "inter_packet_gap_mean_log", "inter_packet_gap_mean" -> "Inter-packet gap"
    "payload_mean_log", "payload_mean" -> "Payload size"
    "load_mean_log", "load_mean" -> "Traffic load"
    else -> feature.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
}

private fun featureExplanation(feature: String): String = when (feature) {
    "flow_count" -> "Unusually high/low number of connections in this window"
    "bytes_out", "total_bytes_out" -> "Outgoing transfer volume differs from normal"
    "bytes_in", "total_bytes_in" -> "Incoming transfer volume differs from normal"
    "mean_packet_size" -> "Packet sizes are atypical for this app"
    "outbound_ratio" -> "Direction of traffic changed from normal behavior"
    "burstiness" -> "Traffic burstiness stayed high after normalization against the app's usual traffic volume"
    "novelty", "novelty_score" -> "App contacted new or uncommon destinations"
    "conn_freq_delta", "connection_frequency_delta" -> "Connection rate changed after smoothing out short-lived startup bursts"
    "bytes_per_flow" -> "Average amount of data per flow changed from the app's baseline"
    "destination_diversity" -> "The app spread traffic across a more diverse set of destinations than usual"
    "activity_ratio" -> "The app stayed active for longer portions of the time window than usual"
    "periodic_beacon", "periodic_beacon_score" -> "Traffic timing became more regular, which can look like beaconing or scheduled callbacks"
    "byte_rate" -> "Total bytes per second changed from the app's usual rate"
    "packet_rate" -> "Packets per second changed from the app's usual rate"
    "mean_duration_ms" -> "Connection durations shifted from the app's baseline"
    "duration_jitter" -> "Flow durations became much less or much more consistent than normal"
    "port_diversity" -> "The app started using a wider or narrower set of destination ports"
    "protocol_diversity" -> "The app used an unusual mix of protocols in the same window"
    "packet_imbalance" -> "The balance between outgoing and incoming packet counts shifted"
    "small_flow_ratio" -> "The app produced an unusual number of very small flows"
    "high_port_ratio" -> "The app shifted toward higher-numbered destination ports"
    "ttl_gap_norm", "ttl_gap" -> "Observed TTL patterns differ across flow directions"
    "syn_rate_total" -> "TCP connection setup behavior changed"
    "rst_rate_total" -> "TCP reset behavior changed"
    "ack_rate_total" -> "TCP acknowledgement behavior changed"
    "fin_rate_total" -> "TCP session teardown behavior changed"
    "psh_rate_total" -> "TCP push-flag behavior changed"
    "fragment_rate_total" -> "Fragmentation-related behavior changed"
    "tcp_window_mean_log", "tcp_window_mean" -> "TCP window sizes differ from normal behavior"
    "ack_delay_mean_log", "ack_delay_mean" -> "ACK timing differs from normal behavior"
    "inter_packet_gap_mean_log", "inter_packet_gap_mean" -> "Packet spacing differs from normal behavior"
    "payload_mean_log", "payload_mean" -> "Payload sizing differs from normal behavior"
    "load_mean_log", "load_mean" -> "Traffic load differs from normal behavior"
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

private fun formatOptionalTimestamp(millis: Long): String {
    return if (millis <= 0L) {
        "never"
    } else {
        formatTimestamp(millis)
    }
}
