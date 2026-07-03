package com.manta.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.manta.app.R
import com.manta.app.core.model.AlertSeverity
import com.manta.app.core.model.AnomalyAlert
import com.manta.app.core.model.RuntimeHealth
import com.manta.app.core.model.ThresholdProfile
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private const val ALL_MODELS_KEY = "__all_models__"

private val KNOWN_MODEL_FILTERS = listOf(
    AnomalyEngine.MODE_ENSEMBLE,
    AnomalyEngine.MODE_STATISTICAL,
    AnomalyEngine.MODE_MULTIVARIATE,
    AnomalyEngine.MODE_SEQUENCE,
    AnomalyEngine.MODE_LOCAL,
    AnomalyEngine.MODE_LOCAL_SENSITIVE,
    AnomalyEngine.MODE_LOCAL_QUIET,
    AnomalyEngine.MODE_LOCAL_BALANCED,
    AnomalyEngine.MODE_LOCAL_PRIVACY,
    AnomalyEngine.MODE_TFLITE,
    AnomalyEngine.MODE_REMOTE
)

private val PRIMARY_DETECTION_MODELS = listOf(
    AnomalyEngine.MODE_ENSEMBLE,
    AnomalyEngine.MODE_LOCAL_BALANCED,
    AnomalyEngine.MODE_LOCAL_SENSITIVE,
    AnomalyEngine.MODE_LOCAL_QUIET,
    AnomalyEngine.MODE_LOCAL_PRIVACY,
    AnomalyEngine.MODE_LOCAL
)

private val ADVANCED_DETECTION_MODELS = listOf(
    AnomalyEngine.MODE_STATISTICAL,
    AnomalyEngine.MODE_MULTIVARIATE,
    AnomalyEngine.MODE_SEQUENCE,
    AnomalyEngine.MODE_TFLITE
)

private val SHADOW_MODEL_FILTERS = PRIMARY_DETECTION_MODELS + ADVANCED_DETECTION_MODELS + AnomalyEngine.MODE_REMOTE

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
    APPS("Apps"),
    ALERTS("Alerts"),
    SETTINGS("Settings")
}

private enum class SeverityFilter(val label: String) {
    ALL("All"),
    HIGH("High"),
    MEDIUM("Medium"),
    LOW("Low")
}

private enum class AppTypeFilter(val label: String) {
    USER("User"),
    ALL("All"),
    SYSTEM("System")
}

private enum class AppStatusFilter(val label: String) {
    ALL("All"),
    OPEN_ALERTS("Needs review"),
    HAS_ALERTS("Has alerts"),
    HIGH_RISK("High risk"),
    QUIET("Quiet")
}

private enum class AppSortOption(val label: String) {
    SMART("Smart"),
    RECENT("Recent"),
    ALERTS("Alerts"),
    NAME("Name")
}

private const val ALL_SHADOWS_KEY = "__all_shadows__"
private const val DISABLED_SHADOW_KEY = "__disabled_shadow__"

private data class PendingUndoAction(
    val alertId: String,
    val appLabel: String,
    val action: AlertAction
)

private data class InstalledAppCatalogEntry(
    val appId: String,
    val label: String,
    val isSystem: Boolean
)

private data class AppInventoryEntry(
    val appId: String,
    val label: String,
    val isInstalled: Boolean,
    val isSystem: Boolean,
    val alertCount: Int,
    val openAlertCount: Int,
    val highestSeverity: AlertSeverity?,
    val lastAlertMillis: Long,
    val thresholdLow: Double,
    val thresholdMedium: Double,
    val thresholdHigh: Double,
    val profile: AppProfile
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
    runtimeHealth: RuntimeHealth,
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
    onSetTestModeEnabled: (Boolean) -> Unit,
    onSetPrivacyMode: (PrivacyMode) -> Unit,
    onSetCustomPrivacyOptions: (CustomPrivacyOptions) -> Unit,
    onSaveProtectedBrandsCsv: (String) -> Unit,
    onSyncPolicy: () -> Unit,
    onPingBackend: () -> Unit,
    onAcceptConsent: () -> Unit,
    onExportDataset: () -> Unit,
    onExportAlerts: () -> Unit,
    onExportForensics: () -> Unit,
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
    currentAppThresholdOverrides: (ThresholdProfile) -> Map<String, ThresholdProfile>,
    currentAppProfiles: () -> Map<String, AppProfile>,
    onSetAppThresholdOverride: (String, Double, Double, Double) -> Unit,
    onSetAppProfile: (String, AppProfile) -> Unit
) {
    var backendUrl by rememberSaveable { mutableStateOf(config.backendUrl) }
    var apiToken by rememberSaveable { mutableStateOf(config.apiToken) }
    var backendUrlDirty by rememberSaveable { mutableStateOf(false) }
    var apiTokenDirty by rememberSaveable { mutableStateOf(false) }
    var lowThreshold by rememberSaveable(config.lowThreshold) { mutableStateOf(formatDecimal(config.lowThreshold)) }
    var mediumThreshold by rememberSaveable(config.mediumThreshold) { mutableStateOf(formatDecimal(config.mediumThreshold)) }
    var highThreshold by rememberSaveable(config.highThreshold) { mutableStateOf(formatDecimal(config.highThreshold)) }
    var fusionStatisticalWeight by rememberSaveable(config.fusionWeights.statistical) { mutableStateOf(formatDecimal(config.fusionWeights.statistical)) }
    var fusionMultivariateWeight by rememberSaveable(config.fusionWeights.multivariate) { mutableStateOf(formatDecimal(config.fusionWeights.multivariate)) }
    var fusionSequenceWeight by rememberSaveable(config.fusionWeights.sequence) { mutableStateOf(formatDecimal(config.fusionWeights.sequence)) }
    var fusionLocalWeight by rememberSaveable(config.fusionWeights.local) { mutableStateOf(formatDecimal(config.fusionWeights.local)) }
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
    var protectedBrandsCsv by rememberSaveable(config.protectedBrandsCsv) { mutableStateOf(config.protectedBrandsCsv) }
    var selectedTab by rememberSaveable { mutableStateOf(MainTab.HOME) }
    var severityFilter by rememberSaveable { mutableStateOf(SeverityFilter.ALL) }
    var selectedModelFilter by rememberSaveable { mutableStateOf(ALL_MODELS_KEY) }
    var selectedShadowFilter by rememberSaveable { mutableStateOf(ALL_SHADOWS_KEY) }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var modelInfoDialog by rememberSaveable { mutableStateOf<String?>(null) }
    var alertsPage by rememberSaveable { mutableStateOf(1) }
    var pendingUndo by rememberSaveable { mutableStateOf<PendingUndoAction?>(null) }
    var appsSearchQuery by rememberSaveable { mutableStateOf("") }
    var appTypeFilter by rememberSaveable { mutableStateOf(AppTypeFilter.USER) }
    var appStatusFilter by rememberSaveable { mutableStateOf(AppStatusFilter.ALL) }
    var appSortOption by rememberSaveable { mutableStateOf(AppSortOption.SMART) }
    var appScanNonce by rememberSaveable { mutableStateOf(0) }
    var scannedInstalledApps by remember { mutableStateOf<List<InstalledAppCatalogEntry>?>(null) }
    var appsScanInProgress by remember { mutableStateOf(false) }
    var selectedAppId by rememberSaveable { mutableStateOf<String?>(null) }
    var appAlertsSearchQuery by rememberSaveable { mutableStateOf("") }
    var appAlertsSeverityFilter by rememberSaveable { mutableStateOf(SeverityFilter.ALL) }
    var appAlertsSelectedModelFilter by rememberSaveable { mutableStateOf(ALL_MODELS_KEY) }
    var appAlertsSelectedShadowFilter by rememberSaveable { mutableStateOf(ALL_SHADOWS_KEY) }
    var appAlertsPage by rememberSaveable { mutableStateOf(1) }

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
        config.fusionWeights.local,
        config.fusionWeights.tflite,
        config.fusionWeights.remote,
        config.fusionWeights.beacon,
        config.fusionWeights.drift,
        config.fusionWeights.reputation,
        config.fusionWeights.dataQualityPenalty,
        config.fusionWeights.responseAnomalyBlend,
        config.fusionWeights.responseContextBlend
    ) {
        val backendUrlMatchesConfig = backendUrl == config.backendUrl
        if (backendUrlMatchesConfig) {
            backendUrlDirty = false
        }
        if (!backendUrlDirty || backendUrlMatchesConfig) {
            backendUrl = config.backendUrl
        }

        val apiTokenMatchesConfig = apiToken == config.apiToken
        if (apiTokenMatchesConfig) {
            apiTokenDirty = false
        }
        if (!apiTokenDirty || apiTokenMatchesConfig) {
            apiToken = config.apiToken
        }

        lowThreshold = formatDecimal(config.lowThreshold)
        mediumThreshold = formatDecimal(config.mediumThreshold)
        highThreshold = formatDecimal(config.highThreshold)
        falsePositiveBudget = config.falsePositiveBudgetPerAppDay.toString()
        driftHighThreshold = formatDecimal(config.driftHighThreshold)
        protectedBrandsCsv = config.protectedBrandsCsv
        fusionStatisticalWeight = formatDecimal(config.fusionWeights.statistical)
        fusionMultivariateWeight = formatDecimal(config.fusionWeights.multivariate)
        fusionSequenceWeight = formatDecimal(config.fusionWeights.sequence)
        fusionLocalWeight = formatDecimal(config.fusionWeights.local)
        fusionTfliteWeight = formatDecimal(config.fusionWeights.tflite)
        fusionRemoteWeight = formatDecimal(config.fusionWeights.remote)
        fusionBeaconWeight = formatDecimal(config.fusionWeights.beacon)
        fusionDriftWeight = formatDecimal(config.fusionWeights.drift)
        fusionReputationWeight = formatDecimal(config.fusionWeights.reputation)
        fusionDataQualityPenaltyWeight = formatDecimal(config.fusionWeights.dataQualityPenalty)
        responseAnomalyBlendWeight = formatDecimal(config.fusionWeights.responseAnomalyBlend)
        responseContextBlendWeight = formatDecimal(config.fusionWeights.responseContextBlend)
    }

    val modelFilters = remember(alerts, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            listOf(ALL_MODELS_KEY) + KNOWN_MODEL_FILTERS
        } else {
            buildList {
                add(ALL_MODELS_KEY)
                addAll(KNOWN_MODEL_FILTERS)
                addAll(alerts.map { it.sourceModel }.distinct().sorted())
            }.distinct()
        }
    }

    val shadowFilters = remember(alerts, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            listOf(ALL_SHADOWS_KEY, DISABLED_SHADOW_KEY) + KNOWN_MODEL_FILTERS
        } else {
            buildList {
                add(ALL_SHADOWS_KEY)
                add(DISABLED_SHADOW_KEY)
                addAll(KNOWN_MODEL_FILTERS)
                addAll(alerts.mapNotNull { it.shadowModel }.distinct().sorted())
            }.distinct()
        }
    }

    val severityScopedAlerts = remember(alerts, selectedModelFilter, selectedShadowFilter, searchQuery, selectedTab) {
        if (selectedTab != MainTab.ALERTS) {
            emptyList()
        } else {
            alerts.filter { alert ->
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

    val packageManager = LocalContext.current.packageManager
    val baseThresholdProfile = remember(config.lowThreshold, config.mediumThreshold, config.highThreshold) {
        ThresholdProfile(config.lowThreshold, config.mediumThreshold, config.highThreshold).normalize()
    }
    val appThresholdOverrides = if (selectedTab == MainTab.APPS) {
        currentAppThresholdOverrides(baseThresholdProfile)
    } else {
        emptyMap()
    }
    val appProfileOverrides = if (selectedTab == MainTab.APPS) {
        currentAppProfiles()
    } else {
        emptyMap()
    }
    LaunchedEffect(appScanNonce, packageManager) {
        if (appScanNonce <= 0) {
            return@LaunchedEffect
        }
        appsScanInProgress = true
        scannedInstalledApps = withContext(Dispatchers.IO) {
            loadInstalledApps(packageManager)
        }
        appsScanInProgress = false
    }
    val installedApps = if (selectedTab == MainTab.APPS) {
        scannedInstalledApps.orEmpty()
    } else {
        emptyList()
    }
    val appInventory = remember(
        selectedTab,
        installedApps,
        alerts,
        appsSearchQuery,
        appTypeFilter,
        appStatusFilter,
        appSortOption,
        baseThresholdProfile,
        appThresholdOverrides,
        appProfileOverrides
    ) {
        if (selectedTab == MainTab.APPS) {
            buildAppInventory(
                installedApps = installedApps,
                alerts = alerts,
                searchQuery = appsSearchQuery,
                typeFilter = appTypeFilter,
                statusFilter = appStatusFilter,
                sortOption = appSortOption,
                baseThresholdProfile = baseThresholdProfile,
                thresholdOverrides = appThresholdOverrides,
                appProfileOverrides = appProfileOverrides
            )
        } else {
            emptyList()
        }
    }
    val selectedAppEntry = remember(appInventory, selectedAppId) {
        appInventory.firstOrNull { it.appId == selectedAppId }
    }
    val selectedAppAlertsSource = remember(alerts, selectedAppId) {
        alerts.filter { it.appId == selectedAppId }
    }
    val selectedAppModelFilters = remember(selectedAppAlertsSource) {
        buildList {
            add(ALL_MODELS_KEY)
            addAll(KNOWN_MODEL_FILTERS)
            addAll(selectedAppAlertsSource.map { it.sourceModel }.distinct().sorted())
        }.distinct()
    }
    val selectedAppShadowFilters = remember(selectedAppAlertsSource) {
        buildList {
            add(ALL_SHADOWS_KEY)
            add(DISABLED_SHADOW_KEY)
            addAll(KNOWN_MODEL_FILTERS)
            addAll(selectedAppAlertsSource.mapNotNull { it.shadowModel }.distinct().sorted())
        }.distinct()
    }
    val selectedAppScopedAlerts = remember(
        selectedAppAlertsSource,
        appAlertsSelectedModelFilter,
        appAlertsSelectedShadowFilter,
        appAlertsSearchQuery
    ) {
        selectedAppAlertsSource.filter { alert ->
            val modelMatches = appAlertsSelectedModelFilter == ALL_MODELS_KEY || alert.sourceModel == appAlertsSelectedModelFilter
            val shadowMatches = when (appAlertsSelectedShadowFilter) {
                ALL_SHADOWS_KEY -> true
                DISABLED_SHADOW_KEY -> alert.shadowModel.isNullOrBlank()
                else -> alert.shadowModel == appAlertsSelectedShadowFilter
            }
            val query = appAlertsSearchQuery.trim().lowercase()
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
    val selectedAppSeverityCounts = remember(selectedAppScopedAlerts) {
        mapOf(
            SeverityFilter.ALL to selectedAppScopedAlerts.size,
            SeverityFilter.HIGH to selectedAppScopedAlerts.count { it.severity == AlertSeverity.HIGH },
            SeverityFilter.MEDIUM to selectedAppScopedAlerts.count { it.severity == AlertSeverity.MEDIUM },
            SeverityFilter.LOW to selectedAppScopedAlerts.count { it.severity == AlertSeverity.LOW }
        )
    }
    val selectedAppFilteredAlerts = remember(selectedAppScopedAlerts, appAlertsSeverityFilter) {
        selectedAppScopedAlerts.filter { alert ->
            when (appAlertsSeverityFilter) {
                SeverityFilter.ALL -> true
                SeverityFilter.HIGH -> alert.severity == AlertSeverity.HIGH
                SeverityFilter.MEDIUM -> alert.severity == AlertSeverity.MEDIUM
                SeverityFilter.LOW -> alert.severity == AlertSeverity.LOW
            }
        }
    }
    val selectedAppTotalPages = remember(selectedAppFilteredAlerts) {
        maxOf(1, (selectedAppFilteredAlerts.size + 19) / 20)
    }
    val currentAppAlertsPage = appAlertsPage.coerceIn(1, selectedAppTotalPages)
    val selectedAppPagedAlerts = remember(selectedAppFilteredAlerts, currentAppAlertsPage) {
        selectedAppFilteredAlerts.drop((currentAppAlertsPage - 1) * 20).take(20)
    }
    LaunchedEffect(severityFilter, selectedModelFilter, selectedShadowFilter, searchQuery, alerts.size) {
        alertsPage = 1
    }

    LaunchedEffect(
        selectedAppId,
        appAlertsSeverityFilter,
        appAlertsSelectedModelFilter,
        appAlertsSelectedShadowFilter,
        appAlertsSearchQuery,
        selectedAppFilteredAlerts.size
    ) {
        appAlertsPage = 1
    }

    LaunchedEffect(selectedAppId) {
        appAlertsSearchQuery = ""
        appAlertsSeverityFilter = SeverityFilter.ALL
        appAlertsSelectedModelFilter = ALL_MODELS_KEY
        appAlertsSelectedShadowFilter = ALL_SHADOWS_KEY
    }

    LaunchedEffect(appInventory, selectedAppId) {
        if (selectedAppId != null && appInventory.none { it.appId == selectedAppId }) {
            selectedAppId = null
        }
    }

    BackHandler(enabled = selectedTab != MainTab.HOME || selectedAppId != null) {
        if (selectedAppId != null) {
            selectedAppId = null
        } else {
            selectedTab = MainTab.HOME
        }
    }

    LaunchedEffect(alerts) {
        val currentIds = alerts.map { it.id }.toSet()
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
        pendingUndo = PendingUndoAction(
            alertId = alert.id,
            appLabel = displayAppName(alert.appId),
            action = action
        )
    }

    fun undoPendingAction() {
        pendingUndo ?: return
        pendingUndo = null
    }

    Scaffold(
        topBar = {
            val screenTitle = if (selectedTab == MainTab.HOME) "Resistine" else selectedTab.label
            val screenSubtitle = when (selectedTab) {
                MainTab.HOME -> if (config.captureEnabled) "Protection active" else "Protection paused"
                MainTab.APPS -> if (scannedInstalledApps == null) "Scan when you need the installed app list" else "${appInventory.size} apps in view"
                MainTab.ALERTS -> "${filteredAlerts.size} matching alerts"
                MainTab.SETTINGS -> modelDisplayName(config.detectionModel)
            }
            TopAppBar(
                navigationIcon = {
                    if (selectedTab != MainTab.HOME) {
                        IconButton(
                            onClick = {
                                if (selectedAppId != null) selectedAppId = null else selectedTab = MainTab.HOME
                            }
                        ) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                title = {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Image(
                            painter = painterResource(id = R.drawable.logo),
                            contentDescription = null,
                            modifier = Modifier.size(36.dp)
                        )
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(screenTitle, style = MaterialTheme.typography.titleLarge)
                            Text(
                                screenSubtitle,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
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
                    runtimeHealth = runtimeHealth,
                    onAcceptConsent = onAcceptConsent,
                    onStartCapture = onStartCapture,
                    onStopCapture = onStopCapture,
                    onNavigate = { selectedTab = it }
                )

                MainTab.APPS -> AppsView(
                    entries = appInventory,
                    selectedApp = selectedAppEntry,
                    selectedAppAlerts = selectedAppPagedAlerts,
                    selectedAppAllFilteredAlerts = selectedAppFilteredAlerts,
                    statusMessage = statusMessage,
                    hasScannedApps = scannedInstalledApps != null,
                    isScanningApps = appsScanInProgress,
                    appTypeFilter = appTypeFilter,
                    onAppTypeFilterChange = { appTypeFilter = it },
                    appStatusFilter = appStatusFilter,
                    onAppStatusFilterChange = { appStatusFilter = it },
                    appSortOption = appSortOption,
                    onAppSortOptionChange = { appSortOption = it },
                    searchQuery = appsSearchQuery,
                    onSearchQueryChange = { appsSearchQuery = it },
                    onScanApps = { appScanNonce++ },
                    onOpenApp = { selectedAppId = it },
                    onBackToApps = { selectedAppId = null },
                    appAlertsSearchQuery = appAlertsSearchQuery,
                    onAppAlertsSearchQueryChange = { appAlertsSearchQuery = it },
                    appAlertsSeverityFilter = appAlertsSeverityFilter,
                    onAppAlertsSeverityFilterChange = { appAlertsSeverityFilter = it },
                    appAlertsSeverityCounts = selectedAppSeverityCounts,
                    appAlertModelFilters = selectedAppModelFilters,
                    selectedAppModelFilter = appAlertsSelectedModelFilter,
                    onSelectedAppModelFilterChange = { appAlertsSelectedModelFilter = it },
                    appAlertShadowFilters = selectedAppShadowFilters,
                    selectedAppShadowFilter = appAlertsSelectedShadowFilter,
                    onSelectedAppShadowFilterChange = { appAlertsSelectedShadowFilter = it },
                    onShowModelInfo = { modelInfoDialog = it },
                    currentPage = currentAppAlertsPage,
                    totalPages = selectedAppTotalPages,
                    onPreviousPage = { appAlertsPage = (currentAppAlertsPage - 1).coerceAtLeast(1) },
                    onNextPage = { appAlertsPage = (currentAppAlertsPage + 1).coerceAtMost(selectedAppTotalPages) },
                    onMarkDangerous = { alertId ->
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.DANGEROUS) }
                    },
                    onMarkFalsePositive = { alertId ->
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.FALSE_POSITIVE) }
                    },
                    onDismissNeutral = { alertId ->
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.NEUTRAL) }
                    },
                    currentAppProfile = currentAppProfile,
                    onSetAppProfile = onSetAppProfile,
                    onSetAppThresholdOverride = onSetAppThresholdOverride,
                    debugModeEnabled = config.debugModeEnabled,
                    privacyModeEnabled = config.privacyModeEnabled,
                    pendingUndo = pendingUndo,
                    onUndoPendingAction = ::undoPendingAction
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
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.DANGEROUS) }
                    },
                    onMarkFalsePositive = { alertId ->
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.FALSE_POSITIVE) }
                    },
                    onDismissNeutral = { alertId ->
                        alerts.find { it.id == alertId }?.let { queueUndoAction(it, AlertAction.NEUTRAL) }
                    },
                    onClearAlerts = onClearAlerts,
                    debugModeEnabled = config.debugModeEnabled,
                    testModeEnabled = config.testModeEnabled,
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
                    runtimeHealth = runtimeHealth,
                    backendUrl = backendUrl,
                    onBackendUrlChange = {
                        backendUrl = it
                        backendUrlDirty = it != config.backendUrl
                    },
                    onSaveBackendUrl = {
                        backendUrlDirty = false
                        onSaveBackendUrl(backendUrl)
                    },
                    apiToken = apiToken,
                    onApiTokenChange = {
                        apiToken = it
                        apiTokenDirty = it != config.apiToken
                    },
                    onSaveApiToken = {
                        apiTokenDirty = false
                        onSaveApiToken(apiToken)
                    },
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
                    fusionLocalWeight = fusionLocalWeight,
                    onFusionLocalWeightChange = { fusionLocalWeight = it },
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
                    protectedBrandsCsv = protectedBrandsCsv,
                    onProtectedBrandsCsvChange = { protectedBrandsCsv = it },
                    onSaveFusionWeights = {
                        onSaveFusionWeights(
                            FusionWeights(
                                statistical = fusionStatisticalWeight.toDoubleOrNull() ?: config.fusionWeights.statistical,
                                multivariate = fusionMultivariateWeight.toDoubleOrNull() ?: config.fusionWeights.multivariate,
                                sequence = fusionSequenceWeight.toDoubleOrNull() ?: config.fusionWeights.sequence,
                                local = fusionLocalWeight.toDoubleOrNull() ?: config.fusionWeights.local,
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
                    onSetTestModeEnabled = onSetTestModeEnabled,
                    onSetPrivacyMode = onSetPrivacyMode,
                    onSetCustomPrivacyOptions = onSetCustomPrivacyOptions,
                    onSaveProtectedBrandsCsv = { onSaveProtectedBrandsCsv(protectedBrandsCsv) },
                    onToggleExport = onToggleExport,
                    onSyncPolicy = onSyncPolicy,
                    onPingBackend = onPingBackend,
                    onExportDataset = onExportDataset,
                    onExportAlerts = onExportAlerts,
                    onExportForensics = onExportForensics,
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun HomeView(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    statusMessage: String?,
    runtimeHealth: RuntimeHealth,
    onAcceptConsent: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onNavigate: (MainTab) -> Unit
) {
    val highCount = remember(alerts) { alerts.count { it.severity == AlertSeverity.HIGH } }
    val mediumCount = remember(alerts) { alerts.count { it.severity == AlertSeverity.MEDIUM } }
    val openCount = remember(alerts) { alerts.count { it.triageStatus == TriageStatus.OPEN } }

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
                Text("Protection", style = MaterialTheme.typography.titleMedium)
                Text(
                    if (config.captureEnabled) "Network protection is active."
                    else "Network protection is paused.",
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
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text("Today", style = MaterialTheme.typography.titleMedium)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    InventoryChip("${alerts.size} alerts")
                    InventoryChip("$openCount open")
                    InventoryChip("$highCount high")
                    InventoryChip("$mediumCount medium")
                    InventoryChip(if (config.isEffectiveExportEnabled()) "Cloud sync on" else "Cloud sync off")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Open", style = MaterialTheme.typography.titleMedium)
                HomeDestinationRow(
                    title = "Apps",
                    subtitle = "Review app activity, alerts, and per-app tuning.",
                    icon = Icons.Filled.Palette,
                    onClick = { onNavigate(MainTab.APPS) }
                )
                HomeDestinationRow(
                    title = "Alerts",
                    subtitle = "Triage detections and inspect evidence.",
                    icon = Icons.Filled.Notifications,
                    onClick = { onNavigate(MainTab.ALERTS) }
                )
                HomeDestinationRow(
                    title = "Settings",
                    subtitle = "Detection, privacy, cloud, and appearance.",
                    icon = Icons.Filled.Settings,
                    onClick = { onNavigate(MainTab.SETTINGS) }
                )
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text("Health", style = MaterialTheme.typography.titleMedium)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    RuntimeHealthChip("On-device", runtimeHealth.localModelAvailable)
                    RuntimeHealthChip("Cloud", runtimeHealth.remoteConfigured)
                }
                Text(
                    "Active ${modelDisplayName(runtimeHealth.activeDetectionModel)}" +
                        (runtimeHealth.shadowModel?.let { " • Shadow ${modelDisplayName(it)}" } ?: ""),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (config.debugModeEnabled) {
                    Text(
                        "Packets ${runtimeHealth.packetPipeline.packetsRead} • Active flows ${runtimeHealth.packetPipeline.activeFlows} • Parser failures ${runtimeHealth.packetPipeline.parserFailure}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Drops: forward ${runtimeHealth.packetPipeline.forwardQueueDropped} • ingress ${runtimeHealth.packetPipeline.analysisIngressDropped} • shard ${runtimeHealth.packetPipeline.analysisShardDropped}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
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
@OptIn(ExperimentalFoundationApi::class)
private fun HomeDestinationRow(
    title: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .combinedClickable(onClick = onClick),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
        shape = RoundedCornerShape(18.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text("Open", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
private fun AppsView(
    entries: List<AppInventoryEntry>,
    selectedApp: AppInventoryEntry?,
    selectedAppAlerts: List<AnomalyAlert>,
    selectedAppAllFilteredAlerts: List<AnomalyAlert>,
    statusMessage: String?,
    hasScannedApps: Boolean,
    isScanningApps: Boolean,
    appTypeFilter: AppTypeFilter,
    onAppTypeFilterChange: (AppTypeFilter) -> Unit,
    appStatusFilter: AppStatusFilter,
    onAppStatusFilterChange: (AppStatusFilter) -> Unit,
    appSortOption: AppSortOption,
    onAppSortOptionChange: (AppSortOption) -> Unit,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onScanApps: () -> Unit,
    onOpenApp: (String) -> Unit,
    onBackToApps: () -> Unit,
    appAlertsSearchQuery: String,
    onAppAlertsSearchQueryChange: (String) -> Unit,
    appAlertsSeverityFilter: SeverityFilter,
    onAppAlertsSeverityFilterChange: (SeverityFilter) -> Unit,
    appAlertsSeverityCounts: Map<SeverityFilter, Int>,
    appAlertModelFilters: List<String>,
    selectedAppModelFilter: String,
    onSelectedAppModelFilterChange: (String) -> Unit,
    appAlertShadowFilters: List<String>,
    selectedAppShadowFilter: String,
    onSelectedAppShadowFilterChange: (String) -> Unit,
    onShowModelInfo: (String) -> Unit,
    currentPage: Int,
    totalPages: Int,
    onPreviousPage: () -> Unit,
    onNextPage: () -> Unit,
    onMarkDangerous: (String) -> Unit,
    onMarkFalsePositive: (String) -> Unit,
    onDismissNeutral: (String) -> Unit,
    currentAppProfile: (String) -> AppProfile,
    onSetAppProfile: (String, AppProfile) -> Unit,
    onSetAppThresholdOverride: (String, Double, Double, Double) -> Unit,
    debugModeEnabled: Boolean,
    privacyModeEnabled: Boolean,
    pendingUndo: PendingUndoAction?,
    onUndoPendingAction: () -> Unit
) {
    if (selectedApp == null) {
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
                        Text("Apps", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Known alert history loads instantly. Scan only when you want to merge in the installed app list.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = onSearchQueryChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Search app name or package") }
                        )
                        Text("Type", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(AppTypeFilter.values().toList()) { filter ->
                                FilterChip(
                                    selected = filter == appTypeFilter,
                                    onClick = { onAppTypeFilterChange(filter) },
                                    label = { Text(filter.label) }
                                )
                            }
                        }
                        Text("Status", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(AppStatusFilter.values().toList()) { filter ->
                                FilterChip(
                                    selected = filter == appStatusFilter,
                                    onClick = { onAppStatusFilterChange(filter) },
                                    label = { Text(filter.label) }
                                )
                            }
                        }
                        Text("Sort", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(AppSortOption.values().toList()) { option ->
                                FilterChip(
                                    selected = option == appSortOption,
                                    onClick = { onAppSortOptionChange(option) },
                                    label = { Text(option.label) }
                                )
                            }
                        }
                        Button(
                            onClick = onScanApps,
                            enabled = !isScanningApps,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(if (isScanningApps) "Scanning..." else if (hasScannedApps) "Scan again" else "Scan installed apps")
                        }
                        Text(
                            if (hasScannedApps) "${entries.size} apps match your filters" else "${entries.size} known apps from alerts",
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

            if (entries.isEmpty()) {
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(if (hasScannedApps) "No apps match the current filters." else "No app scan yet.")
                            Text(
                                if (hasScannedApps) "Try clearing search or broadening the type/status filters."
                                else "Tap Scan installed apps when you want the full device app list.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            } else {
                items(entries, key = { it.appId }) { entry ->
                    AppInventoryCard(
                        entry = entry,
                        onOpenApp = { onOpenApp(entry.appId) }
                    )
                }
            }
        }
        return
    }

    var lowThreshold by rememberSaveable(selectedApp.appId) { mutableStateOf(formatDecimal(selectedApp.thresholdLow)) }
    var mediumThreshold by rememberSaveable(selectedApp.appId) { mutableStateOf(formatDecimal(selectedApp.thresholdMedium)) }
    var highThreshold by rememberSaveable(selectedApp.appId) { mutableStateOf(formatDecimal(selectedApp.thresholdHigh)) }

    LaunchedEffect(selectedApp.appId, selectedApp.thresholdLow, selectedApp.thresholdMedium, selectedApp.thresholdHigh) {
        lowThreshold = formatDecimal(selectedApp.thresholdLow)
        mediumThreshold = formatDecimal(selectedApp.thresholdMedium)
        highThreshold = formatDecimal(selectedApp.thresholdHigh)
    }

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
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(onClick = onBackToApps, modifier = Modifier.fillMaxWidth()) {
                        Text("Back to app list")
                    }
                    Text(selectedApp.label, style = MaterialTheme.typography.titleLarge)
                    Text(
                        selectedApp.appId,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        InventoryChip(if (selectedApp.isInstalled) "Installed" else "Historical")
                        InventoryChip(if (selectedApp.isSystem) "System" else "User")
                        InventoryChip("Alerts ${selectedApp.alertCount}")
                        InventoryChip("Open ${selectedApp.openAlertCount}")
                        InventoryChip(selectedApp.profile.label())
                        selectedApp.highestSeverity?.let { InventoryChip("${it.name.lowercase().replaceFirstChar { ch -> ch.uppercaseChar() }} max") }
                    }
                    Text(
                        "Last alert ${formatOptionalTimestamp(selectedApp.lastAlertMillis)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("App thresholds and profile", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Low controls whether alerts for this app are kept at all. Medium and High control the severity bands after the score passes the low floor.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = lowThreshold,
                            onValueChange = { lowThreshold = it },
                            modifier = Modifier.weight(1f),
                            label = { Text("Low") }
                        )
                        OutlinedTextField(
                            value = mediumThreshold,
                            onValueChange = { mediumThreshold = it },
                            modifier = Modifier.weight(1f),
                            label = { Text("Medium") }
                        )
                        OutlinedTextField(
                            value = highThreshold,
                            onValueChange = { highThreshold = it },
                            modifier = Modifier.weight(1f),
                            label = { Text("High") }
                        )
                    }
                    OutlinedButton(
                        onClick = {
                            onSetAppThresholdOverride(
                                selectedApp.appId,
                                lowThreshold.toDoubleOrNull() ?: selectedApp.thresholdLow,
                                mediumThreshold.toDoubleOrNull() ?: selectedApp.thresholdMedium,
                                highThreshold.toDoubleOrNull() ?: selectedApp.thresholdHigh
                            )
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Save app thresholds")
                    }
                    Text("App profile", style = MaterialTheme.typography.labelLarge)
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        AppProfile.values().forEach { profile ->
                            FilterChip(
                                selected = profile == currentAppProfile(selectedApp.appId),
                                onClick = { onSetAppProfile(selectedApp.appId, profile) },
                                label = { Text(profile.label()) }
                            )
                        }
                    }
                }
            }
        }

        item {
            AppAlertsView(
                alerts = selectedAppAlerts,
                allFilteredAlerts = selectedAppAllFilteredAlerts,
                statusMessage = statusMessage,
                searchQuery = appAlertsSearchQuery,
                onSearchQueryChange = onAppAlertsSearchQueryChange,
                severityFilter = appAlertsSeverityFilter,
                onSeverityFilterChange = onAppAlertsSeverityFilterChange,
                severityCounts = appAlertsSeverityCounts,
                modelFilters = appAlertModelFilters,
                selectedModelFilter = selectedAppModelFilter,
                onModelFilterChange = onSelectedAppModelFilterChange,
                shadowFilters = appAlertShadowFilters,
                selectedShadowFilter = selectedAppShadowFilter,
                onShadowFilterChange = onSelectedAppShadowFilterChange,
                onShowModelInfo = onShowModelInfo,
                currentPage = currentPage,
                totalPages = totalPages,
                onPreviousPage = onPreviousPage,
                onNextPage = onNextPage,
                onMarkDangerous = onMarkDangerous,
                onMarkFalsePositive = onMarkFalsePositive,
                onDismissNeutral = onDismissNeutral,
                debugModeEnabled = debugModeEnabled,
                privacyModeEnabled = privacyModeEnabled,
                currentAppProfile = currentAppProfile,
                onSetAppProfile = onSetAppProfile,
                pendingUndo = pendingUndo,
                onUndoPendingAction = onUndoPendingAction
            )
        }
    }
}

@Composable
@OptIn(ExperimentalFoundationApi::class, ExperimentalLayoutApi::class)
private fun AppInventoryCard(
    entry: AppInventoryEntry,
    onOpenApp: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(onClick = onOpenApp),
        colors = CardDefaults.cardColors(
            containerColor = when (entry.highestSeverity) {
                AlertSeverity.HIGH -> MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.45f)
                AlertSeverity.MEDIUM -> MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.40f)
                else -> MaterialTheme.colorScheme.surface
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(entry.label, style = MaterialTheme.typography.titleMedium)
            Text(
                entry.appId,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                InventoryChip(if (entry.isInstalled) "Installed" else "Historical")
                InventoryChip(if (entry.isSystem) "System" else "User")
                InventoryChip("Alerts ${entry.alertCount}")
                InventoryChip("Open ${entry.openAlertCount}")
                InventoryChip(entry.profile.label())
                entry.highestSeverity?.let { InventoryChip("${it.name.lowercase().replaceFirstChar { ch -> ch.uppercaseChar() }} max") }
            }
            Text(
                "Thresholds L ${formatDecimal(entry.thresholdLow)} • M ${formatDecimal(entry.thresholdMedium)} • H ${formatDecimal(entry.thresholdHigh)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                "Last alert ${formatOptionalTimestamp(entry.lastAlertMillis)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun InventoryChip(label: String) {
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.55f)
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            style = MaterialTheme.typography.labelSmall
        )
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
    testModeEnabled: Boolean,
    privacyModeEnabled: Boolean,
    currentAppProfile: (String) -> AppProfile,
    onSetAppProfile: (String, AppProfile) -> Unit,
    pendingUndo: PendingUndoAction?,
    onUndoPendingAction: () -> Unit
) {
    var filtersExpanded by rememberSaveable { mutableStateOf(false) }
    var compactRepeatedAlerts by rememberSaveable { mutableStateOf(true) }
    val activeFilterCount = (
        (if (severityFilter != SeverityFilter.ALL) 1 else 0) +
            (if (selectedModelFilter != ALL_MODELS_KEY) 1 else 0) +
            (if (selectedShadowFilter != ALL_SHADOWS_KEY) 1 else 0) +
            (if (searchQuery.isNotBlank()) 1 else 0)
        )

    val displayedAlerts = remember(alerts, compactRepeatedAlerts) {
        if (!compactRepeatedAlerts) {
            alerts
        } else {
            alerts
                .groupBy { alert ->
                    alert.correlationKey.takeIf { it.isNotBlank() }
                        ?: "${alert.appId}|${alert.sourceModel}|${alert.siteHint ?: alert.destinationHash ?: "unknown"}"
                }
                .map { (_, grouped) -> grouped.maxByOrNull { it.lastSeenMillis } ?: grouped.first() }
                .sortedByDescending { it.createdAtMillis }
        }
    }

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
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Reset filters")
                            }
                            if (allAlertsCount > 0) {
                                OutlinedButton(onClick = onClearAlerts, modifier = Modifier.weight(1f)) {
                                    Text("Clear all alerts")
                                }
                            }
                        }
                    } else if (allAlertsCount > 0) {
                        OutlinedButton(onClick = onClearAlerts, modifier = Modifier.fillMaxWidth()) {
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
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Compact repeated alerts", style = MaterialTheme.typography.bodyMedium)
                                    Text(
                                        "Show only the latest card for repeated incidents from the same app/correlation group.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Switch(
                                    checked = compactRepeatedAlerts,
                                    onCheckedChange = { compactRepeatedAlerts = it }
                                )
                            }

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
                        "Showing ${displayedAlerts.size} alerts on this page • ${allFilteredAlerts.size} match the filters • $allAlertsCount total stored",
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
                        if (debugModeEnabled) {
                            Text(
                                if (testModeEnabled) {
                                    "Debug hint: test mode is enabled, so low-severity browser-risk alerts should surface more easily."
                                } else {
                                    "Debug hint: enable test mode in Settings to lower browser-risk validation thresholds while testing."
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        } else {
            items(items = displayedAlerts, key = { it.id }) { alert ->
                if (pendingUndo?.alertId == alert.id) {
                    PendingUndoCard(
                        pendingUndo = pendingUndo,
                        onUndoPendingAction = onUndoPendingAction
                    )
                } else {
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
                            OutlinedButton(onClick = onPreviousPage, enabled = currentPage > 1, modifier = Modifier.weight(1f)) {
                                Text("Previous")
                            }
                            Button(onClick = onNextPage, enabled = currentPage < totalPages, modifier = Modifier.weight(1f)) {
                                Text("Next")
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SettingsView(
    config: EndpointConfig,
    deviceIdPseudo: String,
    statusMessage: String?,
    runtimeHealth: RuntimeHealth,
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
    fusionLocalWeight: String,
    onFusionLocalWeightChange: (String) -> Unit,
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
    protectedBrandsCsv: String,
    onProtectedBrandsCsvChange: (String) -> Unit,
    onSaveFusionWeights: () -> Unit,
    onSaveGuardrails: () -> Unit,
    onSetAblationFlags: (Boolean, Boolean, Boolean) -> Unit,
    onSetDetectionModel: (String) -> Unit,
    onSetShadowModel: (String?) -> Unit,
    onShowModelInfo: (String) -> Unit,
    onSetThemeMode: (ThemeMode) -> Unit,
    onSetDebugModeEnabled: (Boolean) -> Unit,
    onSetTestModeEnabled: (Boolean) -> Unit,
    onSetPrivacyMode: (PrivacyMode) -> Unit,
    onSetCustomPrivacyOptions: (CustomPrivacyOptions) -> Unit,
    onSaveProtectedBrandsCsv: () -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSyncPolicy: () -> Unit,
    onPingBackend: () -> Unit,
    onExportDataset: () -> Unit,
    onExportAlerts: () -> Unit,
    onExportForensics: () -> Unit,
    onFlushExportQueue: () -> Unit,
    onPurgeData: () -> Unit
) {
    var isTokenVisible by rememberSaveable { mutableStateOf(false) }
    val serverOnline = config.lastServerPingStatus == "online"
    val serverStatusLabel = when (config.lastServerPingStatus) {
        "online" -> "Online"
        "offline" -> "Offline"
        "not_configured" -> "Not configured"
        null -> "Unknown"
        else -> config.lastServerPingStatus.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
    }
    val devicePresenceLabel = when (config.lastDeviceHeartbeatStatus) {
        "online" -> "Visible"
        "offline" -> "Offline"
        "not_configured" -> "Not configured"
        null -> "Unknown"
        else -> config.lastDeviceHeartbeatStatus.replace('_', ' ').replaceFirstChar { it.uppercaseChar() }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(start = 0.dp, top = 16.dp, end = 0.dp, bottom = 24.dp)
    ) {
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Text("Cloud connection", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Connect the app to your dashboard for cloud analysis, policy updates, and alert sync.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = backendUrl,
                        onValueChange = onBackendUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Server address") }
                    )
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
                        label = { Text("Access token") }
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onSaveBackendUrl, modifier = Modifier.weight(1f)) {
                            Text("Save server")
                        }
                        Button(onClick = onSaveApiToken, modifier = Modifier.weight(1f)) {
                            Text("Save token")
                        }
                    }
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                if (config.isConfigured()) "Cloud connection is configured."
                                else "Add a server address and access token to enable cloud features.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Device ID: $deviceIdPseudo",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Server: $serverStatusLabel • ${formatOptionalTimestamp(config.lastServerPingEpoch)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (serverOnline) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Device presence: $devicePresenceLabel • ${formatOptionalTimestamp(config.lastDeviceHeartbeatEpoch)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Last cloud update: ${formatOptionalTimestamp(config.lastPolicySyncEpoch)} • ${config.lastPolicySyncStatus ?: "never"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            if (config.debugModeEnabled && !config.lastPolicyDiffSummary.isNullOrBlank()) {
                                Text(
                                    "Policy changes: ${config.lastPolicyDiffSummary}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onPingBackend, modifier = Modifier.weight(1f)) {
                            Text("Check")
                        }
                        OutlinedButton(onClick = onSyncPolicy, modifier = Modifier.weight(1f)) {
                            Text("Update")
                        }
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
                        "Detection style",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Choose the on-device scoring behavior. Cloud assistance is controlled separately below and uses the selected privacy mode when sending feature windows.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        items(PRIMARY_DETECTION_MODELS) { model ->
                            ModelInfoChip(
                                label = modelDisplayName(model),
                                selected = config.detectionModel == model,
                                onClick = { onSetDetectionModel(model) },
                                onLongPress = { onShowModelInfo(model) }
                            )
                        }
                    }
                    Text(
                        "Long-press a style to see how it behaves and when to use it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Backend analysis")
                                Text(
                                    if (config.detectionModel == AnomalyEngine.MODE_REMOTE) {
                                        "Backend scoring is active. The backend payload follows the privacy level selected below."
                                    } else {
                                        "Keep detection local, or enable backend scoring when you want the server-side model."
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = config.detectionModel == AnomalyEngine.MODE_REMOTE,
                                onCheckedChange = { enabled ->
                                    onSetDetectionModel(
                                        if (enabled) AnomalyEngine.MODE_REMOTE else AnomalyEngine.MODE_ENSEMBLE
                                    )
                                },
                                enabled = runtimeHealth.remoteConfigured || config.detectionModel == AnomalyEngine.MODE_REMOTE
                            )
                        }
                    }

                    if (config.debugModeEnabled) {
                        Text(
                            "Advanced local detectors",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        LazyRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            items(ADVANCED_DETECTION_MODELS) { model ->
                                ModelInfoChip(
                                    label = modelDisplayName(model),
                                    selected = config.detectionModel == model,
                                    onClick = { onSetDetectionModel(model) },
                                    onLongPress = { onShowModelInfo(model) }
                                )
                            }
                        }
                    }

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
                        items(SHADOW_MODEL_FILTERS) { model ->
                            ModelInfoChip(
                                label = modelDisplayName(model),
                                selected = config.shadowModel == model,
                                onClick = { onSetShadowModel(model) },
                                onLongPress = { onShowModelInfo(model) }
                            )
                        }
                    }
                    Text(
                        "Backend retraining updates the backend scorer and the backend contribution inside Fusion. Local RF models update when a new app build ships with refreshed assets.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text("Runtime availability", style = MaterialTheme.typography.labelLarge)
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                RuntimeHealthChip("On-device", runtimeHealth.localModelAvailable)
                                RuntimeHealthChip("Experimental", runtimeHealth.tfliteAvailable)
                                RuntimeHealthChip("Cloud", runtimeHealth.remoteConfigured)
                            }
                            if (config.debugModeEnabled) {
                                Text(
                                    "Packets ${runtimeHealth.packetPipeline.packetsRead} • Active flows ${runtimeHealth.packetPipeline.activeFlows} • Parser failures ${runtimeHealth.packetPipeline.parserFailure}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    "Queue drops: forward ${runtimeHealth.packetPipeline.forwardQueueDropped}, ingress ${runtimeHealth.packetPipeline.analysisIngressDropped}, shard ${runtimeHealth.packetPipeline.analysisShardDropped}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    "Latency avg (ms): read to parse ${formatLatency(runtimeHealth.packetPipeline.readToParseAvgMs)}, parse to shard ${formatLatency(runtimeHealth.packetPipeline.parseToShardAvgMs)}, shard to flush ${formatLatency(runtimeHealth.packetPipeline.shardToFlushAvgMs)}, flush to persist ${formatLatency(runtimeHealth.packetPipeline.flushToPersistAvgMs)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }

        if (config.debugModeEnabled) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text("Protected brands", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "One brand per line. These names are used by the local destination-intelligence engine for lookalike and phishing-style domain detection.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        OutlinedTextField(
                            value = protectedBrandsCsv,
                            onValueChange = onProtectedBrandsCsvChange,
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 6,
                            label = { Text("Protected brand watchlist") }
                        )
                        OutlinedButton(onClick = onSaveProtectedBrandsCsv, modifier = Modifier.fillMaxWidth()) {
                            Text("Save protected brands")
                        }
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
                    Text("Cloud sync")
                    Text(
                        if (config.privacyModeEnabled) {
                            "Privacy mode anonymizes cloud sync. Enabling sync also sends recent local flows and alerts so they appear in the dashboard."
                        } else {
                            "HTTPS is recommended. Local HTTP is only for development. Enabling sync also sends recent local flows and alerts so they appear in the dashboard."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                "Last export: ${formatOptionalTimestamp(config.lastExportSuccessEpoch)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                "Last batch size: ${config.lastExportSentCount} • Last error: ${config.lastExportError ?: "none"}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = config.exportEnabled,
                            onCheckedChange = onToggleExport,
                            enabled = true
                        )
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(onClick = onExportDataset, modifier = Modifier.weight(1f)) {
                            Text("Export flows", style = MaterialTheme.typography.labelSmall)
                        }
                        OutlinedButton(onClick = onExportAlerts, modifier = Modifier.weight(1f)) {
                            Text("Export alerts", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedButton(onClick = onFlushExportQueue, modifier = Modifier.weight(1f)) {
                            Text("Send queued", style = MaterialTheme.typography.labelSmall)
                        }
                        OutlinedButton(onClick = onPurgeData, modifier = Modifier.weight(1f)) {
                            Text("Delete data", style = MaterialTheme.typography.labelSmall)
                        }
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
                    Text("Privacy and diagnostics", style = MaterialTheme.typography.titleMedium)

                    Text("Privacy mode", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "Choose how much destination and app detail is visible in synced data.",
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
                            Text("Test mode")
                            Text(
                                "Lower browser-risk thresholds for manual validation sessions and demonstration testing.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = config.testModeEnabled,
                            onCheckedChange = onSetTestModeEnabled
                        )
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Diagnostics mode")
                            Text(
                                "Shows raw identifiers, destination details, model diagnostics, and advanced actions.",
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
                        Row(modifier = Modifier.fillMaxWidth()) {
                            OutlinedButton(onClick = onExportForensics, modifier = Modifier.fillMaxWidth()) {
                                Text("Forensics bundle", style = MaterialTheme.typography.labelSmall)
                            }
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
            .clip(shape)
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
private fun AppAlertsView(
    alerts: List<AnomalyAlert>,
    allFilteredAlerts: List<AnomalyAlert>,
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
    debugModeEnabled: Boolean,
    privacyModeEnabled: Boolean,
    currentAppProfile: (String) -> AppProfile,
    onSetAppProfile: (String, AppProfile) -> Unit,
    pendingUndo: PendingUndoAction?,
    onUndoPendingAction: () -> Unit
) {
    var filtersExpanded by rememberSaveable { mutableStateOf(false) }
    var compactRepeatedAlerts by rememberSaveable { mutableStateOf(true) }

    val displayedAlerts = remember(alerts, compactRepeatedAlerts) {
        if (!compactRepeatedAlerts) {
            alerts
        } else {
            alerts
                .groupBy { alert ->
                    alert.correlationKey.takeIf { it.isNotBlank() }
                        ?: "${alert.appId}|${alert.sourceModel}|${alert.siteHint ?: alert.destinationHash ?: "unknown"}"
                }
                .map { (_, grouped) -> grouped.maxByOrNull { it.lastSeenMillis } ?: grouped.first() }
                .sortedByDescending { it.createdAtMillis }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
                        Text("Alerts for this app", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (allFilteredAlerts.isNotEmpty()) "${allFilteredAlerts.size} matching alerts" else "No matching alerts",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    OutlinedButton(onClick = { filtersExpanded = !filtersExpanded }) {
                        Text(if (filtersExpanded) "Hide" else "Show")
                    }
                }

                AnimatedVisibility(visible = filtersExpanded) {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = onSearchQueryChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Search explanation / site / features") }
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Compact repeated alerts", style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "Collapse repeated incidents into the latest alert card for this app.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = compactRepeatedAlerts,
                                onCheckedChange = { compactRepeatedAlerts = it }
                            )
                        }

                        Text("Severity", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            items(SeverityFilter.values().toList()) { filter ->
                                FilterChip(
                                    selected = filter == severityFilter,
                                    onClick = { onSeverityFilterChange(filter) },
                                    label = { Text("${filter.label} (${severityCounts[filter] ?: 0})") }
                                )
                            }
                        }

                        Text("Model", style = MaterialTheme.typography.labelLarge)
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                    "Showing ${displayedAlerts.size} alerts on this page",
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

        if (allFilteredAlerts.isEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("No alerts for this app match the current filters.")
                    if (debugModeEnabled) {
                        Text(
                            if (privacyModeEnabled) {
                                "Debug hint: privacy mode can hide some destination context even when alerts are still present."
                            } else {
                                "Debug hint: use the model and shadow filters to compare how this app is being scored."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            displayedAlerts.forEach { alert ->
                if (pendingUndo?.alertId == alert.id) {
                    PendingUndoCard(
                        pendingUndo = pendingUndo,
                        onUndoPendingAction = onUndoPendingAction
                    )
                } else {
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
            }
            if (totalPages > 1) {
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
                            OutlinedButton(onClick = onPreviousPage, enabled = currentPage > 1, modifier = Modifier.weight(1f)) {
                                Text("Previous")
                            }
                            Button(onClick = onNextPage, enabled = currentPage < totalPages, modifier = Modifier.weight(1f)) {
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
private fun PendingUndoCard(
    pendingUndo: PendingUndoAction,
    onUndoPendingAction: () -> Unit
) {
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
            OutlinedButton(
                onClick = onUndoPendingAction,
                modifier = Modifier.defaultMinSize(minHeight = 40.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Text("Undo", style = MaterialTheme.typography.labelSmall)
            }
        }
    }
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
    val container = alertContainerColor(alert.severity)
    val contentColor = alertContentColor(alert.severity)
    val accent = alertAccentColor(alert.severity)
    val appLabel = remember(alert.appId) { displayAppName(alert.appId) }
    val destinationSummary = formatDestinationSummary(alert = alert, privacyModeEnabled = privacyModeEnabled)
    val normalizedContributors = remember(alert.featureContributions, alert.responseScore) {
        normalizeContributors(alert.featureContributions, alert.responseScore)
    }
    val suppressionTokens = remember(alert.suppressionReason) {
        parseSuppressionTokens(alert.suppressionReason)
    }
    val shortReason = remember(alert.explanation) { primaryAlertReason(alert.explanation) }
    val cardShape = RoundedCornerShape(18.dp)
    var detailsOpen by rememberSaveable(alert.id) { mutableStateOf(false) }
    var showingShadowScore by rememberSaveable(alert.id) { mutableStateOf(false) }
    val primaryChipLabel = "${modelDisplayName(alert.sourceModel)} ${formatDecimal(alert.responseScore)}"
    val shadowChipLabel = alert.shadowModel?.let { model ->
        "Shadow ${modelDisplayName(model)} ${formatDecimal(alert.shadowScore ?: 0.0)}"
    }
    val dismissState = rememberSwipeToDismissBoxState(
        positionalThreshold = { distance -> distance * 0.35f },
        confirmValueChange = { value ->
            when (value) {
                SwipeToDismissBoxValue.StartToEnd -> {
                    onMarkFalsePositive()
                    true
                }
                SwipeToDismissBoxValue.EndToStart -> {
                    onMarkDangerous()
                    true
                }
                SwipeToDismissBoxValue.Settled -> false
            }
        }
    )
    val dismissDirection = dismissState.dismissDirection
    val swipeTargetColor = when (dismissDirection) {
        SwipeToDismissBoxValue.StartToEnd -> Color(0xFF2E7D32)
        SwipeToDismissBoxValue.EndToStart -> Color(0xFFB3261E)
        SwipeToDismissBoxValue.Settled -> MaterialTheme.colorScheme.surfaceVariant
    }
    val swipeBackgroundColor by animateColorAsState(targetValue = swipeTargetColor, label = "alertSwipeBackground")

    SwipeToDismissBox(
        state = dismissState,
        backgroundContent = {
            val label = when (dismissDirection) {
                SwipeToDismissBoxValue.StartToEnd -> "False positive"
                SwipeToDismissBoxValue.EndToStart -> "Dangerous"
                SwipeToDismissBoxValue.Settled -> "Swipe right for false positive • left for dangerous"
            }
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .clip(cardShape)
                    .background(swipeBackgroundColor)
                    .padding(horizontal = 18.dp, vertical = 22.dp)
            ) {
                Text(
                    label,
                    modifier = Modifier.align(
                        when (dismissDirection) {
                            SwipeToDismissBoxValue.StartToEnd -> Alignment.CenterStart
                            SwipeToDismissBoxValue.EndToStart -> Alignment.CenterEnd
                            SwipeToDismissBoxValue.Settled -> Alignment.Center
                        }
                    ),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold,
                    color = if (dismissDirection == SwipeToDismissBoxValue.EndToStart) {
                        Color.White
                    } else {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    },
                    maxLines = 1
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

                Text(
                    shortReason,
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor.copy(alpha = 0.92f)
                )
                LazyRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    item {
                        ModelInfoChip(
                            label = primaryChipLabel,
                            selected = !showingShadowScore,
                            onClick = { showingShadowScore = false },
                            onLongPress = { onShowInfo(alert.sourceModel) }
                        )
                    }
                    if (!alert.shadowModel.isNullOrBlank()) {
                        item {
                            ModelInfoChip(
                                label = shadowChipLabel ?: "Shadow ${modelDisplayName(alert.shadowModel.orEmpty())}",
                                selected = showingShadowScore,
                                onClick = { showingShadowScore = true },
                                onLongPress = { onShowInfo(alert.shadowModel.orEmpty()) }
                            )
                        }
                    }
                }

                Text(
                    if (showingShadowScore && alert.shadowScore != null) {
                        "Viewing shadow comparison score"
                    } else {
                        "Viewing primary response score"
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = accent
                )
                Text(
                    if (showingShadowScore && alert.shadowScore != null) {
                        "Shadow score ${"%.3f".format(alert.shadowScore)} • Primary response ${"%.3f".format(alert.responseScore)}"
                    } else {
                        "Response ${"%.3f".format(alert.responseScore)} • Anomaly ${"%.3f".format(alert.baseAnomalyScore)} • Context ${"%.3f".format(alert.contextScore)}"
                    },
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
                        if (showingShadowScore && alert.shadowScore != null) {
                            "Shadow mode only has the comparison score. Contributor badges still reflect the primary alert."
                        } else {
                            "Each score is normalized to this alert's response score."
                        },
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
                        onClick = onMarkDangerous,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 42.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp)
                    ) {
                        Text("Dangerous", style = MaterialTheme.typography.labelSmall, maxLines = 1)
                    }
                    OutlinedButton(
                        onClick = onMarkFalsePositive,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 42.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp)
                    ) {
                        Text(
                            "False positive",
                            maxLines = 1,
                            softWrap = false,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                    OutlinedButton(
                        onClick = onDismissNeutral,
                        modifier = Modifier
                            .weight(1f)
                            .defaultMinSize(minHeight = 42.dp),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 10.dp)
                    ) {
                        Text("Neutral", style = MaterialTheme.typography.labelSmall, maxLines = 1)
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

private fun loadInstalledApps(packageManager: PackageManager?): List<InstalledAppCatalogEntry> {
    if (packageManager == null) {
        return emptyList()
    }
    return runCatching {
        packageManager.getInstalledApplications(0)
            .mapNotNull { appInfo ->
                val packageName = appInfo.packageName?.trim().orEmpty()
                if (packageName.isBlank()) {
                    null
                } else {
                    InstalledAppCatalogEntry(
                        appId = packageName,
                        label = packageManager.getApplicationLabel(appInfo)?.toString()?.trim().takeUnless { it.isNullOrBlank() }
                            ?: displayAppName(packageName),
                        isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                            (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                    )
                }
            }
            .sortedBy { it.label.lowercase() }
    }.getOrDefault(emptyList())
}

private fun buildAppInventory(
    installedApps: List<InstalledAppCatalogEntry>,
    alerts: List<AnomalyAlert>,
    searchQuery: String,
    typeFilter: AppTypeFilter,
    statusFilter: AppStatusFilter,
    sortOption: AppSortOption,
    baseThresholdProfile: ThresholdProfile,
    thresholdOverrides: Map<String, ThresholdProfile>,
    appProfileOverrides: Map<String, AppProfile>
): List<AppInventoryEntry> {
    val alertsByApp = alerts.groupBy { it.appId }
    val installedById = installedApps.associateBy { it.appId }
    val allAppIds = (installedById.keys + alertsByApp.keys).toSortedSet()
    val normalizedQuery = searchQuery.trim().lowercase()

    return allAppIds.mapNotNull { appId ->
        val installed = installedById[appId]
        val appAlerts = alertsByApp[appId].orEmpty()
        val isSystem = installed?.isSystem ?: (appId.startsWith("com.android.") || appId.startsWith("android."))
        val typeMatches = when (typeFilter) {
            AppTypeFilter.ALL -> true
            AppTypeFilter.USER -> !isSystem
            AppTypeFilter.SYSTEM -> isSystem
        }
        if (!typeMatches) {
            return@mapNotNull null
        }

        val label = installed?.label ?: displayAppName(appId)
        if (normalizedQuery.isNotBlank() &&
            !label.lowercase().contains(normalizedQuery) &&
            !appId.lowercase().contains(normalizedQuery)
        ) {
            return@mapNotNull null
        }

        val highestSeverity = appAlerts.maxByOrNull { it.severity.rank() }?.severity
        val openAlertCount = appAlerts.count { it.triageStatus == TriageStatus.OPEN }
        val statusMatches = when (statusFilter) {
            AppStatusFilter.ALL -> true
            AppStatusFilter.OPEN_ALERTS -> openAlertCount > 0
            AppStatusFilter.HAS_ALERTS -> appAlerts.isNotEmpty()
            AppStatusFilter.HIGH_RISK -> highestSeverity == AlertSeverity.HIGH
            AppStatusFilter.QUIET -> appAlerts.isEmpty()
        }
        if (!statusMatches) {
            return@mapNotNull null
        }

        val thresholdProfile = thresholdOverrides[appId] ?: baseThresholdProfile
        AppInventoryEntry(
            appId = appId,
            label = label,
            isInstalled = installed != null,
            isSystem = isSystem,
            alertCount = appAlerts.size,
            openAlertCount = openAlertCount,
            highestSeverity = highestSeverity,
            lastAlertMillis = appAlerts.maxOfOrNull { it.lastSeenMillis } ?: 0L,
            thresholdLow = thresholdProfile.low,
            thresholdMedium = thresholdProfile.medium,
            thresholdHigh = thresholdProfile.high,
            profile = appProfileOverrides[appId] ?: defaultProfileForAppId(appId)
        )
    }.sortedWith(appInventoryComparator(sortOption))
}

private fun appInventoryComparator(sortOption: AppSortOption): Comparator<AppInventoryEntry> {
    return when (sortOption) {
        AppSortOption.SMART -> compareByDescending<AppInventoryEntry> { it.highestSeverity?.rank() ?: 0 }
            .thenByDescending { it.openAlertCount }
            .thenByDescending { it.alertCount }
            .thenByDescending { it.isInstalled }
            .thenBy { it.label.lowercase() }
        AppSortOption.RECENT -> compareByDescending<AppInventoryEntry> { it.lastAlertMillis }
            .thenBy { it.label.lowercase() }
        AppSortOption.ALERTS -> compareByDescending<AppInventoryEntry> { it.alertCount }
            .thenByDescending { it.openAlertCount }
            .thenBy { it.label.lowercase() }
        AppSortOption.NAME -> compareBy<AppInventoryEntry> { it.label.lowercase() }
            .thenBy { it.appId }
    }
}

private fun defaultProfileForAppId(appId: String): AppProfile {
    return when {
        appId.startsWith("com.android.") || appId.startsWith("android.") -> AppProfile.SYSTEM
        appId in BROWSER_APP_IDS -> AppProfile.BROWSER
        else -> AppProfile.DEFAULT
    }
}

private fun AlertSeverity.rank(): Int = when (this) {
    AlertSeverity.HIGH -> 3
    AlertSeverity.MEDIUM -> 2
    AlertSeverity.LOW -> 1
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
    AnomalyEngine.MODE_ENSEMBLE -> "Fusion"
    AnomalyEngine.MODE_STATISTICAL -> "Statistical"
    AnomalyEngine.MODE_MULTIVARIATE -> "Correlation"
    AnomalyEngine.MODE_SEQUENCE -> "Temporal transition"
    AnomalyEngine.MODE_LOCAL -> "Standard RF"
    AnomalyEngine.MODE_LOCAL_SENSITIVE -> "High-recall RF"
    AnomalyEngine.MODE_LOCAL_QUIET -> "Low-FPR RF"
    AnomalyEngine.MODE_LOCAL_BALANCED -> "Adaptive hybrid RF"
    AnomalyEngine.MODE_LOCAL_PRIVACY -> "Privacy RF"
    AnomalyEngine.MODE_TFLITE -> "TFLite"
    AnomalyEngine.MODE_REMOTE -> "Backend"
    else -> model
}

private fun infoDisplayName(key: String): String = when (key) {
    "signal:beacon" -> "Beacon"
    "signal:drift" -> "Drift"
    "signal:reputation" -> "Reputation"
    "signal:data_quality" -> "Quality"
    "signal:response_anomaly" -> "Anomaly"
    "signal:response_context" -> "Context"
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
        "Combines the available statistical, correlation, temporal, RF, optional TFLite, backend, and context signals. It is the default because it smooths short-lived spikes and avoids relying on one detector."
    AnomalyEngine.MODE_STATISTICAL ->
        "A lightweight baseline based on traffic deviations. It is fast and transparent, but less adaptive than the trained local models."
    AnomalyEngine.MODE_MULTIVARIATE ->
        "Scores correlated feature shifts together, so related changes in volume, packet rate, and duration are treated as one pattern instead of separate spikes."
    AnomalyEngine.MODE_SEQUENCE ->
        "Looks for unusual order and timing between recent windows, not just unusual magnitude in a single window."
    AnomalyEngine.MODE_LOCAL ->
        "Uses the bundled full-feature on-device random forest. It is deterministic, efficient, and works without the backend."
    AnomalyEngine.MODE_LOCAL_SENSITIVE ->
        "Catches more suspicious behavior earlier. Use it when missing an alert is worse than seeing extra candidates."
    AnomalyEngine.MODE_LOCAL_QUIET ->
        "Raises fewer alerts by requiring stronger evidence. Use it when the app feels noisy."
    AnomalyEngine.MODE_LOCAL_BALANCED ->
        "Combines High-recall RF and Low-FPR RF. Malware-like traffic keeps sensitivity, while service and system traffic needs stronger agreement."
    AnomalyEngine.MODE_LOCAL_PRIVACY ->
        "Uses a dedicated random forest trained with the reduced privacy feature view, so privacy mode does not rely on a full-feature model seeing missing or coarsened inputs."
    AnomalyEngine.MODE_TFLITE ->
        "Uses the optional TensorFlow Lite inference asset when present, otherwise falls back to local scoring. Keep it in diagnostics unless the asset is available and validated."
    AnomalyEngine.MODE_REMOTE ->
        "Sends a compact feature window to the backend scorer. The Off, Low, Medium, Strict, or Custom privacy mode controls which identifiers and destination hints are included."
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
        return positive
            .sortedByDescending { it.value }
            .take(4)
            .map { it.key to 0.0 }
    }
    return positive
        .sortedByDescending { it.value }
        .take(4)
        .map { entry -> entry.key to ((entry.value / total) * responseScore).coerceIn(0.0, 1.0) }
}

private fun primaryAlertReason(explanation: String): String {
    val normalized = explanation
        .substringBefore(" Suppression:")
        .substringBefore("Top contributors")
        .trim()
    return normalized.ifBlank { "Anomalous behavior detected." }
}

@Composable
private fun RuntimeHealthChip(label: String, available: Boolean) {
    ModelInfoChip(
        label = "$label ${if (available) "ready" else "unavailable"}",
        selected = available,
        onClick = {},
        onLongPress = {}
    )
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
    PrivacyMode.LOW -> "Low"
    PrivacyMode.MEDIUM -> "Medium"
    PrivacyMode.STRICT -> "Strict"
    PrivacyMode.CUSTOM -> "Custom"
}

private fun privacyModeDescription(mode: PrivacyMode): String = when (mode) {
    PrivacyMode.OFF ->
        "Exports normal app identifiers and destination context."
    PrivacyMode.LOW ->
        "Hashes raw IP addresses but keeps app identifiers and selected site context for lighter privacy with easier debugging."
    PrivacyMode.MEDIUM ->
        "Hashes app and IP identifiers while preserving operational metadata such as ports and feature summaries."
    PrivacyMode.STRICT ->
        "Hashes app and IP identifiers, removes site hints, and minimizes evidence fields."
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
        PrivacyMode.LOW -> "com.android.chrome"
        PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(app_id)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeAppId) "com.android.chrome" else "sha256(app_id)"
    }
    val srcIp = when (config.privacyMode) {
        PrivacyMode.OFF -> "10.0.0.2"
        PrivacyMode.LOW, PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(src_ip)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeIpAddresses) "10.0.0.2" else "sha256(src_ip)"
    }
    val dstIp = when (config.privacyMode) {
        PrivacyMode.OFF -> "93.184.216.34"
        PrivacyMode.LOW, PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(dst_ip)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeIpAddresses) "93.184.216.34" else "sha256(dst_ip)"
    }
    val dstPort = when (config.privacyMode) {
        PrivacyMode.STRICT -> "443 (coarse, minimal context)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeExactPorts) "443" else "443 (service bucket)"
        else -> "443"
    }
    val destinationKey = when (config.privacyMode) {
        PrivacyMode.OFF -> "www.example.com:443"
        PrivacyMode.LOW -> "www.example.com:443"
        PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(destination_key)"
        PrivacyMode.CUSTOM -> when {
            config.customPrivacy.includeSiteHint -> "www.example.com:443"
            config.customPrivacy.includeIpAddresses -> "93.184.216.34:443"
            else -> "sha256(destination_key)"
        }
    }
    val explain = when (config.privacyMode) {
        PrivacyMode.OFF -> "[novelty_score, destination_diversity, periodic_beacon_score]"
        PrivacyMode.LOW -> "[feature_window, readable destination_key, hashed IPs]"
        PrivacyMode.MEDIUM -> "[feature_window, ports, protocol, hashed identifiers]"
        PrivacyMode.STRICT -> "[feature_window only, no site hint, minimal endpoint context]"
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
        destination_key=$destinationKey
        is_new_destination_for_app=1.0
        explain_top_features=$explain
    """.trimIndent()
}

private fun buildAlertPreviewText(deviceIdPseudo: String, config: EndpointConfig): String {
    val appId = when (config.privacyMode) {
        PrivacyMode.OFF -> "com.android.chrome"
        PrivacyMode.LOW -> "com.android.chrome"
        PrivacyMode.MEDIUM, PrivacyMode.STRICT -> "sha256(app_id)"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeAppId) "com.android.chrome" else "sha256(app_id)"
    }
    val siteHint = when (config.privacyMode) {
        PrivacyMode.OFF -> "google.com"
        PrivacyMode.LOW -> "google.com"
        PrivacyMode.MEDIUM -> "removed"
        PrivacyMode.STRICT -> "removed"
        PrivacyMode.CUSTOM -> if (config.customPrivacy.includeSiteHint) "google.com" else "removed"
    }
    val destinationContext = when (config.privacyMode) {
        PrivacyMode.LOW -> "site and risk context retained"
        PrivacyMode.MEDIUM -> "risk summary retained"
        PrivacyMode.STRICT -> "minimal risk context only"
        PrivacyMode.OFF -> "site and risk context retained"
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
    "ttl_metrics_present" -> "TTL visibility"
    "transport_metrics_present" -> "Transport metrics visibility"
    "data_quality_penalty" -> "Data-quality penalty"
    "hour_of_day_sin", "hour_of_day_cos" -> "Time-of-day pattern"
    "phishing_domain_pattern" -> "Phishing-style host"
    "credential_lure_pattern" -> "Credential-lure host"
    "tracking_destination" -> "Tracking destination"
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
    "ttl_metrics_present" -> "TTL metadata became newly available or disappeared for this traffic"
    "transport_metrics_present" -> "Transport-side metadata availability changed for this traffic"
    "data_quality_penalty" -> "The final score was adjusted because the captured metadata quality was lower than normal"
    "hour_of_day_sin", "hour_of_day_cos" -> "The activity landed in an unusual time-of-day pattern for this app"
    "phishing_domain_pattern" -> "The destination hostname matched phishing-style domain heuristics"
    "credential_lure_pattern" -> "The destination hostname resembled a login, verify, or credential-lure pattern"
    "tracking_destination" -> "The destination matched tracking, advertising, or telemetry heuristics"
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

private fun formatLatency(value: Double): String = "%.2f".format(value)
