package com.manta.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.manta.app.R
import kotlinx.coroutines.delay

private val DemoInk = Color(0xFF071B18)
private val DemoTeal = Color(0xFF44D7C2)
private val DemoLime = Color(0xFFB7ED67)
private val DemoAmber = Color(0xFFFFC45E)
private val DemoRed = Color(0xFFFF7D7D)

private enum class DemoTab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Default.Home),
    APPS("Apps", Icons.Default.Apps),
    ALERTS("Alerts", Icons.Default.Notifications),
    SETTINGS("Settings", Icons.Default.Settings)
}

private data class DemoApp(
    val name: String,
    val packageName: String,
    val status: String,
    val detail: String,
    val color: Color
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PublicDemoScreen(
    initialPage: Int,
    autoAdvance: Boolean,
    modifier: Modifier = Modifier
) {
    var selectedTab by remember(initialPage) {
        mutableStateOf(DemoTab.entries[initialPage.coerceIn(0, DemoTab.entries.lastIndex)])
    }
    var protectionActive by remember { mutableStateOf(true) }
    var alertResolved by remember { mutableStateOf(false) }
    var privacyLevel by remember { mutableIntStateOf(2) }

    LaunchedEffect(autoAdvance) {
        if (!autoAdvance) return@LaunchedEffect
        while (true) {
            delay(4_800)
            selectedTab = DemoTab.entries[(selectedTab.ordinal + 1) % DemoTab.entries.size]
        }
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Image(
                            painter = painterResource(R.drawable.logo),
                            contentDescription = null,
                            modifier = Modifier.size(38.dp)
                        )
                        Column {
                            Text("MANTA", fontWeight = FontWeight.Bold)
                            Text(
                                "Metadata-only endpoint monitor",
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
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                DemoTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = { Icon(tab.icon, contentDescription = null) },
                        label = { Text(tab.label) },
                        colors = NavigationBarItemDefaults.colors(
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    )
                }
            }
        }
    ) { padding ->
        when (selectedTab) {
            DemoTab.HOME -> DemoHome(
                protectionActive = protectionActive,
                onToggleProtection = { protectionActive = !protectionActive },
                onOpenAlerts = { selectedTab = DemoTab.ALERTS },
                modifier = Modifier.padding(padding)
            )
            DemoTab.APPS -> DemoApps(modifier = Modifier.padding(padding))
            DemoTab.ALERTS -> DemoAlerts(
                resolved = alertResolved,
                onResolve = { alertResolved = true },
                modifier = Modifier.padding(padding)
            )
            DemoTab.SETTINGS -> DemoSettings(
                privacyLevel = privacyLevel,
                onPrivacyLevelChange = { privacyLevel = it },
                modifier = Modifier.padding(padding)
            )
        }
    }
}

@Composable
private fun DemoHome(
    protectionActive: Boolean,
    onToggleProtection: () -> Unit,
    onOpenAlerts: () -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = DemoInk),
                shape = RoundedCornerShape(30.dp)
            ) {
                Column(
                    modifier = Modifier.padding(22.dp),
                    verticalArrangement = Arrangement.spacedBy(18.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            color = DemoTeal.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(999.dp)
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 11.dp, vertical = 7.dp),
                                horizontalArrangement = Arrangement.spacedBy(7.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(7.dp)
                                        .background(if (protectionActive) DemoLime else DemoAmber, CircleShape)
                                )
                                Text(
                                    if (protectionActive) "PROTECTION ACTIVE" else "PROTECTION PAUSED",
                                    color = Color.White,
                                    style = MaterialTheme.typography.labelLarge
                                )
                            }
                        }
                        Icon(Icons.Default.Shield, contentDescription = null, tint = DemoTeal)
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        Text(
                            if (protectionActive) "Monitoring network behaviour" else "Capture is currently paused",
                            style = MaterialTheme.typography.headlineMedium,
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            "MANTA scores encrypted traffic from timing, volume and destination metadata. Packet payloads are never inspected.",
                            color = Color(0xFFB9CCC7),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                    Button(
                        onClick = onToggleProtection,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (protectionActive) Color(0xFF173E38) else DemoTeal,
                            contentColor = if (protectionActive) DemoTeal else DemoInk
                        )
                    ) {
                        Text(if (protectionActive) "Pause capture" else "Start protected capture")
                    }
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                DemoMetric("1,284", "flows today", Modifier.weight(1f))
                DemoMetric("3", "open alerts", Modifier.weight(1f))
                DemoMetric("0", "payloads read", Modifier.weight(1f))
            }
        }

        item {
            DemoSectionLabel("Needs attention", "One high-confidence pattern")
        }

        item {
            Card(
                onClick = onOpenAlerts,
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(18.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(DemoRed.copy(alpha = 0.18f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("82", color = MaterialTheme.colorScheme.onErrorContainer, fontWeight = FontWeight.Bold)
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Telegram", fontWeight = FontWeight.Bold)
                        Text(
                            "Rare destination · outbound burst",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.72f)
                        )
                    }
                    Text("Review", color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.Bold)
                }
            }
        }

        item {
            DemoSectionLabel("Runtime", "Local inference and server assistance")
        }

        item {
            Card(shape = RoundedCornerShape(22.dp)) {
                Column(modifier = Modifier.padding(18.dp)) {
                    DemoStatusRow("On-device model", "Android RF · balanced", "Ready", DemoLime)
                    DemoStatusRow("Privacy export", "Medium · identifiers hashed", "On", DemoTeal)
                    DemoStatusRow("Server backend", "Last sync 14 seconds ago", "Online", DemoTeal)
                }
            }
        }
    }
}

@Composable
private fun DemoApps(modifier: Modifier = Modifier) {
    val apps = listOf(
        DemoApp("Telegram", "org.telegram.messenger", "Needs review", "3 alerts · last activity now", DemoAmber),
        DemoApp("Chrome", "com.android.chrome", "Normal", "428 flows · baseline stable", DemoLime),
        DemoApp("Google Maps", "com.google.android.apps.maps", "Normal", "91 flows · baseline stable", DemoLime),
        DemoApp("Unknown UID 10284", "uid.10284", "High risk", "New destination family", DemoRed)
    )

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            DemoPageIntro(
                title = "App activity",
                body = "Per-app baselines, alert history and tuning profiles."
            )
        }
        items(apps) { app ->
            Card(shape = RoundedCornerShape(22.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(18.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(app.color.copy(alpha = 0.17f), RoundedCornerShape(14.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(app.name.take(1), color = app.color, fontWeight = FontWeight.Bold)
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(app.name, fontWeight = FontWeight.Bold)
                        Text(
                            app.packageName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(app.detail, style = MaterialTheme.typography.bodySmall)
                    }
                    Text(app.status, color = app.color, style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}

@Composable
private fun DemoAlerts(
    resolved: Boolean,
    onResolve: () -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            DemoPageIntro(
                title = "Alert triage",
                body = "Evidence from metadata windows, explained without exposing payload content."
            )
        }
        item {
            Card(
                shape = RoundedCornerShape(26.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (resolved) MaterialTheme.colorScheme.secondaryContainer
                    else MaterialTheme.colorScheme.errorContainer
                ),
                border = BorderStroke(1.dp, if (resolved) DemoTeal else DemoRed.copy(alpha = 0.55f))
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Telegram", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                            Text("High confidence · score 0.82", color = if (resolved) DemoTeal else MaterialTheme.colorScheme.error)
                        }
                        Surface(
                            color = if (resolved) DemoTeal.copy(alpha = 0.16f) else DemoRed.copy(alpha = 0.16f),
                            shape = RoundedCornerShape(999.dp)
                        ) {
                            Text(
                                if (resolved) "REVIEWED" else "OPEN",
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                fontWeight = FontWeight.Bold,
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }
                    Text(
                        "A rare destination appeared during a sharp outbound burst. The score combines local model output, periodicity and destination novelty.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Column {
                        DemoSignalRow("Destination novelty", 0.91f, DemoRed)
                        DemoSignalRow("Outbound byte spike", 0.78f, DemoAmber)
                        DemoSignalRow("Periodic beacon score", 0.64f, DemoTeal)
                    }
                    Text(
                        "Observed: 18:42 · No packet payload captured",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (!resolved) {
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(onClick = onResolve, modifier = Modifier.weight(1f)) {
                                Text("Mark dangerous")
                            }
                            OutlinedButton(onClick = onResolve, modifier = Modifier.weight(1f)) {
                                Text("False positive")
                            }
                        }
                    } else {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Check, contentDescription = null, tint = DemoTeal)
                            Text("Feedback saved for retraining", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DemoSettings(
    privacyLevel: Int,
    onPrivacyLevelChange: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    val levels = listOf("Low", "Medium", "Strict")
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            DemoPageIntro(
                title = "Privacy and models",
                body = "Control which metadata leaves the device and how anomaly decisions are made."
            )
        }
        item {
            Card(shape = RoundedCornerShape(24.dp)) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Column {
                            Text("Privacy mode", fontWeight = FontWeight.Bold)
                            Text(
                                levels[privacyLevel - 1],
                                color = MaterialTheme.colorScheme.primary,
                                style = MaterialTheme.typography.titleLarge
                            )
                        }
                    }
                    Text(
                        when (privacyLevel) {
                            1 -> "Readable app and site context; network addresses are hashed."
                            3 -> "Only the reduced feature window is exported; endpoint context is removed."
                            else -> "App and destination identifiers are hashed while useful timing and count features remain."
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        levels.forEachIndexed { index, label ->
                            OutlinedButton(
                                onClick = { onPrivacyLevelChange(index + 1) },
                                modifier = Modifier.weight(1f),
                                border = BorderStroke(
                                    1.dp,
                                    if (privacyLevel == index + 1) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
                                )
                            ) {
                                Text(label)
                            }
                        }
                    }
                }
            }
        }
        item {
            Card(shape = RoundedCornerShape(24.dp)) {
                Column(modifier = Modifier.padding(18.dp)) {
                    DemoStatusRow("Active detector", "Android RF · balanced", "Local", DemoLime)
                    DemoStatusRow("Shadow model", "Sequence detector", "Compare", DemoTeal)
                    DemoStatusRow("Server endpoint", "bachelor.elfeel.me", "Connected", DemoTeal)
                    DemoStatusRow("Export queue", "0 pending · 0 dead-letter", "Clear", DemoLime)
                }
            }
        }
    }
}

@Composable
private fun DemoPageIntro(title: String, body: String) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text(body, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun DemoSectionLabel(title: String, subtitle: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Bottom
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun DemoMetric(value: String, label: String, modifier: Modifier = Modifier) {
    Card(modifier = modifier, shape = RoundedCornerShape(20.dp)) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun DemoStatusRow(title: String, detail: String, status: String, color: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(modifier = Modifier.size(8.dp).background(color, CircleShape))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Bold)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(status, color = color, style = MaterialTheme.typography.labelLarge)
    }
}

@Composable
private fun DemoSignalRow(label: String, progress: Float, color: Color) {
    Column(
        modifier = Modifier.padding(vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodySmall)
            Text("${(progress * 100).toInt()}%", style = MaterialTheme.typography.labelLarge)
        }
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier.fillMaxWidth().height(7.dp),
            color = color,
            trackColor = color.copy(alpha = 0.13f)
        )
    }
}
