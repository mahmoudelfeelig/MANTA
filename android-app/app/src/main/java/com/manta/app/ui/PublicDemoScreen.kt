package com.manta.app.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.PrivacyTip
import androidx.compose.material.icons.filled.ReportProblem
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay

private val DemoBg = Color(0xFF071411)
private val DemoPanel = Color(0xFF111B18)
private val DemoCard = Color(0xFF1D2A26)
private val DemoCardStrong = Color(0xFF172A25)
private val DemoText = Color(0xFFF4F7F5)
private val DemoMuted = Color(0xFFB8C3BE)
private val DemoCyan = Color(0xFF67D8D0)
private val DemoGreen = Color(0xFF9BE36D)
private val DemoAmber = Color(0xFFF3B35A)
private val DemoRed = Color(0xFFF05D5E)

@Composable
fun PublicDemoScreen(
    initialPage: Int,
    autoAdvance: Boolean,
    modifier: Modifier = Modifier
) {
    var page by remember(initialPage) { mutableIntStateOf(initialPage.coerceIn(0, 2)) }

    LaunchedEffect(autoAdvance) {
        if (!autoAdvance) return@LaunchedEffect
        while (true) {
            delay(4_500)
            page = (page + 1) % 3
        }
    }

    Surface(
        modifier = modifier.fillMaxSize(),
        color = DemoBg
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF071411), Color(0xFF0D201B))
                    )
                )
                .padding(horizontal = 22.dp, vertical = 28.dp),
            contentAlignment = Alignment.Center
        ) {
            Card(
                modifier = Modifier.fillMaxSize(),
                shape = RoundedCornerShape(34.dp),
                colors = CardDefaults.cardColors(containerColor = DemoPanel),
                border = BorderStroke(1.dp, Color(0xFF243A34))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = 24.dp, vertical = 28.dp)
                ) {
                    Text(
                        text = "MANTA Endpoint",
                        style = MaterialTheme.typography.headlineLarge,
                        color = DemoText,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = when (page) {
                            1 -> "Plain-language security alert"
                            2 -> "Control how much metadata leaves the device"
                            else -> "Network safety without reading your messages"
                        },
                        style = MaterialTheme.typography.bodyLarge,
                        color = DemoMuted,
                        modifier = Modifier.padding(top = 4.dp)
                    )

                    Spacer(modifier = Modifier.height(34.dp))

                    when (page) {
                        1 -> AlertDemoPage()
                        2 -> PrivacyDemoPage()
                        else -> HomeDemoPage()
                    }
                }
            }
        }
    }
}

@Composable
private fun HomeDemoPage() {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = DemoCardStrong),
            border = BorderStroke(1.dp, Color(0xFF31534C))
        ) {
            Row(
                modifier = Modifier.padding(22.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                StatusIcon(icon = Icons.Default.Check, color = DemoCyan)
                Spacer(modifier = Modifier.width(18.dp))
                Column {
                    Text("PROTECTION ACTIVE", color = DemoCyan, fontWeight = FontWeight.Bold)
                    Text(
                        "Watching patterns, not private content",
                        color = DemoText,
                        fontWeight = FontWeight.Bold,
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                    Text(
                        "Payload inspection is off. Only traffic metadata is analyzed.",
                        color = DemoMuted,
                        modifier = Modifier.padding(top = 10.dp)
                    )
                }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            MetricTile("0", "message contents read", "No payload storage", Modifier.weight(1f))
            MetricTile("24/7", "background monitoring", "Low-noise scoring", Modifier.weight(1f))
        }

        Text(
            "Today at a glance",
            color = DemoText,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(top = 8.dp)
        )
        StatusRow("Normal app activity", "Expected timing and volume", "OK", DemoCyan)
        StatusRow("Unusual destination check", "One connection is queued for review", "REVIEW", DemoAmber)

        Spacer(modifier = Modifier.weight(1f))
        MessagePanel(
            title = "Why this matters",
            body = "A compromised app can look quiet on-screen while its network behavior changes."
        )
        DemoButton("Start protected capture")
    }
}

@Composable
private fun AlertDemoPage() {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF2A211C)),
            border = BorderStroke(2.dp, DemoAmber)
        ) {
            Column(modifier = Modifier.padding(22.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusIcon(icon = Icons.Default.ReportProblem, color = DemoAmber)
                    Spacer(modifier = Modifier.width(18.dp))
                    Column {
                        Text("SUSPICIOUS PATTERN", color = DemoAmber, fontWeight = FontWeight.Bold)
                        Text(
                            "Unusual app traffic",
                            color = DemoText,
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.headlineSmall,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                        Text(
                            "New destination and a sudden data spike. No message contents were inspected.",
                            color = DemoMuted,
                            modifier = Modifier.padding(top = 10.dp)
                        )
                    }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Button(
                        onClick = {},
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = DemoAmber, contentColor = Color(0xFF16110D))
                    ) {
                        Text("Review alert", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = {},
                        modifier = Modifier.weight(1f),
                        border = BorderStroke(1.dp, Color(0xFF8D7657))
                    ) {
                        Text("Mark safe", color = DemoAmber, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Text(
            "What the model saw",
            color = DemoText,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(top = 8.dp)
        )
        SignalRow("SIGNAL 1", "Connection frequency jumped above the app's baseline")
        SignalRow("SIGNAL 2", "Destination was rare for this app profile")
        SignalRow("SIGNAL 3", "Outbound byte volume changed quickly")

        Spacer(modifier = Modifier.weight(1f))
        MessagePanel(
            title = "Public message",
            body = "You do not need to read personal data to notice that an app's network behavior suddenly looks wrong."
        )
    }
}

@Composable
private fun PrivacyDemoPage() {
    Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = DemoCardStrong),
            border = BorderStroke(1.dp, Color(0xFF31534C))
        ) {
            Column(modifier = Modifier.padding(22.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.PrivacyTip,
                        contentDescription = null,
                        tint = DemoCyan,
                        modifier = Modifier.size(38.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("PRIVACY MODE", color = DemoCyan, fontWeight = FontWeight.Bold)
                }
                Text(
                    "Medium",
                    color = DemoText,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.headlineMedium,
                    modifier = Modifier.padding(top = 16.dp)
                )
                Text(
                    "Coarsen app and destination detail while keeping enough signal for useful anomaly detection.",
                    color = DemoMuted,
                    modifier = Modifier.padding(top = 10.dp)
                )
                LinearProgressIndicator(
                    progress = { 0.58f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(12.dp)
                        .padding(top = 24.dp),
                    color = DemoCyan,
                    trackColor = Color(0xFF243A34)
                )
            }
        }

        Text(
            "Exported to backend",
            color = DemoText,
            fontWeight = FontWeight.Bold,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(top = 8.dp)
        )
        StatusRow("Timing, counts, ratios", "Coarse behavior features", "YES", DemoCyan)
        StatusRow("Messages, passwords, photos", "Private content stays out", "NO", DemoRed)
        StatusRow("Exact app identifiers", "Reduced in stricter modes", "REDUCED", DemoAmber)

        Spacer(modifier = Modifier.weight(1f))
        Card(
            shape = RoundedCornerShape(28.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF241B1B)),
            border = BorderStroke(1.dp, DemoRed)
        ) {
            Column(modifier = Modifier.padding(22.dp)) {
                Text("Important limit", color = DemoText, fontWeight = FontWeight.Bold)
                Text(
                    "Even encrypted traffic leaks behavior to a passive network observer. Reducing exported metadata does not erase the original traffic pattern.",
                    color = DemoMuted,
                    modifier = Modifier.padding(top = 10.dp)
                )
            }
        }
        DemoButton("Use privacy-focused export")
    }
}

@Composable
private fun MetricTile(value: String, label: String, note: String, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = DemoCard)
    ) {
        Column(modifier = Modifier.padding(18.dp)) {
            Text(value, color = DemoCyan, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.headlineSmall)
            Text(label, color = DemoMuted, modifier = Modifier.padding(top = 6.dp))
            Text(note, color = DemoText, modifier = Modifier.padding(top = 12.dp))
        }
    }
}

@Composable
private fun StatusRow(title: String, body: String, status: String, color: Color) {
    Card(
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = DemoCard)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(title, color = DemoText, fontWeight = FontWeight.Bold)
                Text(body, color = DemoMuted, modifier = Modifier.padding(top = 4.dp))
            }
            Text(status, color = color, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun SignalRow(label: String, body: String) {
    Card(
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = DemoCard)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp)
        ) {
            Text(label, color = DemoCyan, fontWeight = FontWeight.Bold)
            Text(body, color = DemoMuted, modifier = Modifier.padding(top = 8.dp))
        }
    }
}

@Composable
private fun MessagePanel(title: String, body: String) {
    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF13241F)),
        border = BorderStroke(1.dp, Color(0xFF31534C))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(title, color = DemoText, fontWeight = FontWeight.Bold)
            Text(body, color = DemoMuted, modifier = Modifier.padding(top = 8.dp))
        }
    }
}

@Composable
private fun StatusIcon(icon: androidx.compose.ui.graphics.vector.ImageVector, color: Color) {
    Box(
        modifier = Modifier
            .size(72.dp)
            .background(color.copy(alpha = 0.18f), RoundedCornerShape(36.dp)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(46.dp)
        )
    }
}

@Composable
private fun DemoButton(text: String) {
    Button(
        onClick = {},
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp),
        colors = ButtonDefaults.buttonColors(containerColor = DemoCyan, contentColor = DemoBg)
    ) {
        Text(text, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
    }
}
