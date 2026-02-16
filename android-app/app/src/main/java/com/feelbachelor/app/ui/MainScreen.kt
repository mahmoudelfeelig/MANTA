package com.feelbachelor.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.feelbachelor.app.core.model.AnomalyAlert
import com.feelbachelor.app.core.model.TriageStatus
import com.feelbachelor.app.core.settings.EndpointConfig

@Composable
fun MainScreen(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    statusMessage: String?,
    onSaveBackendUrl: (String) -> Unit,
    onSaveApiToken: (String) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onSaveThresholds: (Double, Double) -> Unit,
    onSyncPolicy: () -> Unit,
    onAcceptConsent: () -> Unit,
    onExportDataset: () -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onPurgeData: () -> Unit,
    onUpdateTriage: (String, TriageStatus) -> Unit
) {
    var backendUrl by remember(config.backendUrl) { mutableStateOf(config.backendUrl) }
    var apiToken by remember(config.apiToken) { mutableStateOf(config.apiToken) }
    var mediumThreshold by remember(config.mediumThreshold) { mutableStateOf(config.mediumThreshold.toString()) }
    var highThreshold by remember(config.highThreshold) { mutableStateOf(config.highThreshold.toString()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Feel Endpoint Prototype", style = MaterialTheme.typography.headlineSmall)
        Text("Policy version: ${config.policyVersion}")

        if (!config.consentAccepted) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("Consent required", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "This app captures metadata-only network flow information via Android VPNService. " +
                            "No packet payload is inspected. Export is optional and controlled by the toggle."
                    )
                    Button(onClick = onAcceptConsent) {
                        Text("I understand and consent")
                    }
                }
            }
        }

        OutlinedTextField(
            value = backendUrl,
            onValueChange = { backendUrl = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Backend Base URL (HTTPS)") }
        )
        Button(onClick = { onSaveBackendUrl(backendUrl) }) {
            Text("Save backend URL")
        }

        OutlinedTextField(
            value = apiToken,
            onValueChange = { apiToken = it },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(),
            label = { Text("API token") }
        )
        Button(onClick = { onSaveApiToken(apiToken) }) {
            Text("Save API token")
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text("Export to backend")
            Switch(checked = config.exportEnabled, onCheckedChange = onToggleExport)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = mediumThreshold,
                onValueChange = { mediumThreshold = it },
                label = { Text("Medium threshold") },
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = highThreshold,
                onValueChange = { highThreshold = it },
                label = { Text("High threshold") },
                modifier = Modifier.weight(1f)
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val medium = mediumThreshold.toDoubleOrNull() ?: config.mediumThreshold
                val high = highThreshold.toDoubleOrNull() ?: config.highThreshold
                onSaveThresholds(medium, high)
            }) {
                Text("Save thresholds")
            }
            Button(onClick = onSyncPolicy) {
                Text("Sync policy")
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = onStartCapture,
                enabled = config.consentAccepted
            ) { Text("Start capture") }
            Button(onClick = onStopCapture) { Text("Stop capture") }
            Button(onClick = onPurgeData) { Text("Purge local data") }
        }

        Button(onClick = onExportDataset) {
            Text("Export dataset snapshot")
        }

        if (!statusMessage.isNullOrBlank()) {
            Text(statusMessage, style = MaterialTheme.typography.bodySmall)
        }

        Spacer(Modifier.height(8.dp))
        Text("Recent alerts", style = MaterialTheme.typography.titleMedium)

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(alerts) { alert ->
                AlertCard(
                    alert = alert,
                    onUpdateTriage = { status -> onUpdateTriage(alert.id, status) }
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
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("App: ${alert.appId}", style = MaterialTheme.typography.titleSmall)
            Text("Severity: ${alert.severity}  Score: ${"%.3f".format(alert.anomalyScore)}")
            Text("Model: ${alert.sourceModel}")
            Text("Top features: ${alert.topFeatures.joinToString(", ")}")
            Text("Explanation: ${alert.explanation}")
            Text("Triage: ${alert.triageStatus}")
            Text("Timestamp: ${alert.createdAtMillis}")

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Button(onClick = { onUpdateTriage(TriageStatus.OPEN) }) { Text("Open") }
                Button(onClick = { onUpdateTriage(TriageStatus.INVESTIGATING) }) { Text("Investigating") }
                Button(onClick = { onUpdateTriage(TriageStatus.RESOLVED) }) { Text("Resolved") }
                Button(onClick = { onUpdateTriage(TriageStatus.FALSE_POSITIVE) }) { Text("False +") }
            }
        }
    }
}
