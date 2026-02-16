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
import com.feelbachelor.app.core.settings.EndpointConfig

@Composable
fun MainScreen(
    config: EndpointConfig,
    alerts: List<AnomalyAlert>,
    onSaveBackendUrl: (String) -> Unit,
    onSaveApiToken: (String) -> Unit,
    onToggleExport: (Boolean) -> Unit,
    onStartCapture: () -> Unit,
    onStopCapture: () -> Unit,
    onPurgeData: () -> Unit
) {
    var backendUrl by remember(config.backendUrl) { mutableStateOf(config.backendUrl) }
    var apiToken by remember(config.apiToken) { mutableStateOf(config.apiToken) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Feel Endpoint Prototype", style = MaterialTheme.typography.headlineSmall)

        OutlinedTextField(
            value = backendUrl,
            onValueChange = { backendUrl = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Backend URL (HTTPS)") }
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
            Button(onClick = onStartCapture) { Text("Start capture") }
            Button(onClick = onStopCapture) { Text("Stop capture") }
            Button(onClick = onPurgeData) { Text("Purge local data") }
        }

        Spacer(Modifier.height(8.dp))
        Text("Recent alerts", style = MaterialTheme.typography.titleMedium)

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(alerts) { alert ->
                AlertCard(alert)
            }
        }
    }
}

@Composable
private fun AlertCard(alert: AnomalyAlert) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("App: ${alert.appId}", style = MaterialTheme.typography.titleSmall)
            Text("Severity: ${alert.severity}  Score: ${"%.3f".format(alert.anomalyScore)}")
            Text("Top features: ${alert.topFeatures.joinToString(", ")}")
            Text("Timestamp: ${alert.createdAtMillis}")
        }
    }
}
