package com.manta.app.core.settings

import android.content.Context
import android.content.RestrictionsManager

class ManagedConfigApplier(
    private val context: Context,
    private val settingsStore: SecureSettingsStore,
) {
    fun applyIfPresent() {
        val manager = context.getSystemService(Context.RESTRICTIONS_SERVICE) as? RestrictionsManager ?: return
        val restrictions = manager.applicationRestrictions ?: return
        if (restrictions.isEmpty) {
            return
        }

        restrictions.getString("backend_url")?.let(settingsStore::setBackendUrl)
        restrictions.getString("api_token")?.let(settingsStore::setApiToken)
        if (restrictions.containsKey("export_enabled")) {
            settingsStore.setExportEnabled(restrictions.getBoolean("export_enabled"))
        }
        if (restrictions.containsKey("capture_enabled")) {
            settingsStore.setCaptureEnabled(restrictions.getBoolean("capture_enabled"))
        }
        restrictions.getString("privacy_mode")?.let { raw ->
            runCatching { PrivacyMode.valueOf(raw.trim().uppercase()) }.getOrNull()?.let(settingsStore::setPrivacyMode)
        }
        restrictions.getString("theme_mode")?.let { raw ->
            runCatching { ThemeMode.valueOf(raw.trim().uppercase()) }.getOrNull()?.let(settingsStore::setThemeMode)
        }
        restrictions.getString("detection_model")?.let(settingsStore::setDetectionModel)
        if (restrictions.containsKey("shadow_model")) {
            settingsStore.setShadowModel(restrictions.getString("shadow_model"))
        }
        if (restrictions.containsKey("custom_include_app_id") ||
            restrictions.containsKey("custom_include_site_hint") ||
            restrictions.containsKey("custom_include_ip_addresses") ||
            restrictions.containsKey("custom_include_exact_ports") ||
            restrictions.containsKey("custom_include_device_label") ||
            restrictions.containsKey("custom_include_explanations") ||
            restrictions.containsKey("custom_include_feature_window")
        ) {
            val current = settingsStore.readConfig().customPrivacy
            settingsStore.setCustomPrivacyOptions(
                current.copy(
                    includeAppId = restrictions.getBoolean("custom_include_app_id", current.includeAppId),
                    includeSiteHint = restrictions.getBoolean("custom_include_site_hint", current.includeSiteHint),
                    includeIpAddresses = restrictions.getBoolean("custom_include_ip_addresses", current.includeIpAddresses),
                    includeExactPorts = restrictions.getBoolean("custom_include_exact_ports", current.includeExactPorts),
                    includeDeviceLabel = restrictions.getBoolean("custom_include_device_label", current.includeDeviceLabel),
                    includeExplanations = restrictions.getBoolean("custom_include_explanations", current.includeExplanations),
                    includeFeatureWindow = restrictions.getBoolean("custom_include_feature_window", current.includeFeatureWindow),
                )
            )
        }
        settingsStore.setConsentAccepted(true)
    }
}
