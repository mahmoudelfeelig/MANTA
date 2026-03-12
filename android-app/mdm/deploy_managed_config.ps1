param(
  [string]$BackendUrl = "https://manta.example.com",
  [string]$ApiToken = "REPLACE_WITH_TOKEN",
  [string]$PrivacyMode = "MEDIUM",
  [string]$DetectionModel = "ensemble_fusion"
)

$config = @{
  backend_url = $BackendUrl
  api_token = $ApiToken
  export_enabled = $true
  capture_enabled = $true
  privacy_mode = $PrivacyMode
  theme_mode = "SYSTEM"
  detection_model = $DetectionModel
  shadow_model = ""
  custom_include_app_id = $false
  custom_include_site_hint = $false
  custom_include_ip_addresses = $false
  custom_include_exact_ports = $true
  custom_include_device_label = $false
  custom_include_explanations = $true
  custom_include_feature_window = $true
}

$output = Join-Path $PSScriptRoot "managed-configurations.generated.json"
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $output -Encoding UTF8
Write-Host "Wrote managed configuration bundle to $output"
Write-Host "Import this JSON into your Android Enterprise / EMM managed app configuration."
