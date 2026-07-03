param(
    [string]$Base = "http://127.0.0.1:8080",
    [string]$Token = "",
    [string]$DeviceId = "abcd1234",
    [switch]$IncludeDeadLetter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Token)) {
    $Token = $env:ADAPTER_SHARED_TOKEN
}
if ([string]::IsNullOrWhiteSpace($Token)) {
    throw "Token missing. Pass -Token or set ADAPTER_SHARED_TOKEN."
}

$headers = @{
    Authorization = "Bearer $Token"
    "Content-Type" = "application/json"
}

[int]$pass = 0
[int]$fail = 0

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )

    if ($Condition) {
        $script:pass++
        Write-Host "PASS: $Message" -ForegroundColor Green
    } else {
        $script:fail++
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

function Invoke-Api {
    param(
        [ValidateSet("Get", "Post", "Put", "Patch")]
        [string]$Method,
        [string]$Path,
        [object]$Body
    )

    $url = "$Base$Path"
    if ($PSBoundParameters.ContainsKey("Body")) {
        $json = $Body | ConvertTo-Json -Depth 20
        return Invoke-RestMethod -Method $Method -Uri $url -Headers $headers -Body $json
    }
    return Invoke-RestMethod -Method $Method -Uri $url -Headers $headers
}

Write-Host "Running backend manual functional check against $Base" -ForegroundColor Cyan

# 1) Health
$health = Invoke-RestMethod -Method Get -Uri "$Base/health"
Assert-True ($health.status -eq "ok") "Health endpoint returns status=ok"
Assert-True ($null -ne $health.queue) "Health payload includes queue stats"

# Shared identifiers
$epoch = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$suffix = Get-Random -Minimum 10000 -Maximum 99999
$corrKey = "corr-key-$suffix"
$alertMainId = "alert-main-$suffix"
$alertCorrId = "alert-corr-$suffix"
$alertFpId = "alert-fp-$suffix"
$alertTpId = "alert-tp-$suffix"

# 2) Ingest mobile flow
$flow = @{
    event_type = "mobile_flow"
    event_version = "1.0"
    device_id_pseudo = $DeviceId
    app_id = "com.manual.test"
    protocol = "TCP"
    src_ip = "10.0.0.2"
    src_port = 44444
    dst_ip = "8.8.8.8"
    dst_port = 443
    dst_host_hash = "abcd1234"
    bytes_out = 100
    bytes_in = 200
    packets_out = 1
    packets_in = 1
    duration_ms = 100
    timestamp_start = $epoch
    timestamp_end = $epoch + 1
    netflow_version = 9
    ipfix_template_id = 256
    ipfix_elements = @(@{ id = 8; name = "sourceIPv4Address"; value = "10.0.0.2" })
}
$flowResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-flow" -Body $flow
Assert-True ($flowResp.status -eq "accepted") "mobile-flow ingest accepted"
Assert-True (-not [string]::IsNullOrWhiteSpace($flowResp.event_id)) "mobile-flow response contains event_id"

# 3) Ingest primary alert (OPEN)
$alertMain = @{
    event_type = "mobile_alert"
    event_version = "1.0"
    device_id_pseudo = $DeviceId
    alert_id = $alertMainId
    app_id = "com.manual.test"
    anomaly_score = 0.91
    severity = "HIGH"
    top_features = @("novelty", "burstiness")
    explanation = "Primary correlated alert"
    source_model = "statistical"
    correlation_key = $corrKey
    data_quality_warnings = @("zero_bytes_flow")
    triage_status = "OPEN"
    triage_note = ""
    timestamp = $epoch + 2
}
$alertMainResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-alert" -Body $alertMain
Assert-True ($alertMainResp.status -eq "accepted") "mobile-alert ingest accepted"

# 4) Alerts list + triage patch
$openAlerts = Invoke-Api -Method Get -Path "/api/v1/alerts?triage_status=OPEN&device_id_pseudo=$DeviceId&limit=200"
$hasMainOpen = $false
foreach ($a in $openAlerts.alerts) {
    if ($a.alert_id -eq $alertMainId) { $hasMainOpen = $true; break }
}
Assert-True $hasMainOpen "OPEN alerts include primary alert"

$triagePatch = @{ status = "INVESTIGATING"; note = "manual-check" }
$triageResp = Invoke-Api -Method Patch -Path "/api/v1/alerts/$alertMainId/triage" -Body $triagePatch
Assert-True ($triageResp.status -eq "ok") "triage patch accepted"
Assert-True ($triageResp.alert.triage_status -eq "INVESTIGATING") "triage status updated to INVESTIGATING"

# 5) Policy roundtrip
$policy = @{
    policy_version = 2
    default_thresholds = @{ medium = 0.55; high = 0.80 }
    app_threshold_overrides = @{ "com.manual.test" = @{ medium = 0.50; high = 0.75 } }
    export_enabled = $true
    retention_days = 14
    detection_model = "ensemble_fusion"
    shadow_model = "local"
    false_positive_budget_per_app_day = 12
    drift_high_threshold = 0.65
}
$setPolicy = Invoke-Api -Method Put -Path "/api/v1/policy/device/$DeviceId" -Body $policy
$getPolicy = Invoke-Api -Method Get -Path "/api/v1/policy/device/$DeviceId"
Assert-True ($setPolicy.status -eq "ok") "policy PUT returns ok"
Assert-True ($getPolicy.policy.policy_version -eq 2) "policy GET returns policy_version=2"

# 6) Add second correlated alert and verify incidents/quality/forensics
$alertCorr = @{
    event_type = "mobile_alert"
    event_version = "1.0"
    device_id_pseudo = $DeviceId
    alert_id = $alertCorrId
    app_id = "com.manual.test"
    anomaly_score = 0.72
    severity = "MEDIUM"
    top_features = @("burstiness")
    explanation = "Secondary correlated alert"
    source_model = "local"
    correlation_key = $corrKey
    data_quality_warnings = @("zero_bytes_flow")
    triage_status = "OPEN"
    triage_note = ""
    timestamp = $epoch + 3
}
$alertCorrResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-alert" -Body $alertCorr
Assert-True ($alertCorrResp.status -eq "accepted") "second correlated alert accepted"

$incidents = Invoke-Api -Method Get -Path "/api/v1/incidents?device_id_pseudo=$DeviceId&limit=200"
$incidentFound = $false
foreach ($i in $incidents.incidents) {
    if ($i.correlation_key -eq $corrKey) { $incidentFound = $true; break }
}
Assert-True $incidentFound "incidents include correlation key"

$quality = Invoke-Api -Method Get -Path "/api/v1/quality/summary?device_id_pseudo=$DeviceId"
$warningCount = 0
if ($null -ne $quality.quality.warning_counts.zero_bytes_flow) {
    $warningCount = [int]$quality.quality.warning_counts.zero_bytes_flow
}
Assert-True ($quality.status -eq "ok") "quality summary returns ok"
Assert-True ($warningCount -ge 1) "quality summary counts zero_bytes_flow warnings"

$bundle = Invoke-Api -Method Get -Path "/api/v1/forensics/device/$DeviceId/bundle?limit=200"
Assert-True ($bundle.status -eq "ok") "forensics bundle returns ok"
Assert-True (($bundle.alerts | Measure-Object).Count -ge 2) "forensics bundle includes alerts"
Assert-True (($bundle.incidents | Measure-Object).Count -ge 1) "forensics bundle includes incidents"

# 7) Add feedback alerts and verify auto-tune/simulate/retraining
$alertFp = @{
    event_type = "mobile_alert"
    event_version = "1.0"
    device_id_pseudo = $DeviceId
    alert_id = $alertFpId
    app_id = "com.manual.test"
    anomaly_score = 0.71
    severity = "MEDIUM"
    top_features = @("novelty")
    explanation = "noise"
    source_model = "ensemble_fusion"
    triage_status = "FALSE_POSITIVE"
    triage_note = "noise"
    timestamp = $epoch + 4
}
$alertTp = @{
    event_type = "mobile_alert"
    event_version = "1.0"
    device_id_pseudo = $DeviceId
    alert_id = $alertTpId
    app_id = "com.manual.test"
    anomaly_score = 0.92
    severity = "HIGH"
    top_features = @("burstiness")
    explanation = "confirmed"
    source_model = "local"
    triage_status = "RESOLVED"
    triage_note = "confirmed"
    timestamp = $epoch + 5
}
$fpResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-alert" -Body $alertFp
$tpResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-alert" -Body $alertTp
Assert-True ($fpResp.status -eq "accepted" -and $tpResp.status -eq "accepted") "feedback alerts accepted"

$autoTune = Invoke-Api -Method Post -Path "/api/v1/policy/device/$DeviceId/auto-tune"
Assert-True ($autoTune.status -eq "ok") "auto-tune returns ok"
Assert-True ($autoTune.policy.policy_version -ge 3) "auto-tune increments policy version"

$simReq = @{
    policy = @{
        policy_version = 1
        default_thresholds = @{ medium = 0.55; high = 0.85 }
        app_threshold_overrides = @{}
        export_enabled = $true
        retention_days = 7
        detection_model = "ensemble_fusion"
        shadow_model = $null
        false_positive_budget_per_app_day = 12
        drift_high_threshold = 0.65
    }
    limit = 500
}
$simulation = Invoke-Api -Method Post -Path "/api/v1/policy/simulate/$DeviceId" -Body $simReq
Assert-True ($simulation.status -eq "ok") "policy simulation returns ok"
Assert-True ($null -ne $simulation.simulation.severity_distribution) "policy simulation includes severity_distribution"

$samples = Invoke-Api -Method Get -Path "/api/v1/retraining/samples/${DeviceId}?limit=500"
Assert-True ($samples.status -eq "ok") "retraining samples endpoint returns ok"
Assert-True (($samples.samples | Measure-Object).Count -ge 1) "retraining samples are non-empty"

# 8) Optional dead-letter test
if ($IncludeDeadLetter) {
    Write-Host "Running dead-letter check (requires backend started with failing WAZUH_INGEST_URL and low retry timings)..." -ForegroundColor Yellow

    $flowDl = $flow.Clone()
    $flowDl.timestamp_start = $epoch + 6
    $flowDl.timestamp_end = $epoch + 7
    $flowDl.dst_host_hash = "deadletter01"

    $dlResp = Invoke-Api -Method Post -Path "/api/v1/events/mobile-flow" -Body $flowDl
    Assert-True ($dlResp.status -eq "accepted") "dead-letter test event accepted"

    $r1 = Invoke-Api -Method Post -Path "/api/v1/events/retry?limit=100"
    Start-Sleep -Milliseconds 1200
    $r2 = Invoke-Api -Method Post -Path "/api/v1/events/retry?limit=100"
    Start-Sleep -Milliseconds 2200
    $r3 = Invoke-Api -Method Post -Path "/api/v1/events/retry?limit=100"

    $dead = Invoke-Api -Method Get -Path "/api/v1/queue/dead-letter?limit=200"
    Assert-True (($dead.dead_letter | Measure-Object).Count -ge 1) "dead-letter queue has entries"

    $replay = Invoke-Api -Method Post -Path "/api/v1/queue/dead-letter/replay?limit=10"
    Assert-True ($replay.replayed -ge 1) "dead-letter replay moved at least one item"
}

Write-Host ""
Write-Host "Summary: PASS=$pass FAIL=$fail" -ForegroundColor Cyan
if ($fail -gt 0) {
    exit 1
}
exit 0
