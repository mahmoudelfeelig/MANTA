param(
    [Alias("Input")]
    [string]$DatasetPath = ".\data\real\manta-real-training.csv",
    [string]$RunsRoot = ".\experiment-runs",
    [string]$CacheRoot = "",
    [double]$ModelThreshold = 0.5,
    [double]$IdsThreshold = 0.55,
    [int]$ParallelJobs = 2,
    [switch]$FastMode,
    [int]$MaxTotalWindows = 0,
    [int]$MaxBenignWindows = 0,
    [switch]$SkipEvaluationProtocol,
    [switch]$ResumeLatest,
    [string]$ResumeRunDir = ""
)

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
  throw "Expected Python virtual environment at $PythonExe"
}

$ResolvedDatasetPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $DatasetPath))
if (-not (Test-Path $ResolvedDatasetPath)) {
  throw "Input dataset not found: $ResolvedDatasetPath"
}

$ResolvedRunsRoot = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $RunsRoot))

$cmd = @(
  "-m", "ml_pipeline.train_all",
  "--input", $ResolvedDatasetPath,
  "--runs-root", $ResolvedRunsRoot,
  "--model-threshold", "$ModelThreshold",
  "--ids-threshold", "$IdsThreshold",
  "--parallel-jobs", "$ParallelJobs"
)
if ($CacheRoot -ne "") {
  $ResolvedCacheRoot = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $CacheRoot))
  $cmd += @("--cache-root", $ResolvedCacheRoot)
}
if ($FastMode) {
  $cmd += "--fast-mode"
}
if ($MaxTotalWindows -gt 0) {
  $cmd += @("--max-total-windows", "$MaxTotalWindows")
}
if ($MaxBenignWindows -gt 0) {
  $cmd += @("--max-benign-windows", "$MaxBenignWindows")
}
if ($SkipEvaluationProtocol) {
  $cmd += "--skip-evaluation-protocol"
}
if ($ResumeLatest) {
  $cmd += "--resume-latest"
}
if ($ResumeRunDir -ne "") {
  $ResolvedResumeRunDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $ResumeRunDir))
  $cmd += @("--resume-run-dir", $ResolvedResumeRunDir)
}

& $PythonExe @cmd
