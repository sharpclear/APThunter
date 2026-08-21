<#
.SYNOPSIS
Runs the weekly Qianxin incremental PDF pipeline with durable per-SHA recovery.

.DESCRIPTION
Replays unfinished manifests, downloads incrementally, processes only PDFs created by
the current downloader run, refreshes the two full-corpus parsing batch summaries, and
    reuses the API-managed local model server for all ready SHA values. Normal runs hold an exclusive
cross-process file lock. DryRun is read-only and invokes no Python, browser, MinerU, or
model process.

.PARAMETER DryRun
Validate paths, manifests, SHA-prefix routing, and the llama port without changing state.

.NOTES
Exit 0 means no technical failure (including the no-new-PDF case), exit 1 means a stage
failed and its manifest retains retryable SHA values, and exit 20 means another wrapper
instance owns the lock. Manual-review results are quarantined in the manifest rather than
retried forever.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [string]$InvocationId,
    [string]$StartDate = '2026-04-01',
    [string]$EndDate = 'today',
    [ValidateRange(1000, 3600000)]
    [int]$PageTimeoutMs = 120000,
    [ValidateRange(1000, 3600000)]
    [int]$DownloadTimeoutMs = 180000,
    [ValidateRange(1, 86400)]
    [int]$SummaryRequestTimeoutSeconds = 1800,
    [string]$ModelManagerUrl = 'http://127.0.0.1:8787',
    [ValidateRange(1, 900)]
    [int]$ModelManagerTimeoutSeconds = 240,
    [ValidateRange(1024, 65535)]
    [int]$LlamaPort = 8091
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:ReportsRoot = Join-Path $script:ProjectRoot 'data\reports'
$script:MetadataPath = Join-Path $script:ProjectRoot 'data\metadata\qianxin-reports.jsonl'
$script:RunStateRoot = Join-Path $script:ProjectRoot 'data\state\weekly-incremental-runs'
$script:LockPath = Join-Path $script:ProjectRoot 'data\state\qianxin-weekly-incremental.lock'
$script:LogRoot = Join-Path $script:ProjectRoot 'logs'
$script:LogPath = $null
$script:PythonExe = Join-Path $script:ProjectRoot '.venv\Scripts\python.exe'
$script:DownloadScript = Join-Path $script:ProjectRoot 'scripts\qianxin\download_historical_reports.py'
$script:ParseScript = Join-Path $script:ProjectRoot 'scripts\qianxin\parse_reports.py'
$script:EnrichScript = Join-Path $script:ProjectRoot 'scripts\qianxin\enrich_reports.py'
$script:SummarizeScript = Join-Path $script:ProjectRoot 'scripts\qianxin\summarize_reports.py'
$script:MinerUExe = Join-Path $script:ProjectRoot '.venv-mineru\Scripts\mineru.exe'
$script:LlamaServerExe = Join-Path $script:ProjectRoot 'tools\llama.cpp\b10278\llama-server.exe'
$script:DefaultModel = Join-Path $script:ProjectRoot 'data\models\llm\Qwen3-4B-Q4_K_M.gguf'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Write-RunLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-UtcTimestamp), $Level, $Message
    Write-Host $line
    if ($null -ne $script:LogPath) {
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    }
}

function Set-ObjectProperty {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Value
    )
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}

function New-StageState {
    return [pscustomobject][ordered]@{
        status           = 'pending'
        attempts         = 0
        started_at       = $null
        completed_at     = $null
        duration_seconds = $null
        exit_code        = $null
        error            = $null
        quality_status   = $null
    }
}

function Ensure-StageState {
    param([Parameter(Mandatory = $true)]$Stage)
    $defaults = [ordered]@{
        status           = 'pending'
        attempts         = 0
        started_at       = $null
        completed_at     = $null
        duration_seconds = $null
        exit_code        = $null
        error            = $null
        quality_status   = $null
    }
    foreach ($name in $defaults.Keys) {
        if ($null -eq $Stage.PSObject.Properties[$name]) {
            Set-ObjectProperty $Stage $name $defaults[$name]
        }
    }
    return $Stage
}

function New-WorkItem {
    param(
        [Parameter(Mandatory = $true)][string]$PdfPath,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Organization
    )

    return [pscustomobject][ordered]@{
        sha256         = $Sha256.ToLowerInvariant()
        sha8           = $Sha256.Substring(0, 8).ToLowerInvariant()
        pdf_path       = $PdfPath
        organization   = $Organization
        status         = 'pending'
        review_required = $false
        metadata_matched = $false
        technical_failures = 0
        quarantined_at = $null
        error_kind     = $null
        error          = $null
        parse          = New-StageState
        enrich         = New-StageState
        summary        = New-StageState
    }
}

function Normalize-WorkItem {
    param([Parameter(Mandatory = $true)]$Item)

    $required = @('sha256', 'sha8', 'pdf_path', 'organization')
    foreach ($name in $required) {
        if ($null -eq $Item.PSObject.Properties[$name] -or [string]::IsNullOrWhiteSpace([string]$Item.$name)) {
            throw "Run manifest item is missing '$name'."
        }
    }
    if ([string]$Item.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
        throw "Run manifest contains an invalid SHA-256: $($Item.sha256)"
    }
    if ([string]$Item.sha8 -ne ([string]$Item.sha256).Substring(0, 8)) {
        throw "Run manifest SHA prefix does not match SHA-256: $($Item.sha256)"
    }

    if ($null -eq $Item.PSObject.Properties['status']) {
        Set-ObjectProperty $Item 'status' 'pending'
    }
    if ($null -eq $Item.PSObject.Properties['review_required']) {
        Set-ObjectProperty $Item 'review_required' $false
    }
    if ($null -eq $Item.PSObject.Properties['metadata_matched']) {
        Set-ObjectProperty $Item 'metadata_matched' $false
    }
    if ($null -eq $Item.PSObject.Properties['technical_failures']) {
        Set-ObjectProperty $Item 'technical_failures' 0
    }
    if ($null -eq $Item.PSObject.Properties['quarantined_at']) {
        Set-ObjectProperty $Item 'quarantined_at' $null
    }
    if ($null -eq $Item.PSObject.Properties['error_kind']) {
        Set-ObjectProperty $Item 'error_kind' $null
    }
    if ($null -eq $Item.PSObject.Properties['error']) {
        Set-ObjectProperty $Item 'error' $null
    }
    foreach ($stageName in @('parse', 'enrich', 'summary')) {
        if ($null -eq $Item.PSObject.Properties[$stageName] -or $null -eq $Item.$stageName) {
            Set-ObjectProperty $Item $stageName (New-StageState)
        }
        [void](Ensure-StageState $Item.$stageName)
    }
    return $Item
}

function Normalize-Manifest {
    param([Parameter(Mandatory = $true)]$Manifest)

    if ($null -eq $Manifest.PSObject.Properties['schema_version']) {
        Set-ObjectProperty $Manifest 'schema_version' 1
    }
    if ([int]$Manifest.schema_version -ne 1) {
        throw "Unsupported weekly manifest schema version: $($Manifest.schema_version)"
    }
    foreach ($name in @('run_id', 'created_at', 'updated_at', 'status')) {
        if ($null -eq $Manifest.PSObject.Properties[$name]) {
            Set-ObjectProperty $Manifest $name $null
        }
    }
    if ($null -eq $Manifest.PSObject.Properties['started_at']) {
        Set-ObjectProperty $Manifest 'started_at' $Manifest.created_at
    }
    if ($null -eq $Manifest.PSObject.Properties['completed_at']) {
        Set-ObjectProperty $Manifest 'completed_at' $null
    }
    if ($null -eq $Manifest.PSObject.Properties['fatal_error']) {
        Set-ObjectProperty $Manifest 'fatal_error' $null
    }
    if ($null -eq $Manifest.PSObject.Properties['download'] -or $null -eq $Manifest.download) {
        Set-ObjectProperty $Manifest 'download' (New-StageState)
    }
    [void](Ensure-StageState $Manifest.download)
    if ($null -eq $Manifest.download.PSObject.Properties['metadata_start_line']) {
        Set-ObjectProperty $Manifest.download 'metadata_start_line' 0
    }
    $downloadDefaults = [ordered]@{
        metadata_end_line    = $null
        baseline_pdf_count   = $null
        baseline_fingerprint = $null
        baseline_sha256      = @()
        result_pdf_count     = $null
        result_fingerprint   = $null
        result_sha256        = @()
        new_sha256           = @()
    }
    foreach ($name in $downloadDefaults.Keys) {
        if ($null -eq $Manifest.download.PSObject.Properties[$name]) {
            Set-ObjectProperty $Manifest.download $name $downloadDefaults[$name]
        }
    }
    if ($null -eq $Manifest.PSObject.Properties['batch_refresh'] -or $null -eq $Manifest.batch_refresh) {
        Set-ObjectProperty $Manifest 'batch_refresh' ([pscustomobject][ordered]@{
            parse  = New-StageState
            enrich = New-StageState
        })
    }
    foreach ($stageName in @('parse', 'enrich')) {
        if ($null -eq $Manifest.batch_refresh.PSObject.Properties[$stageName] -or
            $null -eq $Manifest.batch_refresh.$stageName) {
            Set-ObjectProperty $Manifest.batch_refresh $stageName (New-StageState)
        }
        [void](Ensure-StageState $Manifest.batch_refresh.$stageName)
    }
    if ($null -eq $Manifest.PSObject.Properties['items'] -or $null -eq $Manifest.items) {
        Set-ObjectProperty $Manifest 'items' @()
    }
    $normalizedItems = @()
    foreach ($item in @($Manifest.items)) {
        $normalizedItems += Normalize-WorkItem $item
    }
    Set-ObjectProperty $Manifest 'items' $normalizedItems
    if ($null -eq $Manifest.PSObject.Properties['pending_sha256']) {
        Set-ObjectProperty $Manifest 'pending_sha256' @()
    }
    if ($null -eq $Manifest.PSObject.Properties['review_sha256']) {
        Set-ObjectProperty $Manifest 'review_sha256' @()
    }
    if ($null -eq $Manifest.PSObject.Properties['recovery_sha256']) {
        Set-ObjectProperty $Manifest 'recovery_sha256' @()
    }
    if ($null -eq $Manifest.PSObject.Properties['recovery_items']) {
        Set-ObjectProperty $Manifest 'recovery_items' @()
    }
    if ($null -eq $Manifest.PSObject.Properties['errors']) {
        Set-ObjectProperty $Manifest 'errors' @()
    }
    return $Manifest
}

function Update-ManifestRollup {
    param([Parameter(Mandatory = $true)]$Manifest)

    $pending = @(
        @($Manifest.items) |
            Where-Object { $_.status -notin @('completed', 'completed_with_review', 'manual_review') } |
            ForEach-Object { $_.sha256 }
    )
    $reviews = @(
        @($Manifest.items) |
            Where-Object { $_.status -in @('completed_with_review', 'manual_review') } |
            ForEach-Object { $_.sha256 }
    )
    Set-ObjectProperty $Manifest 'pending_sha256' @($pending | Sort-Object -Unique)
    Set-ObjectProperty $Manifest 'review_sha256' @($reviews | Sort-Object -Unique)
    Set-ObjectProperty $Manifest 'updated_at' (Get-UtcTimestamp)

    $hasFailedItem = @($Manifest.items | Where-Object { $_.status -eq 'failed' }).Count -gt 0
    $hasRunningItem = @(
        $Manifest.items | Where-Object { $_.status -in @('parsing', 'enriching', 'summarizing') }
    ).Count -gt 0
    $hasFailedBatch = @(
        @($Manifest.batch_refresh.parse, $Manifest.batch_refresh.enrich) |
            Where-Object { $_.status -eq 'failed' }
    ).Count -gt 0
    $hasRunningBatch = @(
        @($Manifest.batch_refresh.parse, $Manifest.batch_refresh.enrich) |
            Where-Object { $_.status -eq 'running' }
    ).Count -gt 0
    $newStatus = 'completed'
    if ($Manifest.download.status -in @('pending', 'running')) {
        $newStatus = 'running'
    }
    elseif ($hasRunningItem -or $hasRunningBatch) {
        $newStatus = 'running'
    }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Manifest.fatal_error) -or
        $hasFailedBatch -or $pending.Count -gt 0 -or $hasFailedItem) {
        $newStatus = 'failed'
    }
    elseif ($Manifest.download.status -eq 'failed') {
        $newStatus = 'failed'
    }
    elseif ($reviews.Count -gt 0) {
        $newStatus = 'completed_with_review'
    }
    Set-ObjectProperty $Manifest 'status' $newStatus
    if ($newStatus -eq 'running') {
        Set-ObjectProperty $Manifest 'completed_at' $null
    }
    elseif ($null -eq $Manifest.completed_at) {
        Set-ObjectProperty $Manifest 'completed_at' (Get-UtcTimestamp)
    }
}

function Save-Manifest {
    param([Parameter(Mandatory = $true)]$Context)

    Update-ManifestRollup $Context.Data
    $json = $Context.Data | ConvertTo-Json -Depth 20
    $temporaryPath = '{0}.tmp.{1}' -f $Context.Path, $PID
    [System.IO.File]::WriteAllText($temporaryPath, $json + [Environment]::NewLine, $script:Utf8NoBom)
    if (Test-Path -LiteralPath $Context.Path) {
        # Windows PowerShell 5.1 can reject a null backup path even though the
        # underlying .NET signature documents it as optional.  A sibling backup
        # also keeps replacement atomic on the same volume.  It is removed only
        # after the new manifest has replaced the old one successfully.
        $backupPath = '{0}.bak.{1}' -f $Context.Path, $PID
        try {
            [System.IO.File]::Replace($temporaryPath, $Context.Path, $backupPath)
            if (Test-Path -LiteralPath $backupPath) {
                Remove-Item -LiteralPath $backupPath -Force
            }
        }
        finally {
            if (Test-Path -LiteralPath $temporaryPath) {
                Remove-Item -LiteralPath $temporaryPath -Force
            }
        }
    }
    else {
        [System.IO.File]::Move($temporaryPath, $Context.Path)
    }
}

function Load-ManifestContexts {
    param([switch]$ReadOnly)
    $contexts = @()
    if (-not (Test-Path -LiteralPath $script:RunStateRoot -PathType Container)) {
        return $contexts
    }
    foreach ($path in Get-ChildItem -LiteralPath $script:RunStateRoot -Filter '*.json' -File | Sort-Object Name) {
        try {
            $data = Get-Content -LiteralPath $path.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            [void](Normalize-Manifest $data)
            $contexts += [pscustomobject]@{ Path = $path.FullName; Data = $data }
        }
        catch {
            $message = "Invalid weekly run manifest '$($path.FullName)': $($_.Exception.Message)"
            if ($ReadOnly) {
                Write-RunLog "$message A real run would quarantine it." 'WARN'
                continue
            }
            try {
                $quarantineRoot = Join-Path $script:RunStateRoot 'quarantine'
                [void](New-Item -ItemType Directory -Path $quarantineRoot -Force)
                $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
                $destination = Join-Path $quarantineRoot ($path.Name + ".bad.$stamp")
                Move-Item -LiteralPath $path.FullName -Destination $destination
                [System.IO.File]::WriteAllText(
                    $destination + '.error.txt',
                    $message + [Environment]::NewLine,
                    $script:Utf8NoBom
                )
                Write-RunLog "$message Quarantined as '$destination'." 'WARN'
            }
            catch {
                Write-RunLog "$message Quarantine move also failed: $($_.Exception.Message)" 'ERROR'
            }
        }
    }
    return $contexts
}

function New-ManifestContext {
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][int]$MetadataStartLine,
        [Parameter(Mandatory = $true)]$BaselineInventory
    )

    $download = New-StageState
    Set-ObjectProperty $download 'metadata_start_line' $MetadataStartLine
    Set-ObjectProperty $download 'metadata_end_line' $null
    Set-ObjectProperty $download 'baseline_pdf_count' ([int]$BaselineInventory.Count)
    Set-ObjectProperty $download 'baseline_fingerprint' ([string]$BaselineInventory.Fingerprint)
    Set-ObjectProperty $download 'baseline_sha256' @($BaselineInventory.Sha256)
    Set-ObjectProperty $download 'result_pdf_count' $null
    Set-ObjectProperty $download 'result_fingerprint' $null
    Set-ObjectProperty $download 'result_sha256' @()
    Set-ObjectProperty $download 'new_sha256' @()
    $now = Get-UtcTimestamp
    $manifest = [pscustomobject][ordered]@{
        schema_version = 1
        run_id          = $RunId
        created_at      = $now
        started_at      = $now
        completed_at    = $null
        updated_at      = $now
        status          = 'running'
        fatal_error     = $null
        download        = $download
        batch_refresh   = [pscustomobject][ordered]@{
            parse  = New-StageState
            enrich = New-StageState
        }
        items           = @()
        pending_sha256  = @()
        review_sha256   = @()
        recovery_sha256 = @()
        recovery_items  = @()
        errors          = @()
    }
    return [pscustomobject]@{
        Path = Join-Path $script:RunStateRoot ($RunId + '.json')
        Data = $manifest
    }
}

function Add-ManifestError {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $entry = [pscustomobject][ordered]@{
        at      = Get-UtcTimestamp
        message = $Message
    }
    Set-ObjectProperty $Context.Data 'errors' (@($Context.Data.errors) + $entry)
}

function Register-TechnicalFailure {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$Item,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $failureCount = [int]$Item.technical_failures + 1
    Set-ObjectProperty $Item 'technical_failures' $failureCount
    Set-ObjectProperty $Item 'error_kind' 'technical'
    Set-ObjectProperty $Item 'error' $Message
    if ($failureCount -ge 3) {
        Set-ObjectProperty $Item 'status' 'manual_review'
        Set-ObjectProperty $Item 'review_required' $true
        Set-ObjectProperty $Item 'quarantined_at' (Get-UtcTimestamp)
        $Message = "$Message Automatically quarantined after $failureCount technical failures."
        Set-ObjectProperty $Item 'error' $Message
        Write-RunLog "$($Item.sha8) was quarantined after $failureCount technical failures." 'WARN'
    }
    else {
        Set-ObjectProperty $Item 'status' 'failed'
    }
    Add-ManifestError $Context $Message
}

function Start-Stage {
    param([Parameter(Mandatory = $true)]$Stage)
    Set-ObjectProperty $Stage 'status' 'running'
    Set-ObjectProperty $Stage 'attempts' ([int]$Stage.attempts + 1)
    Set-ObjectProperty $Stage 'started_at' (Get-UtcTimestamp)
    Set-ObjectProperty $Stage 'completed_at' $null
    Set-ObjectProperty $Stage 'duration_seconds' $null
    Set-ObjectProperty $Stage 'exit_code' $null
    Set-ObjectProperty $Stage 'error' $null
}

function Complete-Stage {
    param(
        [Parameter(Mandatory = $true)]$Stage,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][double]$DurationSeconds,
        [string]$ErrorMessage,
        [string]$QualityStatus
    )
    Set-ObjectProperty $Stage 'status' $Status
    Set-ObjectProperty $Stage 'completed_at' (Get-UtcTimestamp)
    Set-ObjectProperty $Stage 'duration_seconds' ([math]::Round($DurationSeconds, 3))
    Set-ObjectProperty $Stage 'exit_code' $ExitCode
    Set-ObjectProperty $Stage 'error' $ErrorMessage
    if ($PSBoundParameters.ContainsKey('QualityStatus')) {
        Set-ObjectProperty $Stage 'quality_status' $QualityStatus
    }
}

function Format-NativeCommand {
    param([string]$Executable, [string[]]$Arguments)
    $parts = @('"' + $Executable + '"')
    foreach ($argument in $Arguments) {
        if ($argument -match '[\s"]') {
            $parts += '"' + ($argument -replace '"', '\"') + '"'
        }
        else {
            $parts += $argument
        }
    }
    return ($parts -join ' ')
}

function Invoke-NativeLogged {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Write-RunLog "$Label command: $(Format-NativeCommand $Executable $Arguments)"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $exitCode = 9001
    $errorMessage = $null
    $previousErrorPreference = $ErrorActionPreference
    try {
        # Windows PowerShell promotes redirected native stderr to ErrorRecord.
        # Keep it as log output so the real process exit code remains authoritative.
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object {
            Write-RunLog ("{0}: {1}" -f $Label, [string]$_)
        }
        $exitCode = $LASTEXITCODE
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-RunLog "$Label could not be started: $errorMessage" 'ERROR'
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
        $stopwatch.Stop()
    }
    return [pscustomobject]@{
        ExitCode        = [int]$exitCode
        DurationSeconds = [double]$stopwatch.Elapsed.TotalSeconds
        Error           = $errorMessage
    }
}

function Test-PortInUse {
    param([Parameter(Mandatory = $true)][int]$Port)
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return @($listeners | Where-Object { $_.Port -eq $Port }).Count -gt 0
}

function Request-SharedModelReady {
    if ([string]::IsNullOrWhiteSpace($ModelManagerUrl)) {
        return $false
    }
    $apiKey = [Environment]::GetEnvironmentVariable('QIANXIN_API_KEY', 'Process')
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        $apiKey = [Environment]::GetEnvironmentVariable('QIANXIN_API_KEY', 'User')
    }
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-RunLog 'Shared model manager key is unavailable; using the bounded legacy model lifecycle.' 'WARN'
        return $false
    }
    $uri = $ModelManagerUrl.TrimEnd('/') + '/api/v1/model/ensure'
    try {
        $response = Invoke-RestMethod `
            -Method Post `
            -Uri $uri `
            -Headers @{ 'X-API-Key' = $apiKey } `
            -TimeoutSec $ModelManagerTimeoutSeconds
        if ($response.running -eq $true -and $response.owned_by_api -eq $true) {
            Write-RunLog 'Reusing the API-managed Qwen3-4B llama-server.'
            return $true
        }
        Write-RunLog 'Shared model manager returned an unexpected readiness response.' 'WARN'
    }
    catch {
        Write-RunLog "Shared model manager is unavailable ($($_.Exception.GetType().Name)); using the bounded legacy model lifecycle." 'WARN'
    }
    return $false
}

function Get-TextSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $script:Utf8NoBom.GetBytes($Text)
        $digest = $hasher.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-PdfInventory {
    $bySha = @{}
    $byPrefix = @{}
    foreach ($pdf in Get-ChildItem -LiteralPath $script:ReportsRoot -Recurse -Filter '*.pdf' -File) {
        $fullPath = [System.IO.Path]::GetFullPath($pdf.FullName)
        $sha = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $sha8 = $sha.Substring(0, 8)
        if ($byPrefix.ContainsKey($sha8) -and $byPrefix[$sha8] -ne $sha) {
            throw "Global SHA8 collision: '$sha8' maps to both $($byPrefix[$sha8]) and $sha. No parse was started."
        }
        $byPrefix[$sha8] = $sha
        if (-not $bySha.ContainsKey($sha)) {
            $bySha[$sha] = [pscustomobject][ordered]@{
                sha256       = $sha
                sha8         = $sha8
                paths        = @()
                organizations = @()
            }
        }
        $entry = $bySha[$sha]
        Set-ObjectProperty $entry 'paths' (@($entry.paths) + $fullPath | Sort-Object -Unique)
        $organization = Split-Path (Split-Path $fullPath -Parent) -Leaf
        Set-ObjectProperty $entry 'organizations' (@($entry.organizations) + $organization | Sort-Object -Unique)
    }
    $shaValues = @($bySha.Keys | Sort-Object)
    return [pscustomobject]@{
        BySha       = $bySha
        Sha256      = $shaValues
        Count       = $shaValues.Count
        Fingerprint = Get-TextSha256 ($shaValues -join "`n")
    }
}

function Test-StringSetEqual {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Expected,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Actual
    )
    $expectedValues = @($Expected | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    $actualValues = @($Actual | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
    if ($expectedValues.Count -ne $actualValues.Count) {
        return $false
    }
    return @(Compare-Object -ReferenceObject $expectedValues -DifferenceObject $actualValues).Count -eq 0
}

function Resolve-ReportPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        $resolved = [System.IO.Path]::GetFullPath($Path)
    }
    else {
        $resolved = [System.IO.Path]::GetFullPath((Join-Path $script:ProjectRoot $Path))
    }
    $reportsPrefix = $script:ReportsRoot.TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($reportsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Report path escapes data\reports: $resolved"
    }
    return $resolved
}

function Get-FastQualityPath {
    param($Item)
    return Join-Path $script:ProjectRoot ('data\parsed\pymupdf4llm\{0}\{1}\quality.json' -f $Item.organization, $Item.sha8)
}

function Get-MergedQualityPath {
    param($Item)
    return Join-Path $script:ProjectRoot ('data\parsed\merged\{0}\{1}\quality.json' -f $Item.organization, $Item.sha8)
}

function Get-MergedDocumentPath {
    param($Item)
    return Join-Path $script:ProjectRoot ('data\parsed\merged\{0}\{1}\document.json' -f $Item.organization, $Item.sha8)
}

function Get-SummaryJsonPath {
    param($Item)
    return Join-Path $script:ProjectRoot ('data\summaries\{0}\{1}\summary.json' -f $Item.organization, $Item.sha8)
}

function Get-SummaryQualityPath {
    param($Item)
    return Join-Path $script:ProjectRoot ('data\summaries\{0}\{1}\quality.json' -f $Item.organization, $Item.sha8)
}

function Test-JsonSourceSha {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha,
        [ValidateSet('source', 'source_sha256')]
        [string]$Shape = 'source'
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    try {
        $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($Shape -eq 'source') {
            $actual = [string]$value.source.sha256
        }
        else {
            $actual = [string]$value.source_sha256
        }
        return $actual.Equals($ExpectedSha, [System.StringComparison]::OrdinalIgnoreCase)
    }
    catch {
        return $false
    }
}

function Assert-WorkItemIdentity {
    param([Parameter(Mandatory = $true)]$Item)

    $pdf = Resolve-ReportPath ([string]$Item.pdf_path)
    if (-not (Test-Path -LiteralPath $pdf -PathType Leaf)) {
        throw "Report PDF is missing: $pdf"
    }
    $actual = (Get-FileHash -LiteralPath $pdf -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $actual.Equals([string]$Item.sha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Report SHA changed for '$pdf': expected $($Item.sha256), got $actual"
    }
    return $pdf
}

function Invoke-ParseAndEnrich {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$Item
    )

    try {
        $pdf = Assert-WorkItemIdentity $Item
    }
    catch {
        Register-TechnicalFailure $Context $Item $_.Exception.Message
        Save-Manifest $Context
        Write-RunLog $_.Exception.Message 'ERROR'
        return $false
    }

    Start-Stage $Item.parse
    Set-ObjectProperty $Item 'status' 'parsing'
    Save-Manifest $Context
    $parseResult = Invoke-NativeLogged $script:PythonExe @($script:ParseScript, '--pdf', $pdf) "parse/$($Item.sha8)"
    $fastQualityPath = Get-FastQualityPath $Item
    $parseValid = $parseResult.ExitCode -eq 0 -and (Test-JsonSourceSha $fastQualityPath $Item.sha256)
    if (-not $parseValid) {
        $message = "Parse failed or produced no matching quality.json for $($Item.sha8) (exit $($parseResult.ExitCode))."
        Complete-Stage $Item.parse 'failed' $parseResult.ExitCode $parseResult.DurationSeconds $message
        Register-TechnicalFailure $Context $Item $message
        Save-Manifest $Context
        Write-RunLog $message 'ERROR'
        return $false
    }
    $fastQuality = Get-Content -LiteralPath $fastQualityPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Complete-Stage $Item.parse 'success' $parseResult.ExitCode $parseResult.DurationSeconds $null ([string]$fastQuality.metrics.status)
    Set-ObjectProperty $Item 'status' 'parsed'
    Set-ObjectProperty $Item 'error' $null
    Set-ObjectProperty $Item 'error_kind' $null
    Save-Manifest $Context

    Start-Stage $Item.enrich
    Set-ObjectProperty $Item 'status' 'enriching'
    Save-Manifest $Context
    $enrichResult = Invoke-NativeLogged $script:PythonExe @($script:EnrichScript, '--sha', [string]$Item.sha256) "enrich/$($Item.sha8)"
    $mergedQualityPath = Get-MergedQualityPath $Item
    $mergedDocumentPath = Get-MergedDocumentPath $Item
    $mergedValid = $enrichResult.ExitCode -eq 0 -and
        (Test-JsonSourceSha $mergedQualityPath $Item.sha256) -and
        (Test-JsonSourceSha $mergedDocumentPath $Item.sha256)
    if (-not $mergedValid) {
        $message = "MinerU/merge failed or produced no matching output for $($Item.sha8) (exit $($enrichResult.ExitCode))."
        Complete-Stage $Item.enrich 'failed' $enrichResult.ExitCode $enrichResult.DurationSeconds $message
        Register-TechnicalFailure $Context $Item $message
        Save-Manifest $Context
        Write-RunLog $message 'ERROR'
        return $false
    }

    $mergedQuality = Get-Content -LiteralPath $mergedQualityPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $qualityStatus = [string]$mergedQuality.metrics.status
    Complete-Stage $Item.enrich 'success' $enrichResult.ExitCode $enrichResult.DurationSeconds $null $qualityStatus
    if ($qualityStatus -eq 'needs_manual_review') {
        Set-ObjectProperty $Item 'status' 'manual_review'
        Set-ObjectProperty $Item 'review_required' $true
        Set-ObjectProperty $Item 'error_kind' 'quality'
        Set-ObjectProperty $Item 'error' 'Merged PDF requires manual review; summary was not generated.'
        Save-Manifest $Context
        Write-RunLog "$($Item.sha8) requires manual review after merge; summary is quarantined." 'WARN'
        return $false
    }
    if ($qualityStatus -notin @('ready_for_summary', 'ready_for_summary_with_visual_gaps')) {
        $message = "Unexpected merged quality status '$qualityStatus' for $($Item.sha8)."
        Register-TechnicalFailure $Context $Item $message
        Save-Manifest $Context
        Write-RunLog $message 'ERROR'
        return $false
    }

    Set-ObjectProperty $Item 'status' 'ready_for_summary'
    Set-ObjectProperty $Item 'error' $null
    Set-ObjectProperty $Item 'error_kind' $null
    Save-Manifest $Context
    return $true
}

function Invoke-ParseAndEnrichSafely {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$Item
    )
    try {
        return Invoke-ParseAndEnrich $Context $Item
    }
    catch {
        $message = "Unexpected per-SHA parse/enrich exception for $($Item.sha8): $($_.Exception.Message)"
        Register-TechnicalFailure $Context $Item $message
        try {
            Save-Manifest $Context
        }
        catch {
            throw "Could not persist per-SHA failure for $($Item.sha8): $($_.Exception.Message)"
        }
        Write-RunLog $message 'ERROR'
        return $false
    }
}

function Get-MetadataRowsAfter {
    param(
        [Parameter(Mandatory = $true)][int]$StartLine,
        [Nullable[int]]$EndLine
    )
    if (-not (Test-Path -LiteralPath $script:MetadataPath -PathType Leaf)) {
        return @()
    }
    $allLines = @(Get-Content -LiteralPath $script:MetadataPath -Encoding UTF8)
    if ($allLines.Count -lt $StartLine) {
        throw "Downloader metadata JSONL has fewer than the recorded $StartLine baseline lines."
    }
    $takeCount = $allLines.Count - $StartLine
    if ($null -ne $EndLine) {
        $endLineValue = [int]$EndLine
        if ($endLineValue -lt $StartLine -or $endLineValue -gt $allLines.Count) {
            throw "Manifest metadata line range $StartLine..$endLineValue is invalid."
        }
        $takeCount = $endLineValue - $StartLine
    }
    $rows = @()
    for ($lineIndex = $StartLine; $lineIndex -lt ($StartLine + $takeCount); $lineIndex += 1) {
        $line = $allLines[$lineIndex]
        if ([string]::IsNullOrWhiteSpace([string]$line)) {
            continue
        }
        try {
            $rows += ($line | ConvertFrom-Json)
        }
        catch {
            Write-RunLog "Skipping malformed downloader metadata JSONL line $($lineIndex + 1): $($_.Exception.Message)" 'WARN'
        }
    }
    return $rows
}

function Get-MetadataLineCount {
    if (-not (Test-Path -LiteralPath $script:MetadataPath -PathType Leaf)) {
        return 0
    }
    return @(Get-Content -LiteralPath $script:MetadataPath -Encoding UTF8).Count
}

function New-InventoryWorkItem {
    param(
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][string]$Sha256
    )

    $sha = $Sha256.ToLowerInvariant()
    if (-not $Inventory.BySha.ContainsKey($sha)) {
        throw "PDF inventory does not contain SHA $sha."
    }
    $entry = $Inventory.BySha[$sha]
    $path = [string](@($entry.paths)[0])
    $organization = [string](@($entry.organizations)[0])
    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($organization)) {
        throw "PDF inventory entry $sha has no routable path/organization."
    }
    return New-WorkItem $path $sha $organization
}

function Reconcile-HistoricalManifests {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Contexts,
        [Parameter(Mandatory = $true)]$Inventory,
        [switch]$ReadOnly
    )

    $metadataLineCount = Get-MetadataLineCount
    $tracked = @{}
    foreach ($context in $Contexts) {
        foreach ($item in @($context.Data.items)) {
            $tracked[([string]$item.sha256).ToLowerInvariant()] = $true
        }
    }

    foreach ($context in $Contexts) {
        $download = $context.Data.download
        if ($download.status -notin @('running', 'failed')) {
            continue
        }

        $startLine = [int]$download.metadata_start_line
        $endLine = $null
        if ($null -ne $download.metadata_end_line) {
            $endLine = [int]$download.metadata_end_line
        }
        else {
            $laterStarts = @(
                $Contexts |
                    ForEach-Object { [int]$_.Data.download.metadata_start_line } |
                    Where-Object { $_ -gt $startLine } |
                    Sort-Object
            )
            $endLine = if ($laterStarts.Count -gt 0) { [int]$laterStarts[0] } else { $metadataLineCount }
        }
        if ($startLine -lt 0 -or $endLine -lt $startLine -or $endLine -gt $metadataLineCount) {
            Write-RunLog "Manifest $($context.Data.run_id) has an invalid metadata range $startLine..$endLine; global PDF fallback will cover it." 'WARN'
            continue
        }

        $changed = $false
        $items = @($context.Data.items)
        $inManifest = @{}
        foreach ($item in $items) {
            $inManifest[([string]$item.sha256).ToLowerInvariant()] = $item
        }
        try {
            foreach ($row in @(Get-MetadataRowsAfter $startLine $endLine)) {
                if ([string]$row.download_status -ne 'downloaded' -or
                    [string]$row.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
                    continue
                }
                $sha = ([string]$row.sha256).ToLowerInvariant()
                if (-not $Inventory.BySha.ContainsKey($sha)) {
                    Write-RunLog "Manifest $($context.Data.run_id) metadata references downloaded SHA $sha, but no matching local PDF exists." 'WARN'
                    continue
                }
                if ($inManifest.ContainsKey($sha)) {
                    if (-not [bool]$inManifest[$sha].metadata_matched -and -not $ReadOnly) {
                        Set-ObjectProperty $inManifest[$sha] 'metadata_matched' $true
                        $changed = $true
                    }
                    continue
                }
                if ($tracked.ContainsKey($sha)) {
                    continue
                }
                if ($ReadOnly) {
                    Write-RunLog "DryRun: manifest $($context.Data.run_id) would recover metadata SHA $sha." 'WARN'
                    $tracked[$sha] = $true
                    continue
                }
                $item = New-InventoryWorkItem $Inventory $sha
                Set-ObjectProperty $item 'metadata_matched' $true
                $items += $item
                $inManifest[$sha] = $item
                $tracked[$sha] = $true
                $changed = $true
                Write-RunLog "Recovered SHA $sha into interrupted manifest $($context.Data.run_id) from metadata lines $startLine..$endLine." 'WARN'
            }
        }
        catch {
            Write-RunLog "Could not reconcile metadata for manifest $($context.Data.run_id): $($_.Exception.Message). Global PDF fallback will cover it." 'WARN'
        }

        if (-not $ReadOnly) {
            if ($null -eq $download.metadata_end_line) {
                Set-ObjectProperty $download 'metadata_end_line' $endLine
                $changed = $true
            }
            if ($download.status -eq 'running') {
                $message = 'Downloader was interrupted before its manifest was finalized; startup reconciliation recovered any visible PDFs.'
                Complete-Stage $download 'failed' 97 0 $message
                Add-ManifestError $context $message
                $changed = $true
            }
            if ($changed) {
                Set-ObjectProperty $context.Data 'items' $items
                Save-Manifest $context
            }
        }
    }
    return @($Contexts)
}

function Ensure-GlobalPdfRecovery {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Contexts,
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$ValidSummarySha256,
        [Parameter(Mandatory = $true)][string]$RecoveryRunId,
        [Parameter(Mandatory = $true)][int]$MetadataLineCount,
        [switch]$ReadOnly
    )

    $valid = @{}
    foreach ($sha in $ValidSummarySha256) {
        $valid[([string]$sha).ToLowerInvariant()] = $true
    }
    $isolated = @{}
    $existing = @{}
    foreach ($context in $Contexts) {
        foreach ($item in @($context.Data.items)) {
            $sha = ([string]$item.sha256).ToLowerInvariant()
            if (-not $existing.ContainsKey($sha)) {
                $existing[$sha] = @()
            }
            $existing[$sha] = @($existing[$sha]) + [pscustomobject]@{ Context = $context; Item = $item }
            if ($item.status -eq 'manual_review' -or $null -ne $item.quarantined_at) {
                $isolated[$sha] = $true
            }
        }
    }

    $untracked = @()
    foreach ($sha in @($Inventory.Sha256)) {
        $sha = ([string]$sha).ToLowerInvariant()
        if ($valid.ContainsKey($sha) -or $isolated.ContainsKey($sha)) {
            continue
        }
        if ($existing.ContainsKey($sha)) {
            $retryable = @(
                $existing[$sha] |
                    Where-Object { $_.Item.status -notin @('completed', 'completed_with_review', 'manual_review') }
            )
            if ($retryable.Count -eq 0) {
                if ($ReadOnly) {
                    Write-RunLog "DryRun: completed manifest item $sha has no valid current summary and would be reset to pending." 'WARN'
                }
                else {
                    $entry = @($existing[$sha] | Where-Object { $_.Item.status -ne 'manual_review' })[0]
                    Set-ObjectProperty $entry.Item 'status' 'pending'
                    Set-ObjectProperty $entry.Item 'review_required' $false
                    Set-ObjectProperty $entry.Item 'error' 'Existing summary is missing, stale, or failed current source/content validation; item was recovered.'
                    Set-ObjectProperty $entry.Item 'error_kind' 'technical'
                    Set-ObjectProperty $entry.Item 'summary' (New-StageState)
                    Save-Manifest $entry.Context
                    Write-RunLog "Reset SHA $sha to pending because no valid summary matches the current merged content." 'WARN'
                }
            }
            continue
        }
        $untracked += $sha
    }

    if ($untracked.Count -eq 0) {
        return @($Contexts)
    }
    if ($ReadOnly) {
        Write-RunLog "DryRun: global PDF fallback would recover $($untracked.Count) untracked SHA(s): $($untracked -join ', ')." 'WARN'
        return @($Contexts)
    }

    $recovery = New-ManifestContext $RecoveryRunId $MetadataLineCount $Inventory
    Complete-Stage $recovery.Data.download 'success' 0 0
    Set-ObjectProperty $recovery.Data.download 'metadata_end_line' $MetadataLineCount
    Set-ObjectProperty $recovery.Data.download 'result_pdf_count' ([int]$Inventory.Count)
    Set-ObjectProperty $recovery.Data.download 'result_fingerprint' ([string]$Inventory.Fingerprint)
    Set-ObjectProperty $recovery.Data.download 'result_sha256' @($Inventory.Sha256)
    $items = @()
    foreach ($sha in $untracked) {
        $items += New-InventoryWorkItem $Inventory $sha
    }
    Set-ObjectProperty $recovery.Data 'items' $items
    Add-ManifestError $recovery 'Created by startup global PDF fallback: local PDF had neither a valid summary nor an active/manual-review manifest item.'
    Save-Manifest $recovery
    Write-RunLog "Global PDF fallback created recovery manifest $RecoveryRunId for $($items.Count) SHA(s)." 'WARN'
    return @($Contexts) + $recovery
}

function Get-NewItemsFromInventory {
    param(
        [Parameter(Mandatory = $true)]$BaselineInventory,
        [Parameter(Mandatory = $true)]$CurrentInventory,
        [Parameter(Mandatory = $true)][int]$MetadataStartLine,
        [Parameter(Mandatory = $true)][int]$MetadataEndLine
    )

    $baselineSet = @{}
    foreach ($sha in @($BaselineInventory.Sha256)) {
        $baselineSet[([string]$sha).ToLowerInvariant()] = $true
    }
    $newSha = @(
        $CurrentInventory.Sha256 |
            Where-Object { -not $baselineSet.ContainsKey(([string]$_).ToLowerInvariant()) } |
            Sort-Object -Unique
    )
    $metadataBySha = @{}
    $metadataRows = @()
    try {
        $metadataRows = @(Get-MetadataRowsAfter $MetadataStartLine $MetadataEndLine)
    }
    catch {
        Write-RunLog "Could not read downloader metadata range $MetadataStartLine..$MetadataEndLine; B0/B1 inventory remains authoritative: $($_.Exception.Message)" 'WARN'
    }
    foreach ($row in $metadataRows) {
        if ([string]$row.download_status -ne 'downloaded' -or
            [string]$row.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
            continue
        }
        $metadataBySha[([string]$row.sha256).ToLowerInvariant()] = $row
    }

    foreach ($sha in $metadataBySha.Keys) {
        if ($newSha -notcontains $sha) {
            Write-RunLog "Metadata marked SHA $sha downloaded, but it is not in the B1-B0 local PDF SHA difference." 'WARN'
        }
    }

    $items = @()
    foreach ($sha in $newSha) {
        $entry = $CurrentInventory.BySha[$sha]
        $path = [string](@($entry.paths)[0])
        $organization = [string](@($entry.organizations)[0])
        $item = New-WorkItem $path $sha $organization
        if ($metadataBySha.ContainsKey($sha)) {
            $row = $metadataBySha[$sha]
            Set-ObjectProperty $item 'metadata_matched' $true
            if (-not [string]::IsNullOrWhiteSpace([string]$row.local_path)) {
                try {
                    $metadataPath = Resolve-ReportPath ([string]$row.local_path)
                    if (-not $metadataPath.Equals($path, [System.StringComparison]::OrdinalIgnoreCase)) {
                        Write-RunLog "Metadata path differs from inventory path for $sha; inventory path is authoritative." 'WARN'
                    }
                }
                catch {
                    Write-RunLog "Metadata path for $sha is invalid; inventory path is authoritative: $($_.Exception.Message)" 'WARN'
                }
            }
        }
        else {
            Write-RunLog "New local PDF SHA $sha has no matching downloaded metadata row; it will still be recovered." 'WARN'
        }
        $items += $item
    }
    return $items
}

function Assert-NoSha8Collisions {
    param([Parameter(Mandatory = $true)][array]$Entries)
    $seen = @{}
    foreach ($entry in $Entries) {
        $item = $entry.Item
        $prefix = ([string]$item.sha8).ToLowerInvariant()
        $sha = ([string]$item.sha256).ToLowerInvariant()
        if ($seen.ContainsKey($prefix) -and $seen[$prefix] -ne $sha) {
            throw "Two different SHA-256 values share prefix '$prefix'; sha8-based summary routing is unsafe."
        }
        $seen[$prefix] = $sha
    }
}

function Get-BatchSummaryShaSet {
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return @()
    }
    try {
        $summary = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $values = @()
        foreach ($report in @($summary.reports)) {
            $sha = [string]$report.source.sha256
            if ($sha -match '^[a-fA-F0-9]{64}$') {
                $values += $sha.ToLowerInvariant()
            }
        }
        return @($values | Sort-Object -Unique)
    }
    catch {
        Write-RunLog "Batch summary '$Path' is unreadable or has an invalid source schema: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Test-ParsingBatchShaSets {
    param([Parameter(Mandatory = $true)]$ExpectedInventory)
    try {
        $fastPath = Join-Path $script:ProjectRoot 'data\parsed\pymupdf4llm\batch-summary.json'
        $mergedPath = Join-Path $script:ProjectRoot 'data\parsed\merged\batch-summary.json'
        $fastSha = @(Get-BatchSummaryShaSet $fastPath)
        $mergedSha = @(Get-BatchSummaryShaSet $mergedPath)
        $fastExact = Test-StringSetEqual $ExpectedInventory.Sha256 $fastSha
        $mergedExact = Test-StringSetEqual $ExpectedInventory.Sha256 $mergedSha
        if (-not $fastExact -or -not $mergedExact) {
            Write-RunLog "Parsing batch SHA sets require repair: PDFs=$($ExpectedInventory.Count), PyMuPDF4LLM=$($fastSha.Count), merged=$($mergedSha.Count)." 'WARN'
            return $false
        }
        return $true
    }
    catch {
        Write-RunLog "Parsing batch SHA sets could not be validated and require repair: $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Invoke-FullBatchRefresh {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)]$ExpectedInventory
    )

    Write-RunLog 'Refreshing full-corpus PyMuPDF4LLM and merged batch summaries after targeted work.'
    $allSucceeded = $true
    $expectedSha = @($ExpectedInventory.Sha256)

    Start-Stage $Context.Data.batch_refresh.parse
    Save-Manifest $Context
    $parseResult = Invoke-NativeLogged $script:PythonExe @($script:ParseScript) 'batch-refresh/parse'
    $fastBatchPath = Join-Path $script:ProjectRoot 'data\parsed\pymupdf4llm\batch-summary.json'
    $fastBatchSha = @(Get-BatchSummaryShaSet $fastBatchPath)
    $parseValid = $parseResult.ExitCode -eq 0 -and (Test-StringSetEqual $expectedSha $fastBatchSha)
    if ($parseValid) {
        Complete-Stage $Context.Data.batch_refresh.parse 'success' $parseResult.ExitCode $parseResult.DurationSeconds
    }
    else {
        $message = "Full PyMuPDF4LLM batch refresh failed or its complete SHA set differs from the PDF inventory (exit $($parseResult.ExitCode))."
        Complete-Stage $Context.Data.batch_refresh.parse 'failed' $parseResult.ExitCode $parseResult.DurationSeconds $message
        Add-ManifestError $Context $message
        Write-RunLog $message 'ERROR'
        $allSucceeded = $false
    }
    Save-Manifest $Context

    Start-Stage $Context.Data.batch_refresh.enrich
    Save-Manifest $Context
    $enrichResult = Invoke-NativeLogged $script:PythonExe @($script:EnrichScript, '--merge-only') 'batch-refresh/enrich'
    $mergedBatchPath = Join-Path $script:ProjectRoot 'data\parsed\merged\batch-summary.json'
    $mergedBatchSha = @(Get-BatchSummaryShaSet $mergedBatchPath)
    $enrichValid = $enrichResult.ExitCode -eq 0 -and (Test-StringSetEqual $expectedSha $mergedBatchSha)
    if ($enrichValid) {
        Complete-Stage $Context.Data.batch_refresh.enrich 'success' $enrichResult.ExitCode $enrichResult.DurationSeconds
    }
    else {
        $message = "Full merged batch refresh failed or its complete SHA set differs from the PDF inventory (exit $($enrichResult.ExitCode))."
        Complete-Stage $Context.Data.batch_refresh.enrich 'failed' $enrichResult.ExitCode $enrichResult.DurationSeconds $message
        Add-ManifestError $Context $message
        Write-RunLog $message 'ERROR'
        $allSucceeded = $false
    }
    Save-Manifest $Context
    return $allSucceeded
}

function Get-MergedContentHashMap {
    $mergedRoot = Join-Path $script:ProjectRoot 'data\parsed\merged'
    $pythonCode = @'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
result = {}
for path in sorted(root.glob("*/*/document.json")):
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except Exception:
        continue
    sha = str(value.get("source", {}).get("sha256", "")).lower()
    if len(sha) != 64:
        continue
    rendered = json.dumps(value.get("pages", []), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    result[sha] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
print(json.dumps(result, ensure_ascii=True, sort_keys=True))
'@
    # Windows PowerShell's native argument quoting removes embedded quotes from
    # multiline `python -c` arguments. Base64 keeps the validator byte-exact.
    $encodedCode = [System.Convert]::ToBase64String($script:Utf8NoBom.GetBytes($pythonCode))
    $bootstrap = "import base64;exec(base64.b64decode('$encodedCode'))"
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $script:PythonExe -c $bootstrap $mergedRoot 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($exitCode -ne 0) {
        throw "Could not calculate current merged content hashes (exit $exitCode): $($output -join ' ')"
    }
    $decoded = ($output -join "`n") | ConvertFrom-Json
    $map = @{}
    foreach ($property in $decoded.PSObject.Properties) {
        $map[$property.Name.ToLowerInvariant()] = ([string]$property.Value).ToLowerInvariant()
    }
    return $map
}

function Test-SummaryProduct {
    param(
        [Parameter(Mandatory = $true)][string]$SummaryPath,
        [Parameter(Mandatory = $true)][string]$QualityPath,
        [Parameter(Mandatory = $true)][hashtable]$MergedHashMap,
        [string]$ExpectedSha
    )
    if (-not (Test-Path -LiteralPath $SummaryPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $QualityPath -PathType Leaf)) {
        return $false
    }
    try {
        $summary = Get-Content -LiteralPath $SummaryPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $quality = Get-Content -LiteralPath $QualityPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $summarySha = ([string]$summary.source.sha256).ToLowerInvariant()
        $qualitySha = ([string]$quality.source_sha256).ToLowerInvariant()
        if ($summarySha -notmatch '^[a-f0-9]{64}$' -or $qualitySha -ne $summarySha) {
            return $false
        }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedSha) -and
            $summarySha -ne $ExpectedSha.ToLowerInvariant()) {
            return $false
        }
        if ([string]$quality.status -notin @('ready', 'ready_with_filtered_items', 'needs_review')) {
            return $false
        }
        if (-not $MergedHashMap.ContainsKey($summarySha)) {
            return $false
        }
        return ([string]$quality.parsed_content_sha256).ToLowerInvariant() -eq $MergedHashMap[$summarySha]
    }
    catch {
        return $false
    }
}

function Get-ValidSummaryShaSet {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable]$MergedHashMap)
    $values = @()
    $summaryRoot = Join-Path $script:ProjectRoot 'data\summaries'
    if (-not (Test-Path -LiteralPath $summaryRoot -PathType Container)) {
        return $values
    }
    foreach ($summaryPath in Get-ChildItem -LiteralPath $summaryRoot -Recurse -Filter 'summary.json' -File) {
        $organizationDirectory = $summaryPath.Directory.Parent
        $rootDirectory = if ($null -ne $organizationDirectory) { $organizationDirectory.Parent } else { $null }
        if ($null -eq $rootDirectory -or
            -not $rootDirectory.FullName.Equals($summaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        $qualityPath = Join-Path $summaryPath.Directory.FullName 'quality.json'
        if (Test-SummaryProduct $summaryPath.FullName $qualityPath $MergedHashMap) {
            $summary = Get-Content -LiteralPath $summaryPath.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $values += ([string]$summary.source.sha256).ToLowerInvariant()
        }
    }
    return @($values | Sort-Object -Unique)
}

function Get-ShallowSummaryShaSet {
    $values = @()
    $summaryRoot = Join-Path $script:ProjectRoot 'data\summaries'
    if (-not (Test-Path -LiteralPath $summaryRoot -PathType Container)) {
        return $values
    }
    foreach ($summaryPath in Get-ChildItem -LiteralPath $summaryRoot -Recurse -Filter 'summary.json' -File) {
        $organizationDirectory = $summaryPath.Directory.Parent
        $rootDirectory = if ($null -ne $organizationDirectory) { $organizationDirectory.Parent } else { $null }
        if ($null -eq $rootDirectory -or
            -not $rootDirectory.FullName.Equals($summaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        try {
            $summary = Get-Content -LiteralPath $summaryPath.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $qualityPath = Join-Path $summaryPath.Directory.FullName 'quality.json'
            $quality = Get-Content -LiteralPath $qualityPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $sha = ([string]$summary.source.sha256).ToLowerInvariant()
            $mergedPath = Join-Path $script:ProjectRoot ('data\parsed\merged\{0}\{1}\document.json' -f $organizationDirectory.Name, $summaryPath.Directory.Name)
            if ($sha -match '^[a-f0-9]{64}$' -and
                ([string]$quality.source_sha256).ToLowerInvariant() -eq $sha -and
                [string]$quality.status -in @('ready', 'ready_with_filtered_items', 'needs_review') -and
                (Test-JsonSourceSha $mergedPath $sha)) {
                $values += $sha
            }
        }
        catch {
            continue
        }
    }
    return @($values | Sort-Object -Unique)
}

function Get-SummaryBatchShaSet {
    $path = Join-Path $script:ProjectRoot 'data\summaries\batch-summary.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return @()
    }
    try {
        $batch = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $values = @()
        foreach ($report in @($batch.reports)) {
            $sha = [string]$report.source_sha256
            if ($sha -match '^[a-fA-F0-9]{64}$') {
                $values += $sha.ToLowerInvariant()
            }
        }
        return @($values | Sort-Object -Unique)
    }
    catch {
        Write-RunLog "Summary batch '$path' is unreadable or has an invalid source schema: $($_.Exception.Message)" 'WARN'
        return @()
    }
}

function Get-BatchCoveredSummaryShaSet {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$ValidProductSha256
    )
    $batchSet = @{}
    foreach ($sha in @(Get-SummaryBatchShaSet)) {
        $batchSet[([string]$sha).ToLowerInvariant()] = $true
    }
    $covered = @()
    $missing = @()
    foreach ($shaValue in $ValidProductSha256) {
        $sha = ([string]$shaValue).ToLowerInvariant()
        if ($batchSet.ContainsKey($sha)) {
            $covered += $sha
        }
        else {
            $missing += $sha
        }
    }
    if ($missing.Count -gt 0) {
        Write-RunLog "Valid individual summaries omitted from summaries/batch-summary.json will be recovered: $($missing -join ', ')." 'WARN'
    }
    return @($covered | Sort-Object -Unique)
}

function Test-SummaryBatchCoverage {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][hashtable]$MergedHashMap)
    $validProducts = @(Get-ValidSummaryShaSet $MergedHashMap)
    $batchValues = @(Get-SummaryBatchShaSet)
    $batchSet = @{}
    foreach ($sha in $batchValues) {
        $batchSet[$sha] = $true
    }
    $missing = @($validProducts | Where-Object { -not $batchSet.ContainsKey($_) })
    if ($missing.Count -gt 0) {
        Write-RunLog "summaries/batch-summary.json omits valid product SHA(s): $($missing -join ', ')" 'ERROR'
        return $false
    }
    return $true
}

function Invoke-SummaryBatch {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][array]$Entries)

    if ($Entries.Count -eq 0) {
        return $true
    }
    Assert-NoSha8Collisions $Entries
    $useSharedModel = Request-SharedModelReady
    if (-not $useSharedModel -and (Test-PortInUse $LlamaPort)) {
        $message = "TCP port $LlamaPort is already listening; refusing to start or reuse an unknown llama-server."
        foreach ($entry in $Entries) {
            Start-Stage $entry.Item.summary
            Complete-Stage $entry.Item.summary 'failed' 98 0 $message
            Register-TechnicalFailure $entry.Context $entry.Item $message
            Save-Manifest $entry.Context
        }
        Write-RunLog $message 'ERROR'
        return $false
    }

    $unique = @{}
    foreach ($entry in $Entries) {
        $unique[([string]$entry.Item.sha256).ToLowerInvariant()] = $entry.Item
        Start-Stage $entry.Item.summary
        Set-ObjectProperty $entry.Item 'status' 'summarizing'
        Save-Manifest $entry.Context
    }
    $arguments = @(
        $script:SummarizeScript,
        '--base-url', "http://127.0.0.1:$LlamaPort",
        '--request-timeout', [string]$SummaryRequestTimeoutSeconds
    )
    if (-not $useSharedModel) {
        $arguments += '--start-server'
    }
    foreach ($item in @($unique.Values | Sort-Object sha8)) {
        $arguments += @('--sha', [string]$item.sha8)
    }

    $result = Invoke-NativeLogged $script:PythonExe $arguments 'summarize'
    $allSucceeded = $result.ExitCode -eq 0
    $mergedHashMap = $null
    $batchCoverageValid = $false
    try {
        $mergedHashMap = Get-MergedContentHashMap
        $batchCoverageValid = $result.ExitCode -eq 0 -and (Test-SummaryBatchCoverage $mergedHashMap)
    }
    catch {
        Write-RunLog "Summary integrity validation failed: $($_.Exception.Message)" 'ERROR'
        $allSucceeded = $false
    }
    foreach ($entry in $Entries) {
        $item = $entry.Item
        $summaryPath = Get-SummaryJsonPath $item
        $qualityPath = Get-SummaryQualityPath $item
        $valid = $result.ExitCode -eq 0 -and $batchCoverageValid -and $null -ne $mergedHashMap -and
            (Test-SummaryProduct $summaryPath $qualityPath $mergedHashMap $item.sha256)
        if ($valid) {
            $quality = Get-Content -LiteralPath $qualityPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $qualityStatus = [string]$quality.status
            Complete-Stage $item.summary 'success' $result.ExitCode $result.DurationSeconds $null $qualityStatus
            if ($qualityStatus -in @('needs_review', 'ready_with_filtered_items')) {
                Set-ObjectProperty $item 'status' 'completed_with_review'
                Set-ObjectProperty $item 'review_required' $true
                Write-RunLog "$($item.sha8) summary completed with $qualityStatus." 'WARN'
            }
            else {
                Set-ObjectProperty $item 'status' 'completed'
                Set-ObjectProperty $item 'review_required' $false
            }
            Set-ObjectProperty $item 'error' $null
            Set-ObjectProperty $item 'error_kind' $null
        }
        else {
            $message = "Summary failed integrity checks for $($item.sha8): process exit must be 0, quality/source/content hashes must match, and the global batch must cover every valid product (exit $($result.ExitCode))."
            Complete-Stage $item.summary 'failed' $result.ExitCode $result.DurationSeconds $message
            Register-TechnicalFailure $entry.Context $item $message
            Write-RunLog $message 'ERROR'
            $allSucceeded = $false
        }
        Save-Manifest $entry.Context
    }
    if ($result.ExitCode -ne 0) {
        Write-RunLog "Summary process returned exit code $($result.ExitCode)." 'ERROR'
    }
    return $allSucceeded
}

function Test-Configuration {
    $requiredFiles = @(
        $script:PythonExe,
        $script:DownloadScript,
        $script:ParseScript,
        $script:EnrichScript,
        $script:SummarizeScript,
        $script:MinerUExe,
        $script:LlamaServerExe,
        $script:DefaultModel
    )
    foreach ($path in $requiredFiles) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required file is missing: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $script:ReportsRoot -PathType Container)) {
        throw "Reports directory is missing: $script:ReportsRoot"
    }
    if ($StartDate -notmatch '^\d{4}-\d{2}-\d{2}$') {
        throw '-StartDate must be YYYY-MM-DD.'
    }
    if (-not [string]::IsNullOrWhiteSpace($InvocationId) -and
        $InvocationId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw '-InvocationId must be 1-64 characters using only letters, digits, dot, underscore, or hyphen.'
    }
    $parsedStart = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
        $StartDate,
        'yyyy-MM-dd',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None,
        [ref]$parsedStart
    )) {
        throw '-StartDate is not a valid calendar date.'
    }
    if ($EndDate -ne 'today') {
        $parsedEnd = [datetime]::MinValue
        if ($EndDate -notmatch '^\d{4}-\d{2}-\d{2}$' -or -not [datetime]::TryParseExact(
            $EndDate,
            'yyyy-MM-dd',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsedEnd
        )) {
            throw '-EndDate must be today or a valid YYYY-MM-DD date.'
        }
    }
}

function Invoke-DryRunValidation {
    Test-Configuration
    $inventory = Get-PdfInventory
    $parsingBatchesExact = Test-ParsingBatchShaSets $inventory
    $contexts = @(Load-ManifestContexts -ReadOnly)
    $contexts = @(Reconcile-HistoricalManifests $contexts $inventory -ReadOnly)
    $shallowValidSummaries = @(Get-ShallowSummaryShaSet)
    $batchCoveredSummaries = @(Get-BatchCoveredSummaryShaSet $shallowValidSummaries)
    $contexts = @(
        Ensure-GlobalPdfRecovery `
            $contexts `
            $inventory `
            $batchCoveredSummaries `
            'dryrun-recovery' `
            (Get-MetadataLineCount) `
            -ReadOnly
    )
    $pending = 0
    $reviews = 0
    $entries = @()
    foreach ($context in $contexts) {
        foreach ($item in @($context.Data.items)) {
            if ($item.status -notin @('completed', 'completed_with_review', 'manual_review')) {
                $pending += 1
                $entries += [pscustomobject]@{ Context = $context; Item = $item }
            }
            elseif ($item.status -in @('completed_with_review', 'manual_review')) {
                $reviews += 1
            }
        }
    }
    if ($entries.Count -gt 0) {
        Assert-NoSha8Collisions $entries
    }
    Write-RunLog "DryRun validation succeeded. Project root: $script:ProjectRoot"
    Write-RunLog "PDF inventory count=$($inventory.Count), fingerprint=$($inventory.Fingerprint); global SHA8 routing is collision-free."
    Write-RunLog "Historical manifests=$($contexts.Count), retryable items=$pending, review items=$reviews"
    Write-RunLog "Full-corpus parsing batch SHA sets exact=$parsingBatchesExact."
    if (Test-PortInUse $LlamaPort) {
        Write-RunLog "Port $LlamaPort is currently occupied; a real run will ask the model manager to validate its identity before reuse." 'WARN'
    }
    else {
        Write-RunLog "Port $LlamaPort is available."
    }
    Write-RunLog "Downloader would use B0/B1 full-SHA inventory difference for dates $StartDate..$EndDate. Deep content-hash validation is reserved for a real run; no network, Python, MinerU, or model command was run."
    return 0
}

function Invoke-WeeklyIncremental {
    $lockStream = $null
    $currentContext = $null
    try {
        Test-Configuration
        if ($DryRun) {
            return Invoke-DryRunValidation
        }

        [void](New-Item -ItemType Directory -Path (Split-Path $script:LockPath -Parent) -Force)
        try {
            $lockStream = [System.IO.File]::Open(
                $script:LockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
        }
        catch [System.IO.IOException] {
            Write-Error 'Another weekly incremental run holds the exclusive lock.'
            return 20
        }

        $lockText = "pid=$PID started_at=$(Get-UtcTimestamp) project=$script:ProjectRoot`r`n"
        $lockBytes = $script:Utf8NoBom.GetBytes($lockText)
        $lockStream.SetLength(0)
        $lockStream.Write($lockBytes, 0, $lockBytes.Length)
        $lockStream.Flush()

        [void](New-Item -ItemType Directory -Path $script:RunStateRoot -Force)
        [void](New-Item -ItemType Directory -Path $script:LogRoot -Force)
        $runId = if ([string]::IsNullOrWhiteSpace($InvocationId)) {
            (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + $PID
        }
        else {
            $InvocationId
        }
        $script:LogPath = Join-Path $script:LogRoot ("weekly-incremental-$runId.log")
        Write-RunLog "Weekly incremental run started. Project=$script:ProjectRoot"

        $env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $script:ProjectRoot 'data\state\ms-playwright'
        $env:PYTHONIOENCODING = 'utf-8'

        $summaryEntries = @()
        $processingFailure = $false
        $startupInventory = Get-PdfInventory
        Write-RunLog "Startup PDF inventory count=$($startupInventory.Count), fingerprint=$($startupInventory.Fingerprint)."
        $historicalContexts = @(Load-ManifestContexts)
        $historicalContexts = @(Reconcile-HistoricalManifests $historicalContexts $startupInventory)
        $mergedHashMap = Get-MergedContentHashMap
        $validSummaryProducts = @(Get-ValidSummaryShaSet $mergedHashMap)
        $validSummarySha = @(Get-BatchCoveredSummaryShaSet $validSummaryProducts)
        $historicalContexts = @(
            Ensure-GlobalPdfRecovery `
                $historicalContexts `
                $startupInventory `
                $validSummarySha `
                ($runId + '-recovery') `
                (Get-MetadataLineCount)
        )
        $validSummarySet = @{}
        foreach ($sha in $validSummarySha) {
            $validSummarySet[([string]$sha).ToLowerInvariant()] = $true
        }

        $targetedPostProcessingRan = $false
        $scheduledSha = @{}
        $recoverySha = @()
        $recoveryEntries = @()
        foreach ($context in $historicalContexts) {
            foreach ($item in @($context.Data.items)) {
                if ($item.status -in @('completed', 'completed_with_review', 'manual_review')) {
                    continue
                }
                $sha = ([string]$item.sha256).ToLowerInvariant()
                if ($validSummarySet.ContainsKey($sha)) {
                    Write-RunLog "Skipping historical SHA $($item.sha8): a valid summary already matches current merged content."
                    continue
                }
                if ($scheduledSha.ContainsKey($sha)) {
                    Write-RunLog "Skipping duplicate historical manifest reference for SHA $sha." 'WARN'
                    continue
                }
                $scheduledSha[$sha] = $true
                $recoverySha += $sha
                $recoveryEntries += [pscustomobject]@{ Context = $context; Item = $item }
                Write-RunLog "Replaying unfinished SHA $($item.sha8) from manifest $($context.Data.run_id)."
                $targetedPostProcessingRan = $true
                if (Invoke-ParseAndEnrichSafely $context $item) {
                    $summaryEntries += [pscustomobject]@{ Context = $context; Item = $item }
                }
                elseif ($item.error_kind -eq 'technical') {
                    $processingFailure = $true
                }
            }
        }

        # B0 is captured immediately before the downloader. Full SHA difference, not
        # metadata or path names, is authoritative for what this invocation created.
        $baselineInventory = Get-PdfInventory
        $metadataStartLine = Get-MetadataLineCount
        $currentContext = New-ManifestContext $runId $metadataStartLine $baselineInventory
        Save-Manifest $currentContext

        Start-Stage $currentContext.Data.download
        Save-Manifest $currentContext
        $downloadArguments = @(
            $script:DownloadScript,
            '--mode', 'incremental',
            '--start-date', $StartDate,
            '--end-date', $EndDate,
            '--resume',
            '--headless',
            '--page-timeout', [string]$PageTimeoutMs,
            '--download-timeout', [string]$DownloadTimeoutMs
        )
        $downloadResult = Invoke-NativeLogged $script:PythonExe $downloadArguments 'download'
        $metadataEndLine = Get-MetadataLineCount
        $resultInventory = Get-PdfInventory
        Set-ObjectProperty $currentContext.Data.download 'metadata_end_line' $metadataEndLine
        Set-ObjectProperty $currentContext.Data.download 'result_pdf_count' ([int]$resultInventory.Count)
        Set-ObjectProperty $currentContext.Data.download 'result_fingerprint' ([string]$resultInventory.Fingerprint)
        Set-ObjectProperty $currentContext.Data.download 'result_sha256' @($resultInventory.Sha256)
        if ($downloadResult.ExitCode -eq 0) {
            Complete-Stage $currentContext.Data.download 'success' 0 $downloadResult.DurationSeconds
        }
        else {
            $message = "Downloader returned exit code $($downloadResult.ExitCode)."
            Complete-Stage $currentContext.Data.download 'failed' $downloadResult.ExitCode $downloadResult.DurationSeconds $message
            Add-ManifestError $currentContext $message
        }

        $newItems = @(
            Get-NewItemsFromInventory `
                $baselineInventory `
                $resultInventory `
                $metadataStartLine `
                $metadataEndLine
        )
        Set-ObjectProperty $currentContext.Data.download 'new_sha256' @($newItems | ForEach-Object { $_.sha256 })
        Set-ObjectProperty $currentContext.Data 'items' $newItems
        Set-ObjectProperty $currentContext.Data 'recovery_sha256' @($recoverySha | Sort-Object -Unique)
        Set-ObjectProperty $currentContext.Data 'recovery_items' @(
            $recoveryEntries | ForEach-Object {
                [pscustomobject][ordered]@{
                    sha256         = $_.Item.sha256
                    sha8           = $_.Item.sha8
                    organization   = $_.Item.organization
                    status         = $_.Item.status
                    review_required = [bool]$_.Item.review_required
                    error_kind      = $_.Item.error_kind
                    error           = $_.Item.error
                }
            }
        )
        Save-Manifest $currentContext
        Write-RunLog "Downloader B0/B1 inventory identified $($newItems.Count) newly created unique PDF SHA(s); B0=$($baselineInventory.Count), B1=$($resultInventory.Count)."

        foreach ($item in $newItems) {
            $sha = ([string]$item.sha256).ToLowerInvariant()
            if ($scheduledSha.ContainsKey($sha)) {
                Write-RunLog "New inventory SHA $sha was already scheduled from recovery; retaining one processing attempt." 'WARN'
                continue
            }
            $scheduledSha[$sha] = $true
            $targetedPostProcessingRan = $true
            if (Invoke-ParseAndEnrichSafely $currentContext $item) {
                $summaryEntries += [pscustomobject]@{ Context = $currentContext; Item = $item }
            }
            elseif ($item.error_kind -eq 'technical') {
                $processingFailure = $true
            }
        }

        $batchRepairNeeded = -not (Test-ParsingBatchShaSets $resultInventory)
        if ($targetedPostProcessingRan -or $batchRepairNeeded) {
            if (-not (Invoke-FullBatchRefresh $currentContext $resultInventory)) {
                $processingFailure = $true
            }
        }

        $summarySucceeded = Invoke-SummaryBatch $summaryEntries
        if (-not $summarySucceeded) {
            $processingFailure = $true
        }
        Set-ObjectProperty $currentContext.Data 'recovery_items' @(
            $recoveryEntries | ForEach-Object {
                [pscustomobject][ordered]@{
                    sha256          = $_.Item.sha256
                    sha8            = $_.Item.sha8
                    organization    = $_.Item.organization
                    status          = $_.Item.status
                    review_required = [bool]$_.Item.review_required
                    error_kind       = $_.Item.error_kind
                    error            = $_.Item.error
                }
            }
        )
        Save-Manifest $currentContext

        if ($downloadResult.ExitCode -ne 0 -or $processingFailure) {
            Write-RunLog 'Weekly incremental run completed with technical errors; healthy backlog and new PDFs were still processed, while failed SHA values remain retryable or quarantined after three failures.' 'ERROR'
            return 1
        }
        if ($newItems.Count -eq 0 -and $summaryEntries.Count -eq 0) {
            Write-RunLog 'No new PDF and no historical pending summary; run completed successfully.'
            return 0
        }
        Write-RunLog 'Weekly incremental run completed successfully.'
        return 0
    }
    catch {
        $message = $_.Exception.Message
        if ($null -ne $currentContext) {
            try {
                if ($currentContext.Data.download.status -eq 'running') {
                    Complete-Stage $currentContext.Data.download 'failed' 99 0 $message
                }
                Set-ObjectProperty $currentContext.Data 'fatal_error' $message
                Add-ManifestError $currentContext $message
                Save-Manifest $currentContext
            }
            catch {
                Write-RunLog "Could not persist fatal status to current manifest: $($_.Exception.Message)" 'ERROR'
            }
        }
        Write-RunLog "Unhandled weekly incremental error: $message" 'ERROR'
        return 1
    }
    finally {
        if ($null -ne $lockStream) {
            $lockStream.Dispose()
        }
    }
}

exit (Invoke-WeeklyIncremental)
