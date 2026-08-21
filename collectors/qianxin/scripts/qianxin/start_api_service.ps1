<#
.SYNOPSIS
Starts the Qianxin API for the APTHunter virtual machine.

.DESCRIPTION
This wrapper is intended for Windows Task Scheduler. It loads the API secret
from the current user's environment, avoids starting a duplicate listener, and
keeps service output in the project log directory.
#>
[CmdletBinding()]
param(
    [string]$HostAddress = '0.0.0.0',
    [ValidateRange(1, 65535)]
    [int]$Port = 8787,
    [string]$PublicBaseUrl = 'http://192.168.21.181:8787'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'
$logRoot = Join-Path $projectRoot 'logs\api'
$logPath = Join-Path $logRoot 'qianxin-api-service.log'
$errorLogPath = Join-Path $logRoot 'qianxin-api-service.error.log'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

try {
    $existingListener = Get-NetTCPConnection `
        -State Listen `
        -LocalPort $Port `
        -ErrorAction SilentlyContinue
    if ($existingListener) {
        exit 0
    }

    $apiKey = [Environment]::GetEnvironmentVariable('QIANXIN_API_KEY', 'User')
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        throw 'The user-level QIANXIN_API_KEY is not configured.'
    }

    $env:QIANXIN_API_KEY = $apiKey
    $env:QIANXIN_PUBLIC_BASE_URL = $PublicBaseUrl.TrimEnd('/')
    $env:QIANXIN_EVENT_AUTO_ACCEPT = 'false'
    $env:QIANXIN_SHARED_MODEL_ENABLED = 'true'
    if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
        throw 'Python virtual environment was not found under the project root.'
    }

    $ErrorActionPreference = 'Continue'
    Set-Location -LiteralPath $projectRoot
    & $pythonExe -m uvicorn scripts.qianxin.api:app `
        --host $HostAddress `
        --port $Port `
        --workers 1 `
        --no-access-log 1>> $logPath 2>> $errorLogPath
    exit $LASTEXITCODE
}
catch {
    $message = '[{0}] startup failed: {1}: {2}{3}' -f `
        (Get-Date -Format o), `
        $_.Exception.GetType().Name, `
        $_.Exception.Message, `
        [Environment]::NewLine
    [System.IO.File]::AppendAllText($logPath, $message)
    exit 1
}
