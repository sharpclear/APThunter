<#
.SYNOPSIS
Starts the local Qianxin collector API with one worker.

.DESCRIPTION
The API key is read from QIANXIN_API_KEY.  This script intentionally binds to
localhost unless the operator explicitly supplies another address and has put TLS and
firewall controls in front of the service.
#>
[CmdletBinding()]
param(
    [string]$HostAddress = '127.0.0.1',
    [ValidateRange(1, 65535)]
    [int]$Port = 8787,
    [string]$PublicBaseUrl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$pythonExe = Join-Path $projectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    throw "Python virtual environment was not found under the project root."
}
if ([string]::IsNullOrWhiteSpace($env:QIANXIN_API_KEY)) {
    throw 'QIANXIN_API_KEY must be set before the API starts.'
}
if (-not [string]::IsNullOrWhiteSpace($PublicBaseUrl)) {
    $env:QIANXIN_PUBLIC_BASE_URL = $PublicBaseUrl.TrimEnd('/')
}
elseif ([string]::IsNullOrWhiteSpace($env:QIANXIN_PUBLIC_BASE_URL) -and
        $HostAddress -notin @('127.0.0.1', 'localhost', '0.0.0.0', '::')) {
    $env:QIANXIN_PUBLIC_BASE_URL = 'http://{0}:{1}' -f $HostAddress, $Port
}

Set-Location -LiteralPath $projectRoot
& $pythonExe -m uvicorn scripts.qianxin.api:app `
    --host $HostAddress `
    --port $Port `
    --workers 1 `
    --no-access-log
exit $LASTEXITCODE
