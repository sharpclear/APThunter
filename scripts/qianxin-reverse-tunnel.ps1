[CmdletBinding()]
param(
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$sshPath = Join-Path $env:WINDIR "System32\OpenSSH\ssh.exe"
$identityPath = Join-Path $env:USERPROFILE ".ssh\apthunter_vm_ed25519"
$knownHostsPath = Join-Path $env:USERPROFILE ".ssh\known_hosts"
$sshArguments = @(
    "-N",
    "-T",
    "-i", $identityPath,
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=$knownHostsPath",
    "-R", "127.0.0.1:18787:127.0.0.1:8787",
    "mlz@192.168.32.219"
)

foreach ($requiredPath in @($sshPath, $identityPath, $knownHostsPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required SSH file is missing: $requiredPath"
    }
}

if ($ValidateOnly) {
    Write-Output "Qianxin reverse tunnel configuration is valid."
    exit 0
}

while ($true) {
    & $sshPath @sshArguments
    Start-Sleep -Seconds 15
}
