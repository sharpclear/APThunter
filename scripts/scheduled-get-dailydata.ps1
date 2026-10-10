$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$LogDir = Join-Path $ProjectRoot "logs"
$LogFile = Join-Path $LogDir "get_dailydata.cron.log"
$TimeoutSeconds = 1800
if ($env:GET_DAILYDATA_TIMEOUT_SEC) {
    $TimeoutSeconds = [int]$env:GET_DAILYDATA_TIMEOUT_SEC
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Set-Location $ProjectRoot

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
    Add-Content -Path $LogFile -Encoding UTF8 -Value "[$timestamp] $Message"
}

function Quote-Argument {
    param([string]$Value)
    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -match '^[A-Za-z0-9_./:=\\-]+$') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-LoggedProcess {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][int]$TimeoutSeconds
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($Arguments | ForEach-Object { Quote-Argument $_ }) -join " "
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    Write-Log "run: $FilePath $($psi.Arguments)"
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()

    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Write-Log "timeout after ${TimeoutSeconds}s; killing pid=$($process.Id)"
        try {
            taskkill.exe /PID $process.Id /T /F | ForEach-Object { Write-Log $_ }
        } catch {
            try { $process.Kill() } catch {}
        }
        throw "process timed out: $FilePath"
    }

    $stdoutTask.Wait()
    $stderrTask.Wait()

    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($stdout) {
        $stdout -split '\r?\n' | Where-Object { $_ } | ForEach-Object { Write-Log $_ }
    }
    if ($stderr) {
        $stderr -split '\r?\n' | Where-Object { $_ } | ForEach-Object { Write-Log "stderr: $_" }
    }

    Write-Log "exit code: $($process.ExitCode)"
    return $process.ExitCode
}

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return @{ FilePath = $python.Source; ArgumentsPrefix = @() }
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return @{ FilePath = $py.Source; ArgumentsPrefix = @("-3") }
    }

    return $null
}

Write-Log "start get_dailydata"

$hostScript = Join-Path $ProjectRoot "backend\scripts\get_dailydata.py"
$pythonCommand = Get-PythonCommand

if ($pythonCommand -and (Test-Path $hostScript)) {
    Write-Log "using host python path"
    $args = @($pythonCommand["ArgumentsPrefix"]) + @($hostScript)
    $exitCode = Invoke-LoggedProcess `
        -FilePath $pythonCommand["FilePath"] `
        -Arguments $args `
        -WorkingDirectory $ProjectRoot `
        -TimeoutSeconds $TimeoutSeconds
    if ($exitCode -ne 0) {
        throw "host python get_dailydata failed with exit code $exitCode"
    }
} else {
    Write-Log "host python unavailable; fallback to docker compose exec"
    $docker = Get-Command docker -ErrorAction Stop
    $exitCode = Invoke-LoggedProcess `
        -FilePath $docker.Source `
        -Arguments @("compose", "exec", "-T", "-e", "PYTHONIOENCODING=utf-8", "backend", "python", "/app/scripts/get_dailydata.py") `
        -WorkingDirectory $ProjectRoot `
        -TimeoutSeconds $TimeoutSeconds
    if ($exitCode -ne 0) {
        throw "docker get_dailydata failed with exit code $exitCode"
    }
}

Write-Log "finish get_dailydata"
