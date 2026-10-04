# Varro agent installer for Windows. Run from an elevated PowerShell:
#
#   $env:VARRO_TOKEN = "<org-enrollment-token>"
#   iwr -UseBasicParsing __VARRO_SERVER__/install.ps1 | iex
#
# Downloads the varro binary from the latest GitHub release, verifies its
# checksum, and installs a Windows service enrolled against this collector.
$ErrorActionPreference = "Stop"

$server = "__VARRO_SERVER__"
$repo   = "SOC-Foundry/Varro"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "varro-install: must run from an elevated (Administrator) PowerShell"
}
if (-not $env:VARRO_TOKEN) {
    throw "varro-install: set `$env:VARRO_TOKEN to your org's enrollment token first"
}

$dir   = Join-Path $env:ProgramFiles "Varro"
$state = Join-Path $env:ProgramData "Varro"
New-Item -ItemType Directory -Force -Path $dir, $state | Out-Null

$asset = "varro-windows-amd64.exe"
$base  = "https://github.com/$repo/releases/latest/download"
Write-Host "downloading $asset from latest release..."
Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile "$dir\varro-new.exe"
Invoke-WebRequest -UseBasicParsing "$base/checksums.txt" -OutFile "$dir\checksums.txt"

$want = ((Get-Content "$dir\checksums.txt") -match [regex]::Escape($asset))[0].Split(" ")[0].ToLower()
$got  = (Get-FileHash "$dir\varro-new.exe" -Algorithm SHA256).Hash.ToLower()
if ($got -ne $want) { throw "varro-install: checksum verification failed" }

# Replace any existing service/binary.
if (Get-Service varro-agent -ErrorAction SilentlyContinue) {
    Stop-Service varro-agent -Force -ErrorAction SilentlyContinue
    sc.exe delete varro-agent | Out-Null
    Start-Sleep -Seconds 2
}
Move-Item -Force "$dir\varro-new.exe" "$dir\varro.exe"
Remove-Item -Force "$dir\checksums.txt"

# New-Service (not sc.exe create): PowerShell 5.1 mangles embedded quotes in
# native-command arguments, which silently breaks sc.exe binPath values.
$bin = "`"$dir\varro.exe`" agent --server $server --token $($env:VARRO_TOKEN) --state-dir `"$state`""
New-Service -Name varro-agent -BinaryPathName $bin -DisplayName "Varro telemetry agent" -StartupType Automatic | Out-Null
# Self-upgrade exits the service with a failure code; these recovery actions
# restart it on the new binary. (Plain tokens only — safe for sc.exe.)
sc.exe failure varro-agent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Start-Service varro-agent

Start-Sleep -Seconds 3
$svc = Get-Service varro-agent
if ($svc.Status -ne "Running") { throw "varro-install: service failed to start (check Event Viewer)" }

Write-Host ""
Write-Host "varro agent is running and enrolling with $server"
Write-Host "  status:  Get-Service varro-agent"
