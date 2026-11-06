# Install procwatch as a Windows service. Run as administrator.
param([Parameter(Mandatory)][string]$Binary)
$ErrorActionPreference = 'Stop'
$dir = "$env:ProgramFiles\procwatch"
$data = "$env:ProgramData\procwatch"
New-Item -ItemType Directory -Force $dir, $data | Out-Null
Copy-Item $Binary "$dir\procwatch.exe" -Force
if (-not (Test-Path "$data\agent.yml")) { Copy-Item rules\policy\agent-example.yml "$data\agent.yml" }
$bin = "`"$dir\procwatch.exe`" --windows-service `"$data\agent.yml`" --output `"$data\agent.jsonl`""
sc.exe create procwatch binPath= $bin start= auto obj= "NT SERVICE\procwatch" | Out-Null
sc.exe description procwatch "procwatch computer monitor" | Out-Null
# Restart after every failure; the count resets after a quiet day.
sc.exe failure procwatch reset= 86400 actions= restart/2000/restart/2000/restart/5000 | Out-Null
sc.exe failureflag procwatch 1 | Out-Null
# Only administrators may write the program and settings.
icacls $dir /inheritance:r /grant "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "NT SERVICE\procwatch:(OI)(CI)RX" | Out-Null
icacls $data /inheritance:r /grant "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "NT SERVICE\procwatch:(OI)(CI)M" | Out-Null
Start-Service procwatch
Get-Service procwatch
