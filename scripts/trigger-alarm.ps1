# Trigger test alarms in a running procwatch. Same as trigger-alarm.sh.
#   .\scripts\trigger-alarm.ps1 high|medium|low|all|sequence|clear
#   .\scripts\trigger-alarm.ps1 storm 20
param([string]$Action = '', [int]$Count = 20)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$pw = $env:PROCWATCH
if (-not $pw) {
    $pw = @("$root\target\release\procwatch.exe", "$root\target\debug\procwatch.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $pw) { $pw = 'procwatch' }
switch ($Action) {
    { $_ -in 'high', 'medium', 'low' } { & $pw --alarm-trigger $_ }
    'all' { 'low', 'medium', 'high' | ForEach-Object { & $pw --alarm-trigger $_ } }
    'sequence' {
        & $pw --alarm-trigger low; Start-Sleep 5
        & $pw --alarm-trigger medium; Start-Sleep 5
        & $pw --alarm-trigger high
    }
    'storm' { & $pw --alarm-trigger medium --count $Count }
    'clear' { & $pw --alarm-clear }
    default { Get-Content $PSCommandPath -TotalCount 3; exit 2 }
}
exit $LASTEXITCODE
