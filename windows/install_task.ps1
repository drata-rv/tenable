param(
    [Parameter(Mandatory = $true)]
    [string]$RunAsUser,

    [Parameter(Mandatory = $true)]
    [securestring]$Password,

    [string]$StartTime = "06:00",

    [string]$InstallDir = "C:\Program Files\NessusDrataCollector",

    [string]$TaskName = "Drata Nessus CIS Collector"
)

$ErrorActionPreference = "Stop"

$scriptPath = Join-Path $InstallDir "windows\run_collector.cmd"
if (-not (Test-Path $scriptPath)) {
    throw "run_collector.cmd not found at $scriptPath -- check -InstallDir"
}

$action = New-ScheduledTaskAction -Execute $scriptPath
$trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew `
    -StartWhenAvailable `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 15) `
    -DontStopIfGoingOnBatteries `
    -AllowStartIfOnBatteries

$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $action -Trigger $trigger -Settings $settings `
        -User $RunAsUser -Password $plainPassword -RunLevel Limited | Out-Null
}
finally {
    Remove-Variable plainPassword -ErrorAction SilentlyContinue
}

Write-Host "Registered scheduled task '$TaskName' running as $RunAsUser daily at $StartTime."
Write-Host "Force one manual run now with:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Then confirm Last Result is 0 with:"
Write-Host "  (Get-ScheduledTaskInfo -TaskName '$TaskName').LastTaskResult"
