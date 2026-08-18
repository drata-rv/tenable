<#
.SYNOPSIS
  Sets the three required secrets as MACHINE-scope environment variables
  (spec Section 7.2 / 9.5). Run from an elevated PowerShell prompt.

.DESCRIPTION
  Machine-scope variables are readable by any local process on this box --
  an accepted risk for MVP on a controlled admin workstation (spec Section
  9.5). The hardening path (Windows Credential Manager / DPAPI-encrypted
  secrets decryptable only by the run account) is explicitly out of scope
  for this MVP; do not build it here.

  Secrets are accepted as SecureString parameters (prompted interactively
  by PowerShell, e.g. via Read-Host -AsSecureString) rather than plaintext
  command-line arguments, so they never land in shell history or process
  listings during this script's own execution -- an improvement over
  handling them as literal strings, not a change to what gets stored
  afterward (still a plain machine-scope environment variable, per spec).

  If the Scheduled Task already exists when this script runs, restart it
  (or reboot the box) so it inherits the updated environment block --
  Windows does not propagate machine env var changes to an already-running
  or already-registered task automatically (spec Section 9.5).

.EXAMPLE
  .\set_machine_env.ps1 `
    -NessusAccessKey (Read-Host -AsSecureString -Prompt 'NESSUS_ACCESS_KEY') `
    -NessusSecretKey (Read-Host -AsSecureString -Prompt 'NESSUS_SECRET_KEY') `
    -DrataApiKey     (Read-Host -AsSecureString -Prompt 'DRATA_API_KEY')
#>
param(
    [Parameter(Mandatory = $true)]
    [securestring]$NessusAccessKey,

    [Parameter(Mandatory = $true)]
    [securestring]$NessusSecretKey,

    [Parameter(Mandatory = $true)]
    [securestring]$DrataApiKey
)

$ErrorActionPreference = "Stop"

function ConvertTo-PlainText {
    param([securestring]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

[Environment]::SetEnvironmentVariable('NESSUS_ACCESS_KEY', (ConvertTo-PlainText $NessusAccessKey), 'Machine')
[Environment]::SetEnvironmentVariable('NESSUS_SECRET_KEY', (ConvertTo-PlainText $NessusSecretKey), 'Machine')
[Environment]::SetEnvironmentVariable('DRATA_API_KEY', (ConvertTo-PlainText $DrataApiKey), 'Machine')

Write-Host "Machine-scope environment variables set: NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY, DRATA_API_KEY."
Write-Host "If the Scheduled Task already exists, restart it (or reboot) to pick up the new values."
