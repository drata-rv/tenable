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
