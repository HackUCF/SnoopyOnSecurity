param(
    [Parameter(Mandatory = $true)]
    [string]$sourceFile,
    [Parameter(Mandatory = $true)]
    [string]$targetService
)

# Verify the script is running as Administrator.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Optional: Verify minimum PowerShell version (requires 3.0+)
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "This script requires PowerShell 3.0 or later."
    exit 1
}

# Check if the specified service exists on the system.
try {
    Get-Service -Name $targetService -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Service '$targetService' does not exist on this system."
    exit 1
}

$targetReg = "$env:TEMP\${targetService}_restore.reg"
$pattern = "^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\$targetService\]$"
$found = $false

# Read all lines from the source .reg file
$lines = Get-Content $sourceFile

# Write the header from the source file (e.g. "Windows Registry Editor Version 5.00")
Set-Content $targetReg $lines[0]

# Loop through the rest of the lines looking for the target service block.
for ($i = 1; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    if ($line -match $pattern) {
        $found = $true
        Add-Content $targetReg $line
        continue
    }

    if ($found) {
        # Stop if another key block starts.
        if ($line -match '^\[') {
            break
        }
        Add-Content $targetReg $line
    }
}

if ($found) {
    Write-Host "Importing registry settings for service '$targetService'..."
    reg import $targetReg
} else {
    Write-Error "Target service registry key '$targetService' not found in $sourceFile"
    exit 1
}

