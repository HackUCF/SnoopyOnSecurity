#ps1

# Define paths for Procmon, config, and output files 🛠️
# set config to ProcessName = rundll32.exe and Operation = TCP Connection
$procmon = "C:\Sysinternals\procmon.exe"
$config  = "C:\ProcmonConfiguration.pmc"
$backing = "C:\procmon_capture.pml"
$csvOut  = "C:\procmon_capture.csv"

# Make sure Procmon is not blocked by Windows 🔓
Unblock-File -Path "C:\Sysinternals\procmon.exe"

# Check if Procmon exists
if (!(Test-Path $procmon)) {
    Write-Host "[ERROR] Procmon not found"
    exit
}

# Check if config file exists
if (!(Test-Path $config)) {
    Write-Host "[ERROR] Config not found"
    exit
}

# Start Procmon with the given config and save output to a backing file 🚀
Start-Process $procmon -ArgumentList @(
    "/AcceptEula",
    "/Quiet",
    "/Minimized",
    "/LoadConfig", $config,
    "/BackingFile", $backing
) -WindowStyle Hidden

# Give Procmon some time to capture data ⏳
Start-Sleep -Seconds 120

# Create a log file to store detected connections 📝
New-Item -Path C:\Sysinternals -Name "procLOGGED.txt" -ItemType "File" -Value " "

# Stop Procmon and export the log to CSV
& $procmon /Terminate | Out-Null
Start-Sleep -Seconds 1
& $procmon /OpenLog $backing /SaveAs $csvOut | Out-Null

# Check if CSV export was successful
if (!(Test-Path $csvOut)) {
    Write-Host "[ERROR] CSV export failed"
    exit
}

# Import CSV data for analysis 📊
$data = Import-Csv $csvOut

# Get all unique TCP connect targets
$targets = $data |
    Where-Object { $_.Operation -eq "TCP Connect" } |
    Select-Object -ExpandProperty Path -Unique

# Loop indefinitely to alert on new TCP connections 🔔
while ($true) {

    foreach ($t in $targets) {

        # Notify user of TCP connections
        msg * "Procmon Alert: TCP connect -> $t"
        Write-Host "[ALERT] TCP -> $t"

        # Log the detection with timestamp 🕒
        $d = Get-Date -Format "MM/dd/yyyy HH:mm K"
        Out-File -FilePath C:\procLOGGED.txt -Append -InputObject "$d detected TCP $t"
    }

    # Wait a bit before checking again
    Start-Sleep -Seconds 3
}

