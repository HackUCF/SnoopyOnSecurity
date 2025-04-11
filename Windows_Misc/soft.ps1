# general log file
$logpath = "C:\Windows\Logs\log.txt"

# ip/cidr subnets for firewalling
$subnets = @()

# ccs directory (firewall exclusion)
$ccs = "C:\ccs"

## password changes
$usrlog = "C:\windows\logs\usr.log.txt"
net user >> $usrlog
net localgroup administrators >> $usrlog

## PowerShell Transcripts
mkdir c:\bob
reg ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d "C:\bob" /f

## firewall
# file to store original firewall state
$wflog = "C:\Windows\Logs\wf.log.txt"
Get-NetFirewallProfile >> $wflog
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True

$enabledrules = (Get-NetFirewallRule | Where -Property Enabled -eq True)
$enabledrules >> $wflog
$enabledrules | Disable-NetFirewallRule


## checks if FTP server, enable firewall rules for it if so.

if ((get-windowsfeature -name Web-Ftp-Server).installed -eq $true)
{
    ## Firewall Rules
	Enable-NetFirewallRule -DisplayGroup "FTP Server"   
	
    ## FTP backup
	Import-Module WebAdministration
	Get-ChildItem IIS:\Sites | Where-Object { $_.Bindings.Collection -match "ftp" } | % {cp -Path $_.PhysicalPath -Destination c:\ftp-backup -Recurse}
}

do {
    $subnet = read-host "enter subnet ip/cidr"
    if ($subnet -ne "") { $subnets += $subnet }
} while ($subnet -ne "")
New-NetFirewallRule -DisplayName "[ Subnet ]" -Direction Inbound -Protocol Any -Action Allow -RemoteAddress $subnets
New-NetFirewallRule -DisplayName "[ Subnet ]" -Direction Outbound -Protocol Any -Action Allow -RemoteAddress $subnets
New-NetFirewallRule -DisplayName "[ RDP ]" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 3389
New-NetFirewallRule -DisplayName "[ Ping ]" -Direction Inbound -Protocol ICMPv4 -Action Allow

if (test-path -path $ccs ) {
    gci -r $ccs | % {
        $path = $_.FullName
        New-NetFirewallRule -DisplayName "[ CCSClient  ]" -Direction Inbound -Protocol Any -Action Allow -Program $path
        New-NetFirewallRule -DisplayName "[ CCSClient  ]" -Direction Outbound -Protocol Any -Action Allow -Program $path
    }
}


$ports = @()
do {
    $port = read-host "enter inbound tcp port"
    if ($port -ne "") { $ports += $port }
} while ($port -ne "")
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName ("[ TCP $port ]") -Direction Inbound -Protocol TCP -Action Allow -LocalPort ([int]$port)
}

$ports = @()
do {
    $port = read-host "enter inbound udp port"
    if ($port -ne "") { $ports += $port }
} while ($port -ne "")
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName ("[ UDP $port ]") -Direction Inbound -Protocol UDP -Action Allow -LocalPort ([int]$port)
}


$btaIPs = @()
do {
    $btaIP = read-host "enter Blackteam IP"
    if ($btaIP-ne "") { $btaIPs += $btaIP }
} while ($btaIP -ne "")
foreach ($btaIP in $btaIPs) {
    New-NetFirewallRule -DisplayName ("[ BTA IP $btaIP ]") -Direction Outbound -Protocol any -Action Allow -RemoteAddress $btaIP
}

New-NetFirewallRule -DisplayName "[ Blackteam ]" -Direction Outbound -Protocol Any -Action Allow -RemoteAddress 10.120.0.111
New-NetFirewallRule -DisplayName "[ Proxy ]" -Direction Outbound -Protocol TCP -Action Allow -RemotePort 8080 -RemoteAddress 10.120.0.200
New-NetFirewallRule -DisplayName "[ Proxy ]" -Direction Outbound -Protocol UDP -Action Allow -RemotePort 8080 -RemoteAddress 10.120.0.200


Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block


if ((get-windowsfeature -name AD-Domain-Services).installed -eq $true)
{
    ## LDAP logging
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
    
    ## DNS backup
    mkdir C:\Windows\System32\dns\bob
    get-dnsserverzone | where -property isAutocreated -ne True | % { Export-DnsServerZone -Name $_.ZoneName -FileName "bob\$($_.ZoneName).dns"}
    dnscmd /exportsettings
}


## downloads

#Open firewall rule to allow web traffic
New-NetFirewallRule -DisplayName "bob1" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
New-NetFirewallRule -DisplayName "bob2" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow

[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Users\sysinternals.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Users\config.xml"
Invoke-WebRequest -Uri "https://www.voidtools.com/Everything-1.4.1.1005.x64.zip" -OutFile "C:/users/everything.zip"


Expand-Archive -Path "C:\Users\sysinternals.zip" -DestinationPath "C:\Users\sysinternals\" -Force
Expand-Archive -Path "C:\Users\everything.zip" -DestinationPath "C:\Users\everything\" -Force

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("C:\Users\sysinternals.zip", "C:\users\sysinternals")

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("C:\Users\everything.zip", "C:\users\everything")

## sysmon
C:\Users\sysinternals\sysmon.exe -accepteula -i C:\Users\config.xml

# Disable firewall rules
Get-NetFirewallRule | Where -Property DisplayName -match bob | Disable-NetFirewallRule

## password changes
$logpath = "C:\Windows\Logs\log.txt"
# default excluded users for password changes
$exc = @('krbtgt', 'blackteam_adm')

# Function to generate a random password meeting AD complexity requirements
function New-RandomPassword {
    param(
        [int]$length = 13,
        [string]$username
    )
    # Define character sets
    $upper   = 65..90 | ForEach-Object { [char]$_ }
    $lower   = 97..122 | ForEach-Object { [char]$_ }
    $digit   = 48..57 | ForEach-Object { [char]$_ }
    $special = "!", "@", "#", "$", "%", "^", "&", "*"
    $all     = $upper + $lower + $digit + $special
    
    $passwordChars = $username.ToCharArray()
    $passwordChars += @(
        Get-Random -InputObject $upper
        Get-Random -InputObject $lower
        Get-Random -InputObject $digit
        Get-Random -InputObject $special
    )
    while ($passwordChars.Count -lt $length) {
        $passwordChars += Get-Random -InputObject $lower
    }
    return -join $passwordChars
}

$rand = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})
$usrlog = "C:\windows\logs\usr.log-$rand.txt"
$usrsheet = "C:\windows\logs\usr.sheet-$rand.txt"
net user >> $usrlog
net localgroup administrators >> $usrlog
clear-variable pass 2>$null
do {
    if ((get-variable pass 2>$null).Value -ne $null) {
        echo "passwords must match"
    }
    $pass = Read-Host "password 1"
    $pass2 = Read-Host "password 2"
} while ($pass -ne $pass2)
do {
    $name = read-host "exclude a user"
    if ($name -ne "") { $exc += $name }
} while ($name -ne "")
get-wmiobject -class win32_useraccount | % {
    if (($_.name -notin $exc) -and ($_.name -notlike "*$")) {
        add-content -path $logpath -value ("password changed for " + $_.name)
        if ($_.name -eq $env:USERNAME) {
            net user $_.name $pass
        } else {
            $randpass = New-RandomPassword
            echo "$($_.Name),$randpass" >> $usrsheet
            net user $_.name "`"$randpass`""
        }
    }
}
clear-variable pass
clear-variable pass2

## uac
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 4

## smbv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

## ps transcripts
New-Item -Path $profile.AllUsersCurrentHost -Type File -Force
$content = @'
$path       = "C:\Windows\Logs\"
$username   = $env:USERNAME
$hostname   = hostname
$datetime   = Get-Date -f 'MM/dd-HH:mm:ss'
$filename   = "transcript-${username}-${hostname}-${datetime}.txt"
$Transcript = Join-Path -Path $path -ChildPath $filename
Start-Transcript
'@
set-content -path $profile.AllUsersCurrentHost -value $content -force


## Disable scheduled tasks

get-scheduledtask | disable-scheduledtask

## Enable NLA

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1


echo ' param(' > C:\Users\pii.ps1
echo '     [Parameter(Mandatory=$false)]' >> C:\Users\pii.ps1
echo '     [String[]]$Path = "C:\"' >> C:\Users\pii.ps1
echo ' )' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo ' $ErrorActionPreference = "SilentlyContinue"' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo ' $Directory = "C:\Windows\Logs"' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo ' if (-not (Test-Path $Directory)) {' >> C:\Users\pii.ps1
echo '     New-Item -ItemType Directory -Path $Directory' >> C:\Users\pii.ps1
echo ' }' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo ' $patterns = ' >> C:\Users\pii.ps1
echo "     '\b\d{3}[)]?[-| |.]\d{3}[-| |.]\d{4}\b', " >> C:\Users\pii.ps1
echo "     '\b\d{3}[-| |.]\d{2}[-| |.]\d{4}\b'," >> C:\Users\pii.ps1
echo "     '\b\d+\s+[\w\s]+\s+(?:road|street|avenue|boulevard|court|ave|st|blvd|cir|circle)\b'," >> C:\Users\pii.ps1
echo "     '\b(?:\d{4}[-| ]?){3}\d{4}\b'" >> C:\Users\pii.ps1
echo ' $fileExtensions = "\.docx|\.doc|\.odt|\.xlsx|\.xls|\.ods|\.pptx|\.ppt|\.odp|\.pdf|\.mdb|\.accdb|\.sqlite3?|\.eml|\.msg|\.txt|\.csv|\.html?|\.xml|\.json"' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo ' Get-ChildItem -Recurse -Force -Path $Path | Where-Object { $_.Extension -match $fileExtensions } | ForEach-Object {' >> C:\Users\pii.ps1
echo '     $piiMatches = Select-String -Path $_.FullName -Pattern $patterns -AllMatches | Select-Object -ExpandProperty Matches' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo '     if ($piiMatches.Count -ge 20) {' >> C:\Users\pii.ps1
echo '         "PII found in $($_.FullName)" | Out-File -FilePath "$Directory\pii.ttu.log.txt" -Append' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo '         $piiMatches |' >> C:\Users\pii.ps1
echo '             Sort-Object Value -Unique |' >> C:\Users\pii.ps1
echo '             ForEach-Object { $_.Value } |' >> C:\Users\pii.ps1
echo '             Out-File -FilePath "$Directory\pii.txt" -Append' >> C:\Users\pii.ps1
echo ' ' >> C:\Users\pii.ps1
echo '     }' >> C:\Users\pii.ps1
echo ' }' >> C:\Users\pii.ps1

echo ' param ([switch]$d)' > C:\Users\audit.ps1
echo ' ' >> C:\Users\audit.ps1
echo ' $intended = Get-Content users.txt' >> C:\Users\audit.ps1
echo ' ' >> C:\Users\audit.ps1
echo ' $intended += @("krbtgt", "blackteam_adm", "administrator", "wdagutility")' >> C:\Users\audit.ps1
echo ' ' >> C:\Users\audit.ps1
echo ' echo $intended' >> C:\Users\audit.ps1
echo ' ' >> C:\Users\audit.ps1
echo ' Get-ADUser -Filter * | % {if ($_.name -notin $intended) { if ($d) { echo "disabled $_.name" >> Disabled.txt; net user $_.name /active:no } else { echo "not intended $_.name" >> NotIntended.txt  } } }' >> C:\Users\audit.ps1


# Generate password change script
$filepath = 'C:\Users\pass.ps1'
if (!(Test-Path $filepath)) {
    New-Item -Path $filepath -ItemType File -Force | Out-Null
}
$scriptContent = @'
## password changes
$logpath = "C:\Windows\Logs\log.txt"
# default excluded users for password changes
$exc = @('krbtgt', 'blackteam_adm')

# Function to generate a random password meeting AD complexity requirements
function New-RandomPassword {
    param(
        [int]$length = 13,
        [string]$username
    )
    # Define character sets
    $upper   = 65..90 | ForEach-Object { [char]$_ }
    $lower   = 97..122 | ForEach-Object { [char]$_ }
    $digit   = 48..57 | ForEach-Object { [char]$_ }
    $special = "!", "@", "#", "$", "%", "^", "&", "*"
    $all     = $upper + $lower + $digit + $special
    
    $passwordChars = $username.ToCharArray()
    $passwordChars += @(
        Get-Random -InputObject $upper
        Get-Random -InputObject $lower
        Get-Random -InputObject $digit
        Get-Random -InputObject $special
    )
    while ($passwordChars.Count -lt $length) {
        $passwordChars += Get-Random -InputObject $lower
    }
    return -join $passwordChars
}

$rand = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})
$usrlog = "C:\windows\logs\usr.log-$rand.txt"
$usrsheet = "C:\windows\logs\usr.sheet-$rand.txt"
net user >> $usrlog
net localgroup administrators >> $usrlog
clear-variable pass 2>$null
do {
    if ((get-variable pass 2>$null).Value -ne $null) {
        echo "passwords must match"
    }
    $pass = Read-Host "password 1"
    $pass2 = Read-Host "password 2"
} while ($pass -ne $pass2)
do {
    $name = read-host "exclude a user"
    if ($name -ne "") { $exc += $name }
} while ($name -ne "")
get-wmiobject -class win32_useraccount | % {
    if (($_.name -notin $exc) -and ($_.name -notlike "*$")) {
        add-content -path $logpath -value ("password changed for " + $_.name)
        if ($_.name -eq $env:USERNAME) {
            net user $_.name $pass
        } else {
            $randpass = New-RandomPassword
            echo "$($_.Name),$randpass" >> $usrsheet
            net user $_.name "`"$randpass`""
        }
    }
}
clear-variable pass
clear-variable pass2
'@
Set-Content -Path $filepath -Value $scriptContent

Start-Job -FilePath "C:\Users\pii.ps1" -Name "PiiJob"


if (-not [System.IO.File]::Exists("C:\Users\users.txt")){
    New-Item C:\Users\users.txt -ItemType file
}

## Create salt.ps1

echo ' $masterIP = Read-Host "Enter Salt Master IP (press Enter to skip Salt Minion install)"' > C:\Users\salt.ps1
echo '     New-NetFirewallRule -DisplayName "bob1" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow' >> C:\Users\salt.ps1
echo '     New-NetFirewallRule -DisplayName "bob2" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow' >> C:\Users\salt.ps1
echo '     [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1
echo '     # Download Salt Minion MSI' >> C:\Users\salt.ps1
echo '     $msiUrl = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/3007.1/Salt-Minion-3007.1-Py3-AMD64.msi"' >> C:\Users\salt.ps1
echo '     $output = "salt.msi"' >> C:\Users\salt.ps1
echo '     Write-Host "Downloading Salt Minion installer..."' >> C:\Users\salt.ps1
echo '     Invoke-WebRequest -Uri $msiUrl -OutFile $output' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1
echo '     # Install Salt Minion' >> C:\Users\salt.ps1
echo '     Write-Host "Installing Salt Minion..."' >> C:\Users\salt.ps1
echo '     Start-Process msiexec -ArgumentList "/i $output /qn MASTER=$masterIP /L*V install.log" -Wait' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1
echo '     # Add firewall rules' >> C:\Users\salt.ps1
echo '     Write-Host "Adding firewall rule for Salt Minion..."' >> C:\Users\salt.ps1
echo '     New-NetFirewallRule -DisplayName "Allow Outbound to Salt-Master" `' >> C:\Users\salt.ps1
echo '         -Direction Outbound -Action Allow -Protocol TCP `' >> C:\Users\salt.ps1
echo '         -RemotePort 4505,4506 -Profile Any -RemoteAddress $masterIP' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1
echo '     Write-Host "Salt Minion installation complete."' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1
echo '     Get-NetFirewallRule | Where -Property DisplayName -match bob | Disable-NetFirewallRule' >> C:\Users\salt.ps1
echo ' ' >> C:\Users\salt.ps1


## Makes simplewall script


echo ' # ---------------------------Firewall OPEN------------------------------' > c:\Users\simple.ps1
echo ' # Add THE BOB rules to allow the current machine to reach the internet' >> c:\Users\simple.ps1
echo ' New-NetFirewallRule -DisplayName "[ BOB1-sw ]" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow' >> c:\Users\simple.ps1
echo ' New-NetFirewallRule -DisplayName "[ BOB2-sw ]" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow' >> c:\Users\simple.ps1
echo ' [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3" ' >> c:\Users\simple.ps1
echo ' # -----------------------------Download---------------------------------' >> c:\Users\simple.ps1
echo ' # SimpleWall download URL' >> c:\Users\simple.ps1
echo ' $downloadUrl = "https://github.com/henrypp/simplewall/releases/download/v.3.8.5/simplewall-3.8.5-setup.exe"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Destination path for SimpleWall download' >> c:\Users\simple.ps1
echo ' $destinationPath = "C:\Program Files\simplewall-3.8.5-setup.exe"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Download SimpleWall' >> c:\Users\simple.ps1
echo ' Invoke-WebRequest -Uri $downloadUrl -OutFile $destinationPath' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Confirm download' >> c:\Users\simple.ps1
echo ' Write-Host "SimpleWall has been downloaded to $destinationPath"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # ------------------------------SETUP-----------------------------------' >> c:\Users\simple.ps1
echo ' # Run SimpleWall Setup' >> c:\Users\simple.ps1
echo ' Start-Process -FilePath $destinationPath -ArgumentList "/S" -Verb RunAs -Wait' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Remove SimpleWall Uninstall' >> c:\Users\simple.ps1
echo ' $uninstallExe = "C:\Program Files\simplewall\uninstall.exe"' >> c:\Users\simple.ps1
echo ' Remove-Item -Path $uninstallExe -Force -Confirm:$false' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Clean Up Artifacts' >> c:\Users\simple.ps1
echo ' Remove-Item -Path $destinationPath -Force -Confirm:$false' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Confirm Setup' >> c:\Users\simple.ps1
echo ' Write-Host "SimpleWall is installed"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # -------------------------------RUN------------------------------------' >> c:\Users\simple.ps1
echo ' # Run SimpleWall Executable -- DO NOT FULLY AUTOMATE THIS AS CLICKING "ENABLE FIREWALL" NEEDS TO BE A CONSCIOUS USER DECISION' >> c:\Users\simple.ps1
echo ' $simpleWallExe = "C:\Program Files\simplewall\simplewall.exe"' >> c:\Users\simple.ps1
echo ' Start-Process -FilePath $simpleWallExe -Verb RunAs' >> c:\Users\simple.ps1
echo ' Start-Sleep -Seconds 5' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # ------------------------------RULES-----------------------------------' >> c:\Users\simple.ps1
echo ' # Define the path to your XML file in the AppData folder' >> c:\Users\simple.ps1
echo ' $xmlPath = Join-Path -Path $env:APPDATA -ChildPath "Henry++\simplewall\profile.xml"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Define the URL of the profile.xml file on GitHub' >> c:\Users\simple.ps1
echo ' $githubUrl = "https://raw.githubusercontent.com/HackUCF/SnoopyOnSecurity/refs/heads/main/Windows_Misc/profile.xml"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Define a temporary path for downloading the file' >> c:\Users\simple.ps1
echo ' $tempPath = Join-Path -Path $env:TEMP -ChildPath "profile.xml"' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Download the profile.xml file from GitHub' >> c:\Users\simple.ps1
echo ' Invoke-WebRequest -Uri $githubUrl -OutFile $tempPath' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Replace the existing profile.xml file with the downloaded one' >> c:\Users\simple.ps1
echo ' if (Test-Path -Path $xmlPath) {' >> c:\Users\simple.ps1
echo '     Remove-Item -Path $xmlPath -Force' >> c:\Users\simple.ps1
echo ' }' >> c:\Users\simple.ps1
echo ' Move-Item -Path $tempPath -Destination $xmlPath' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' Write-Host "Custom rules have been updated with the new profile.xml file."' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # Restart the SimpleWall process (Reload with Custom Rules)' >> c:\Users\simple.ps1
echo ' Stop-Process -Name "simplewall" -Force' >> c:\Users\simple.ps1
echo ' Start-Process -FilePath $simpleWallExe -Verb RunAs' >> c:\Users\simple.ps1
echo ' ' >> c:\Users\simple.ps1
echo ' # --------------------------Firewall CLOSE------------------------------' >> c:\Users\simple.ps1
echo ' # Disable THE BOB firewall rules to seal back off outbound traffic' >> c:\Users\simple.ps1
echo ' Get-NetFirewallRule | Where -Property DisplayName -match BOB | Disable-NetFirewallRule' >> c:\Users\simple.ps1


## Makes hollow_hunter downloader

echo ' ##download hollows_hunter' > c:\Users\hollow.ps1
echo ' ' >> c:\Users\hollow.ps1
echo ' New-NetFirewallRule -DisplayName "bob1" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow' >> c:\Users\hollow.ps1
echo ' New-NetFirewallRule -DisplayName "bob2" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow' >> c:\Users\hollow.ps1
echo ' [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"' >> c:\Users\hollow.ps1
echo ' ' >> c:\Users\hollow.ps1
echo ' wget https://github.com/hasherezade/hollows_hunter/releases/download/v0.4.1/hollows_hunter64.exe -outfile hunter.exe' >> c:\Users\hollow.ps1
echo ' ' >> c:\Users\hollow.ps1
echo ' Get-NetFirewallRule | Where -Property DisplayName -match bob | Disable-NetFirewallRule' >> c:\Users\hollow.ps1

## Make malwarebytes getter

echo ' ##download hollows_hunter' > c:\Users\hollow.ps1
echo ' ' >> c:\Users\hollow.ps1
echo ' New-NetFirewallRule -DisplayName "bob1" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow' >> c:\Users\mbam.ps1
echo ' New-NetFirewallRule -DisplayName "bob2" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow' >> c:\Users\mbam.ps1
echo ' [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"' >> c:\Users\mbam.ps1
echo ' ' >> c:\Users\mbam.ps1
echo ' wget https://downloads.malwarebytes.com/file/mb4_offline -outfile mbam.exe' >> c:\Users\mbam.ps1
echo ' ' >> c:\Users\mbam.ps1
echo ' Get-NetFirewallRule | Where -Property DisplayName -match bob | Disable-NetFirewallRule' >> c:\Users\mbam.ps1

# Prompt for Salt Master IP
$masterIP = Read-Host "Enter Salt Master IP (press Enter to skip Salt Minion install)"

if (-not [string]::IsNullOrWhiteSpace($masterIP)) {
    
    New-NetFirewallRule -DisplayName "bob1" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow
    New-NetFirewallRule -DisplayName "bob2" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow
    [Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12, Ssl3"

    # Download Salt Minion MSI
    $msiUrl = "https://packages.broadcom.com/artifactory/saltproject-generic/windows/3007.1/Salt-Minion-3007.1-Py3-AMD64.msi"
    $output = "salt.msi"
    Write-Host "Downloading Salt Minion installer..."
    Invoke-WebRequest -Uri $msiUrl -OutFile $output

    # Install Salt Minion
    Write-Host "Installing Salt Minion..."
    Start-Process msiexec -ArgumentList "/i $output /qn MASTER=$masterIP /L*V install.log" -Wait

    # Add firewall rules
    Write-Host "Adding firewall rule for Salt Minion..."
    New-NetFirewallRule -DisplayName "Allow Outbound to Salt-Master" `
        -Direction Outbound -Action Allow -Protocol TCP `
        -RemotePort 4505,4506 -Profile Any -RemoteAddress $masterIP

    Write-Host "Salt Minion installation complete."

    Get-NetFirewallRule | Where -Property DisplayName -match bob | Disable-NetFirewallRule

}

## sticky keys
$hash = get-filehash C:\Windows\System32\cmd.exe
echo $hash
$hash3 = get-filehash C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
echo $hash3
gci -r C:\Windows\system32\ | % {
    $path = $_.fullname
    $hash2 = get-filehash $path 2>$null
    if (($hash.Hash -eq $hash2.Hash -and $hash.path -ne $hash2.path) -or ($hash3.Hash -eq $hash2.Hash -and $hash3.path -ne $hash3.path) ) {
        add-content -path $logpath -value ("sticky keys caught:`t" + $path)
        takeown /f $path
        icacls $path /grant everyone:F
        mv $path ($path + '.bak')
    }
}


## pii
Start-Job -ScriptBlock {
    $piilog = "C:\Windows\Logs\pii.ucf.log.txt"
    $regex = @("^[\+]?[(]?[0-9]{3}[)]?[-\s\.][0-9]{3}[-\s\.][0-9]{4,6}$", "(^4[0-9]{12}(?:[0-9]{3})?$)|(^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$)|(3[47][0-9]{13})|(^3(?:0[0-5]|[68][0-9])[0-9]{11}$)|(^6(?:011|5[0-9]{2})[0-9]{12}$)|(^(?:2131|1800|35\d{3})\d{11}$)")
    $ErrorActionPreference = "SilentlyContinue"
    gci -r "C:\users\" | % {
        $path = $_.fullname
        $str = (C:\users\sysinternals\strings.exe -nobanner -accepteula -n 8 $path)
        foreach ($ex in $regex) {
            if ($str -match $ex) {
                $time = Get-Date -f 'MM/dd-HH:mm:ss'
                add-content -path $piilog -value ($time + "pii caught:`t" + $path)
            }
        }
    }
}
