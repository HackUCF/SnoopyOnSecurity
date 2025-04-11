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

# services backup
reg export "HKLM\SYSTEM\CurrentControlSet\Services" C:\bob\service.reg /y

## firewall
# file to store original firewall state
$wflog = "C:\Windows\Logs\wf.log.txt"
Get-NetFirewallProfile >> $wflog
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow
Set-NetFirewallProfile -All -LogAllowed True -LogBlocked True

$enabledrules = (Get-NetFirewallRule | Where -Property Enabled -eq True)
$enabledrules >> $wflog
$enabledrules | Disable-NetFirewallRule

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
        New-NetFirewallRule -DisplayName "[ BTA ]" -Direction Inbound -Protocol Any -Action Allow -Program $path
        New-NetFirewallRule -DisplayName "[ BTA ]" -Direction Outbound -Protocol Any -Action Allow -Program $path
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

$ports = @()
do {
    $port = read-host "enter outbound udp port"
    if ($port -ne "") { $ports += $port }
} while ($port -ne "")
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName ("[ UDP $port ]") -Direction Outbound -Protocol UDP -Action Allow -LocalPort ([int]$port)
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

Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -UseBasicParsing -OutFile "C:\Users\sysinternals.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -UseBasicParsing -OutFile "C:\Users\config.xml"
Invoke-WebRequest -Uri "https://www.voidtools.com/Everything-1.4.1.1005.x64.zip" -UseBasicParsing -OutFile "C:/users/everything.zip"

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

$usrlog = "C:\windows\logs\usr.log.txt"
net user >> $usrlog
net localgroup administrators >> $usrlog
clear-variable pass 2>$null
do {
    if((get-variable pass 2>$null).Value -ne $null) {
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
        net user $_.name $pass
    }
}
clear-variable pass
clear-variable pass2

# backup user
$name = read-host "backup username"
do {
    if((get-variable pass 2>$null).Value -ne $null) {
        echo "passwords must match"
    }
    $pass = Read-Host "backup password 1"
    $pass2 = Read-Host "backup password 2"
} while ($pass -ne $pass2)
net user $name $pass /add
net localgroup administrators $name /add
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

echo ' ## password changes' > C:\Users\pass.ps1
echo ' $logpath = "C:\Windows\Logs\log.txt"' >> C:\Users\pass.ps1
echo ' # default excluded users for password changes' >> C:\Users\pass.ps1
echo ' $exc = @("krbtgt", "blackteam_adm")' >> C:\Users\pass.ps1
echo ' ' >> C:\Users\pass.ps1
echo ' $usrlog = "C:\windows\logs\usr.log.txt"' >> C:\Users\pass.ps1
echo ' net user >> $usrlog' >> C:\Users\pass.ps1
echo ' net localgroup administrators >> $usrlog' >> C:\Users\pass.ps1
echo ' clear-variable pass 2>$null' >> C:\Users\pass.ps1
echo ' do {' >> C:\Users\pass.ps1
echo '     if((get-variable pass 2>$null).Value -ne $null) {' >> C:\Users\pass.ps1
echo '         echo "passwords must match"' >> C:\Users\pass.ps1
echo '     }' >> C:\Users\pass.ps1
echo '     $pass = Read-Host "password 1"' >> C:\Users\pass.ps1
echo '     $pass2 = Read-Host "password 2"' >> C:\Users\pass.ps1
echo ' } while ($pass -ne $pass2)' >> C:\Users\pass.ps1
echo ' do {' >> C:\Users\pass.ps1
echo '     $name = read-host "exclude a user"' >> C:\Users\pass.ps1
echo '     if ($name -ne "") { $exc += $name }' >> C:\Users\pass.ps1
echo ' } while ($name -ne "")' >> C:\Users\pass.ps1
echo ' get-wmiobject -class win32_useraccount | % {' >> C:\Users\pass.ps1
echo '     if (($_.name -notin $exc) -and ($_.name -notlike "*$")) {' >> C:\Users\pass.ps1
echo '         add-content -path $logpath -value ("password changed for " + $_.name)' >> C:\Users\pass.ps1
echo '         net user $_.name $pass' >> C:\Users\pass.ps1
echo '     }' >> C:\Users\pass.ps1
echo ' }' >> C:\Users\pass.ps1
echo ' clear-variable pass' >> C:\Users\pass.ps1
echo ' clear-variable pass2' >> C:\Users\pass.ps1


Start-Job -FilePath "C:\Users\pii.ps1" -Name "PiiJob"


if (-not [System.IO.File]::Exists("C:\Users\users.txt")){
    New-Item C:\Users\users.txt -ItemType file
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
