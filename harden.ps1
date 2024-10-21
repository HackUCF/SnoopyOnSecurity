# general log file
$logpath = "C:\Windows\Logs\log.txt"

# ip/cidr subnets for firewalling
$subnets = @()

# default excluded users for password changes
$exc = @('krbtgt')

# ccsclient directory (firewall exclusion)
$ccs = "C:\ccs"

## downlaods
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Users\sysinternals.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Users\config.xml"
Invoke-WebRequest -Uri "https://www.voidtools.com/Everything-1.4.1.1005.x64.zip" -OutFile "C:/users/everything.zip"

Expand-Archive -Path "C:\Users\sysinternals.zip" -DestinationPath "C:\Users\sysinternals\" -Force
Expand-Archive -Path "C:\Users\everything.zip" -DestinationPath "C:\Users\everything\" -Force

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
New-NetFirewallRule -DisplayName "[ WinRM ]" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 5985

New-NetFirewallRule -DisplayName "[ Ping ]" -Direction Inbound -Protocol ICMPv4 -Action Allow

if (test-path -path $ccs ) {
    gci -r $ccs | % {
        $path = $_.FullName
        New-NetFirewallRule -DisplayName "[ CCSClient ]" -Direction Inbound -Protocol Any -Action Allow -Program $path
        New-NetFirewallRule -DisplayName "[ CCSClient ]" -Direction Outbound -Protocol Any -Action Allow -Program $path
    }
}

$ports = @()
do {
    $port = read-host "enter tcp port"
    if ($port -ne "") { $ports += $port }
} while ($port -ne "")
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName ("[ TCP $port ]") -Direction Inbound -Protocol TCP -Action Allow -LocalPort ([int]$port)
}

$ports = @()
do {
    $port = read-host "enter udp port"
    if ($port -ne "") { $ports += $port }
} while ($port -ne "")
foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName ("[ UDP $port ]") -Direction Inbound -Protocol UDP -Action Allow -LocalPort ([int]$port)
}

Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block

## password changes
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

get-localuser | % {
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

## winrm (wierd port)
winrm quickconfig -quiet
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

## smbv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

## sticky keys
$hash = get-filehash C:\Windows\System32\cmd.exe
echo $hash
gci -r -depth 1 C:\Windows\system32\ | % {
    $path = $_.fullname
    $hash2 = get-filehash $path 2>$null
    if ($hash.Hash -eq $hash2.Hash -and $hash.path -ne $hash2.path) {
        add-content -path $logpath -value ("sticky keys caught:`t" + $path)
        takeown /f $path
        icacls $path /grant everyone:F
        mv $path ($path + '.bak')
    }
}

## sysmon
C:\Users\sysinternals\sysmon.exe -accepteula -i C:\Users\config.xml

## pii
Start-Job -ScriptBlock {
    $piilog = "C:\Windows\Logs\pii.log.txt"
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