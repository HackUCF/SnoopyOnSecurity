#ps1

# services backup
reg export "HKLM\SYSTEM\CurrentControlSet\Services" C:\service.reg /y


if ((get-windowsfeature -name AD-Domain-Services).installed -eq $true)
{
    ## LDAP logging
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "Expensive Search Results Threshold" /t REG_DWORD /d 1 /f
    
    ## DNS backup
    mkdir C:\Windows\System32\dns\bob
    get-dnsserverzone | where -property isAutocreated -ne True | % { Export-DnsServerZone -Name $_.ZoneName -FileName "bob\$($_.ZoneName).dns"}
    dnscmd /exportsettings

    # ad users
    get-adgroup -filter * | % { echo $_.Name; Get-ADGroupMember -Identity $_.Name | ft name,objectclass } >> C:\adusers.txt
}

# powershell logging72
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d "*" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\LogFiles\PowerShell" /f


## uac
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 4

## smbv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

## Disable scheduled tasks
get-scheduledtask | stop-scheduledtask
get-scheduledtask | disable-scheduledtask

write-host "Services"
netstat -onab > C:\users\netstat.txt

Get-LocalGroup | % { $localgroup = Get-LocalGroupMember -Group $_.Name; if($localgroup -ne $null) { echo $_.Name; $localgroup | ft Name, ObjectClass -AutoSize } else { echo $_.Name "^ EMPTY"}  } > C:\users\users.txt


