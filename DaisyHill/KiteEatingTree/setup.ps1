#ps1

winrm quickconfig -quiet
winrm set winrm/config/service '@{AllowUnencrypted="true"}' # lol
