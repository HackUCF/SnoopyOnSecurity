#ps1
New-Service -Name "otel" -BinaryPathName 'C:\otel\otelcol-contrib.exe --config=C:\otel\otel-config.yaml'
Set-Service -Name otel -StartupType Automatic
Start-Service otel
