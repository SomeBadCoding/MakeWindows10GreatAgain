# Check to see if Anniversary Update is installed
if ([System.Environment]::OSVersion.Version.Build -lt 14393) {
  Write-Host "Anniversary Update is required and not installed. Exiting."
  Exit
}

# Import the registry keys
Write-Host "Importing registry keys..."
regedit /s MakeWindows10GreatAgain.reg

# Install Powershell Help items
Update-Help -Force -ErrorAction SilentlyContinue

# Remove OneDrive from the System
taskkill /f /im OneDrive.exe
c:\Windows\SysWOW64\OneDriveSetup.exe /uninstall

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false

# Install Linux Subsystem
Write-Host "Installing the Linux Subsystem..."
Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux"

# Disable WPAD 
# https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077#workarounds
Add-Content "c:\windows\system32\drivers\etc\hosts" "        255.255.255.255  wpad."

# Disable SSL 2.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null

# Disable SSl 3.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name "DisabledByDefault" -Value "00000001" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name "Enabled" -Value "00000000" 

# Disable TLS 1.0
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null

##### Disable RC4 Protocols##### 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name "Enabled" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -Name "Enabled" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -Name "Enabled" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168' -Name "Enabled" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' -Name "Enabled" -Value "00000000" 

# Disable Weak Ciphers
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

# To enable mitigations for CVE-2018-3639 (Speculative Store Bypass), default mitigations for CVE-2017-5715 (Spectre Variant 2) and CVE-2017-5754 (Meltdown)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 8 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

# Disable Autoplay
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
New-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name "NoDriveTypeAutoRun" -Value "00000255" -PropertyType "DWord" 
Set-ItemProperty -Path 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value "00000001" 

# Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue

# Disable built-in Adobe Flash in IE and Edge
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
	
# Uninstall Internet Explorer
Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Disable P2P Update downloads outside of local network
Set-ItemProperty  "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name DODownloadMode -Type DWORD  -Value 0 -Force -ErrorAction SilentlyContinue |out-null
Set-ItemProperty  "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name SendTrustedIssuerList -Type DWORD  -Value 0 -Force -ErrorAction SilentlyContinue |out-null

#Windows Registry Setting To Globally Prevent Socket Hijacking Missing
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' -Name "ForceActiveDesktopOn" -Value "00000001" 

#Disables Cached Logon Credential
Set-ItemProperty -Path 'hklm:\Software\Microsoft\Windows Nt\CurrentVersion\Winlogon' -Name "CachedLogonsCount" -Value "0" 

#Remove Hello-Face
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart

#Restrict Null Sessions
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\LSA' -Name "RestrictAnonymous" -Value "00000001" 
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\LSA' -Name "everyoneincludesanonymous" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name "ForceActiveDesktopOn" -Value "00000000" 
Set-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name "NoActiveDesktopChanges" -Value "00000001" 
Set-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name "NoActiveDesktop" -Value "00000001" 
Set-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name "ShowSuperHidden" -Value "00000001" 

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

#No more forced updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f

#No license checking
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
#Disable sync
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f

#No Windows Tips
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f

# Block Certain Applications from Outbound Connections
NetSh Advfirewall set allprofiles state on
Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any

# Enable Local Windows Firewall Logging
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

Write-Host "Remove Apps"

# Remove Default Apps
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage "maps" | Remove-AppxPackage
Get-AppxPackage "alarms" | Remove-AppxPackage
Get-AppxPackage "people" | Remove-AppxPackage

# Unistall 3rd Party Apps
Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage

# Block Microsoft Domains

Write-Host "Edit Local Hosts"

$file = "C:\Windows\System32\drivers\etc\hosts"
"127.0.0.1 vortex-win.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 redir.metaservices.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 reports.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 services.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.ppe.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.urs.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net:443" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 settings-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex-win.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 redir.metaservices.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 settings-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 reports.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.ppe.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.urs.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 survey.watson.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.live.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 services.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex-win.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telecommand.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 oca.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.telemetry.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 redir.metaservices.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 choice.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 reports.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 services.wes.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 sqm.df.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.ppe.telemetry.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.urs.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 telemetry.appex.bing.net:443" | Out-File -encoding ASCII -append $file
"127.0.0.1 settings-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 vortex-sandbox.data.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 survey.watson.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.live.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 watson.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 statsfe2.ws.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 corpext.msitadfs.glbdns2.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 compatexchange.cloudapp.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 cs1.wpc.v0cdn.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0001.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0002.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0003.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0004.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0005.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0006.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0007.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0008.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-0009.a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 a-msedge.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 statsfe2.update.microsoft.com.akadns.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 sls.update.microsoft.com.akadns.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 fe2.update.microsoft.com.akadns.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 diagnostics.support.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 corp.sts.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 statsfe1.ws.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 pre.footprintpredict.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 i1.services.social.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 i1.services.social.microsoft.com.nsatc.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 feedback.windows.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 feedback.microsoft-hohm.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 feedback.search.microsoft.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 live.rads.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 ads1.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 static.2mdn.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 g.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 a.ads2.msads.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 b.ads2.msads.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 ad.doubleclick.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 ac3.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 rad.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 msntest.serving-sys.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 bs.serving-sys.com1" | Out-File -encoding ASCII -append $file
"127.0.0.1 flex.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 ec.atdmt.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 cdn.atdmt.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 db3aqu.atdmt.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 cds26.ams9.msecn.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 sO.2mdn.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 aka-cdn-ns.adtech.de" | Out-File -encoding ASCII -append $file
"127.0.0.1 secure.flashtalking.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 adnexus.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 adnxs.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 *.rad.msn.com" | Out-File -encoding ASCII -append $file
"127.0.0.1 *.msads.net" | Out-File -encoding ASCII -append $file
"127.0.0.1 *.msecn.net" | Out-File -encoding ASCII -append $file

Write-Host "Complete"
