#Sysmon설치 전 기본환경변수 가져오
$currentUserName = $env:USERNAME
Write-Host "current user :$currentUserName"

# desktop path
$outputDirectory = "C:\Users\$currentUserName\Desktop"
Write-Host "outputDirectory: $outputDirectory"

#user path
Write-Host "Getting Desktop path for the current user..."
$desktopPath = Join-Path $env:USERPROFILE 'Desktop'
Write-Host "desktop path: $desktopPath"
$ThisDesktop = $desktopPath

#사용자 암호 설정
function Test-PasswordComplexity {
    param (
        [string]$Password
    )

    $UpperCaseRegex = '[A-Z]'
    $LowerCaseRegex = '[a-z]'
    $DigitRegex = '[0-9]'
    $SpecialCharacterRegex = '[^\w\s]'

    $UpperMatch = $Password -match $UpperCaseRegex
    $LowerMatch = $Password -match $LowerCaseRegex
    $DigitMatch = $Password -match $DigitRegex
    $SpecialMatch = $Password -match $SpecialCharacterRegex

    return ($UpperMatch -and $LowerMatch -and $DigitMatch -and $SpecialMatch -and $Password.Length -ge 8)
}
do {
    $NewPassword = Read-Host "새로운 암호를 입력하세요" -AsSecureString
    $NewPasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))
    $PasswordValid = Test-PasswordComplexity -Password $NewPasswordPlainText
    if (-not $PasswordValid) {
        Write-Host "입력한 암호가 조건을 충족하지 않습니다. 다시 입력하세요."
    }
} until ($PasswordValid)
Set-LocalUser -Name $currentUserName -Password (ConvertTo-SecureString -String $NewPasswordPlainText -AsPlainText -Force)

net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /uniquepw:24

#파일 시스템 FAT32일 경우 NTFS포멧으로 설정
# Step 1: NTFS CHECK
$diskVolumes = Get-WmiObject -Class Win32_Volume -Filter "DriveType = 3"
$nonNTFSDrives = @()
foreach ($volume in $diskVolumes) {
    if ($volume.FileSystem -ne "NTFS") {
        $nonNTFSDrives += $volume.DriveLetter
    }
}
# Step 2&3: Convert non-NTFS drives to NTFS
foreach ($drive in $nonNTFSDrives) {
    $cmdCommand = "cmd /c convert $drive /fs:ntfs"
    Invoke-Expression -Command $cmdCommand
}

#Windows Messenger(MSN, .NET 메신저 등)와 같은 상용 메신저 사용 금지
$registryPath="HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
$registryName="PreventRun"
$registryValue=1
if(Test-Path $registryPath){
		New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType DWord -Force
		Get-ItemProperty -Path $registryPath -Name $registryName
}
else{
		Write-Host "Messenger 레지스트리 경로가 존재하지 않습니다."
}

#화면보호기 대기 시간 설정 및 재시작 시 암호 보호 설
$timeoutInSeconds = 600
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value $timeoutInSeconds -PropertyType DWord -Force
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1 -PropertyType DWord -Force

#브라우저 종료 시 임시 인터넷 파일 폴더의 내용 삭제
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache"
$regName = "Persistent"
$regValue = 0
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force

#WINDOWS DEFENDER 실시간 감시 기능 활성화
Set-MpPreference -DisableRealtimeMonitoring $false

#OS에서 제공하는 침입 차단 기능 활성화
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
$regName = "EnableFirewall"
$regValue = 1
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force

#이동식 미디어의 자동실행 방지
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$regName = "NoDriveTypeAutoRun"
$regValue = 255
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force

#윈도우 복구 콘솔 자동 로그인 설정 금지
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole"
$regName = "SecurityLevel"
$regValue = 0
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWord -Force

#과기정통부, KISA기반 주요정보통신기관의 불필요 서비스 비활성화
Stop-Service -Name "ClipSVC" -Force
Stop-Service -Name "CryptSvc" -Force
Stop-Service -Name "TrkWks" -Force
Stop-Service -Name "TrustedInstaller" -Force
Stop-Service -Name "HidServ" -Force
Stop-Service -Name "Spooler" -Force
Stop-Service -Name "RemoteRegistry" -Force
Stop-Service -Name "TermService" -Force
Stop-Service -Name "DiagTrack" -Force
Stop-Service -Name "lfsvc" -Force
Stop-Service -Name "TabletInputService" -Force

#원격 데스크톱 기능 비활성화
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
netsh advfirewall firewall set rule group="원격 데스크톱" new enable=No

#공유파일 삭제
#Delete Shared Folder
$shareFolders = Get-SmbShare
foreach($folder in $shareFolders){
  $folderName = $folder.Name
  net share $folderName /delete
}
#시스템 재부팅 시 기본 공유 폴더가 자동 공유 방지
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$registryName = "AutoShareServer"
$registryValue = 0
New-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue -PropertyType DWord -Force
Get-ItemProperty -Path $registryPath -Name $registryName
#Disable SMB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Type DWORD -Value 0 -Force

#30일마다 임시파일 삭제
$Path = "C:\Users\$currentUserName\AppData\Local\Temp"
$Daysback = "-30"
$CurrentDate = Get-Date
$DatetoDelete = $CurrentDate.AddDays($Daysback)
Get-ChildItem $Path -Recurse | Where-Object { $_.LastWriteTime -lt $DatetoDelete } | Remove-Item

#incident response
#EVENT LOG PATH CHAGE
Set-ExecutionPolicy Unrestricted
$logpath= "HKLM:\System\CurrentControlSet\services\eventlog\Security"
Set-ItemProperty -Path $logpath -Name 'MaxSize' -Value 21474836 -Force
Set-ItemProperty -Path $logpath -Name 'MaxSize' -Value 21474836 -Force
Set-ItemProperty -Path $logpath -Name 'MaxSize' -Value 21474836 -Force
Set-ItemProperty -Path $logpath -Name 'MaxSize' -Value 21474836 -Force

#turn on module logging(powershell)
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "ModuleLogging" -Force
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1 -Type DWORD -Force
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'ModuleNames' -Force
New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type String -Force
#Scriptblock logging
New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell' -Name 'ScriptBlockLogging' -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWORD
#powershell transcription
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\" -Name "Transcription" -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1 -Type DWORD -Force
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value $outputDirectory -Type String -Force

#SYSMON 설치 후 활성화
$currentUserName = $env:USERNAME
Write-Host "current user :$currentUserName"
# desktop path
$outputDirectory = "C:\Users\$currentUserName\Desktop"
Write-Host "outputDirectory: $outputDirectory"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Downloading Sysmon.zip ..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "$outputDirectory\\sysmon.zip"
Write-Host "Unzip Sysmon..."
Expand-Archive -Path "$outputDirectory\sysmon.zip" -DestinationPath "$outputDirectory\sysmon" -Force
Write-Host "INSTALLING SYSMON"
$sysmonExePath = Join-Path "$outputDirectory\sysmon" "sysmon64.exe"
Write-Host "$sysmonExePath"
Start-Process -FilePath $sysmonExePath -ArgumentList '-i', '-h', 'sha1', '-n', '-accepteula'

#윈도우 업데이트 실행
Write-Host "Downloading Security Update..."
$url = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035845-x64_b4c28c9c57c35bac9226cde51685e41c281e40eb.msu"
$downloadPath = "$outputDirectory\SecurityUpdate.msu"
Invoke-WebRequest -Uri $url -OutFile $downloadPath
Start-Process -FilePath $outputDirectory\SecurityUpdate.msu

#주요 이벤트 1149 Alert
$logName="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
$eventID=1149
#경로에서 찾아볼 최신 이벤트 개수
$maxEvents=100
$events=Get-WinEvent -LogName $logName -MaxEvents $maxEvents | Where-Object {$_.Id -eq $eventID} | Sort-Object TimeCreated -Descending
if($events.Count -gt 0){
  #가장 처음의 event id 1149선택
	$latestEvent=$events[0]
	$eventTime=$latestEvent.TimeCreated
}
if($latestEvent){
	#Xml 데이터 추출
	$eventXML=$latestEvent.ToXml()
	#Xml문자열을 XML객체로 파싱
	$xml=[xml]$eventXML
	#네임스페이스 매니저 생성
	$ns=New-Object Xml.XmlNamespaceManager($xml.NameTable)
	$ns.AddNamespace("ns","Event_NS")
	#param1, param3 값 추출
	$param1=$xml.SelectSingleNode("//ns:EventXML/ns:Param1",$ns).InnerText
	$param3=$xml.SelectSingleNode("//ns:EventXML/ns:Param3",$ns).InnerText
	$text=@"
	원격 접속 감지!
	이메일: $param1
	IP주소: $param3
	접속 시간: $eventTime
	"@
	Add-Type -AssemblyName PresentationFramework
	[System.Windows.MessageBox]::Show($text,"원격 접속 감지","OK","Information")
} else{
	Add-Type -AssemblyName PresentationFramework
	[System.Windows.MessageBox]::Show("최근 원격 접속을 감지하지 못했습니다.","원격 접속 감지","OK","Information")
}
