[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Now = Get-Date
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:Report = New-Object System.Collections.Generic.List[string]
$script:Summary = New-Object System.Collections.Generic.List[object]
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Dirs = [ordered]@{}
$script:CaseRoot = ''
$script:ReportPath = ''
$script:LogPath = ''
$script:HashPath = ''
$script:Profile = 'Completo'
$script:ProgressTotal = 0
$script:ProgressCurrent = 0
$script:RunTimer = $null
$script:ArtifactStats = [ordered]@{
 Json = 0
 Csv = 0
 Txt = 0
 Raw = 0
 Registry = 0
 Events = 0
 Browser = 0
 Timeline = 0
 HashFailures = 0
}

function C([string]$m,[string]$c='Gray'){ Write-Host $m -ForegroundColor $c }
function Info([string]$m){ C "[*] $m" 'Cyan' }
function Ok([string]$m){ C "[+] $m" 'Green' }
function Warn([string]$m){ C "[!] $m" 'Yellow' }
function Fail([string]$m){ C "[-] $m" 'Red' }
function RL([string]$t=''){ $script:Report.Add($t) }
function RT([string]$t,[int]$l=2){ RL ''; RL ((('#'*$l)+' '+$t)); RL '' }
function ST([string]$a,[string]$e,[string]$d){ $script:Summary.Add([pscustomobject]@{Area=$a;Estado=$e;Detalle=$d}) }
function LG([string]$lvl,[string]$msg){ Add-Content -LiteralPath $script:LogPath -Value ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$lvl.ToUpper(),$msg) -Encoding utf8 }
function Safe([string]$n){ (($n -replace '[\\/:*?"<>|]','_') -replace '\s+','_') }
function SaveLines([string]$p,[string[]]$lines){ $dir=Split-Path -Parent $p; if(-not(Test-Path $dir)){New-Item -ItemType Directory -Path $dir -Force|Out-Null}; [IO.File]::WriteAllLines($p,$lines,$script:Utf8Bom) }
function AddStat([string]$key,[int]$delta=1){ if($script:ArtifactStats.Contains($key)){ $script:ArtifactStats[$key]+=$delta } }
function Ask([string]$prompt,[string]$def){ $v=Read-Host "$prompt [$def]"; if([string]::IsNullOrWhiteSpace($v)){$def}else{$v.Trim()} }
function Menu([string]$title,[string[]]$opts,[int]$def=0){ while($true){ Write-Host ''; C $title Yellow; for($i=0;$i -lt $opts.Count;$i++){ $m=' '; if($i -eq $def){$m='*'}; Write-Host (" [{0}] {1} {2}" -f ($i+1),$m,$opts[$i]) }; $raw=Read-Host ("Selecciona opcion [{0}]" -f ($def+1)); if([string]::IsNullOrWhiteSpace($raw)){ return $opts[$def] }; $n=0; if([int]::TryParse($raw,[ref]$n) -and $n -ge 1 -and $n -le $opts.Count){ return $opts[$n-1] }; Warn 'Opcion no valida.' } }
function Tbl([string[]]$h,[object[]]$rows){ if(-not $h){return}; RL ('| '+($h -join ' | ')+' |'); RL ('|'+(($h|ForEach-Object{'---'}) -join '|')+'|'); foreach($r in $rows){ $vals=foreach($x in $h){ $v='-'; if($null -ne $r.$x){ $v=[string]$r.$x }; $v.Replace("`r",'').Replace("`n",'<br>') }; RL ('| '+($vals -join ' | ')+' |') }; RL '' }
function ToObj($o){ if($null -eq $o){return $null}; if($o -is [string] -or $o -is [ValueType]){return $o}; if($o -is [System.Collections.IEnumerable] -and -not ($o -is [string])){ return @($o | ForEach-Object { ToObj $_ }) }; $p=[ordered]@{}; foreach($x in $o.PSObject.Properties){ if($x.MemberType -match 'Property'){ try{$p[$x.Name]=ToObj $x.Value}catch{$p[$x.Name]='[unavailable]'} } }; [pscustomobject]$p }
function ExportSet([string]$name,$data,[switch]$NoCsv){ $s=Safe $name; $j=Join-Path $script:Dirs.Json "$s.json"; $t=Join-Path $script:Dirs.Txt "$s.txt"; (ToObj $data)|ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $j -Encoding utf8; AddStat 'Json'; ($data|Out-String -Width 4096) | Set-Content -LiteralPath $t -Encoding utf8; AddStat 'Txt'; if(-not $NoCsv){ try{ $c=Join-Path $script:Dirs.Csv "$s.csv"; @($data)|Export-Csv -LiteralPath $c -NoTypeInformation -Encoding utf8; AddStat 'Csv' }catch{ LG WARN ("CSV {0}: {1}" -f $name,$_.Exception.Message) } } }
function CmdOut([string]$name,[scriptblock]$sb){ $p=Join-Path $script:Dirs.Raw ((Safe $name)+'.txt'); try{ (& $sb 2>&1 | Out-String -Width 4096) | Set-Content -LiteralPath $p -Encoding utf8; AddStat 'Raw'; $true }catch{ $_.Exception.Message | Set-Content -LiteralPath $p -Encoding utf8; AddStat 'Raw'; LG WARN ("Comando {0}: {1}" -f $name,$_.Exception.Message); $false } }
function CopyIf([string]$src,[string]$dst,[switch]$Rec){ try{ if(Test-Path -LiteralPath $src){ Copy-Item -LiteralPath $src -Destination $dst -Force -Recurse:$Rec -ErrorAction Stop; return $true } }catch{ LG WARN ("Copia {0}: {1}" -f $src,$_.Exception.Message) }; $false }
function RegVals([string]$path){ try{ $i=Get-Item -LiteralPath $path -ErrorAction Stop; $p=Get-ItemProperty -LiteralPath $path -ErrorAction Stop; @($p.PSObject.Properties|Where-Object{$_.Name -notmatch '^PS'}|ForEach-Object{ [pscustomobject]@{Key=$i.Name;Name=$_.Name;Value=(($_.Value|Out-String).Trim())} }) }catch{ LG WARN ("Registro {0}: {1}" -f $path,$_.Exception.Message); @() } }
function RegKeys([string]$path){ try{ @(Get-ChildItem -LiteralPath $path -ErrorAction Stop | Select-Object PSChildName,Name,PSPath) }catch{ LG WARN ("Subclaves {0}: {1}" -f $path,$_.Exception.Message); @() } }
function ShowProg([string]$status,[int]$step,[int]$total,[int]$sub=-1){
 $pct=0
 if($total -gt 0){
  $pct=[math]::Floor((($step-1)/$total)*100)
  if($sub -ge 0){ $pct=[math]::Min(99,[math]::Floor((($step-1 + ($sub/100))/$total)*100)) }
 }
 try{ Write-Progress -Activity 'EviDumpWin - Adquisicion Forense' -Status $status -PercentComplete $pct }catch{}
}
function EndProg(){ try{ Write-Progress -Activity 'EviDumpWin - Adquisicion Forense' -Completed }catch{} }
function RunCollect([string]$name,[scriptblock]$sb){
 $script:ProgressCurrent++
 ShowProg -status ("Fase {0}/{1}: {2}" -f $script:ProgressCurrent,$script:ProgressTotal,$name) -step $script:ProgressCurrent -total $script:ProgressTotal
 Info "Ejecutando $name"
 $sw=[Diagnostics.Stopwatch]::StartNew()
 try{
  & $sb
  $sw.Stop()
  $script:Results.Add([pscustomobject]@{Nombre=$name;Estado='OK';Segundos=[math]::Round($sw.Elapsed.TotalSeconds,2);Minutos=[math]::Round($sw.Elapsed.TotalMinutes,2)})
  LG INFO "$name OK"
  Ok ("{0} completado en {1}s" -f $name,[math]::Round($sw.Elapsed.TotalSeconds,2))
 }catch{
  $sw.Stop()
  $script:Results.Add([pscustomobject]@{Nombre=$name;Estado='ERROR';Segundos=[math]::Round($sw.Elapsed.TotalSeconds,2);Minutos=[math]::Round($sw.Elapsed.TotalMinutes,2)})
  LG ERROR ("{0}: {1}" -f $name,$_.Exception.Message)
  Warn "$name fallo: $($_.Exception.Message)"
 }
}

function Banner{
 try{ Clear-Host }catch{}
 C '============================================================' Cyan
 C '         EviDumpWin Forensic Collector  - By: Mayky  ' Yellow
 C '============================================================' Cyan
 Write-Host ''
 Write-Host " Equipo  : $env:COMPUTERNAME"
 Write-Host " Usuario : $env:USERNAME"
 Write-Host " Fecha   : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
 Write-Host " Root    : $(if($script:IsAdmin){'Si'}else{'No'})"
 Write-Host ''

}

function Setup{
 Banner
 $root=Ask 'Ruta base del caso' (Join-Path (Get-Location) 'EviDumpWin-Cases')
 $case=Ask 'Nombre del caso' ("{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
 $script:Profile=Menu 'Perfil de adquisicion' @('Rapido - evidencia volatil y estado actual','Completo - recomendado para auditoria forense','Pro - intenta extraer todo lo posible') 1
 $script:CaseRoot=Join-Path $root (Safe $case)
 $script:Dirs=[ordered]@{Reports=(Join-Path $script:CaseRoot 'Reports');Logs=(Join-Path $script:CaseRoot 'Logs');Json=(Join-Path $script:CaseRoot 'Artifacts\Json');Csv=(Join-Path $script:CaseRoot 'Artifacts\Csv');Txt=(Join-Path $script:CaseRoot 'Artifacts\Txt');Raw=(Join-Path $script:CaseRoot 'Artifacts\Raw');Registry=(Join-Path $script:CaseRoot 'Artifacts\Registry');Events=(Join-Path $script:CaseRoot 'Artifacts\Events');Browser=(Join-Path $script:CaseRoot 'Artifacts\Browser');Timeline=(Join-Path $script:CaseRoot 'Artifacts\Timeline')}
 foreach($p in $script:Dirs.Values){ New-Item -ItemType Directory -Path $p -Force|Out-Null }
 $script:ReportPath=Join-Path $script:Dirs.Reports 'Informe_Forense.md'
 $script:LogPath=Join-Path $script:Dirs.Logs 'EviDumpWin.log'
 $script:HashPath=Join-Path $script:Dirs.Reports 'hash_manifest_sha256.csv'
 Set-Content -LiteralPath $script:LogPath -Value '' -Encoding utf8
}

function InitReport{
 RT 'EviDumpWin - Adquisicion Forense Windows' 1
 RL "Generado: $($script:Now.ToString('yyyy-MM-dd HH:mm:ss zzz'))"
 RL "Equipo: $env:COMPUTERNAME"
 RL "Usuario: $env:USERNAME"
 RL "Perfil: $script:Profile"
 RL "Elevado: $(if($script:IsAdmin){'Si'}else{'No'})"
 RL "Ruta del caso: $script:CaseRoot"
 RL ''
 RL '> Nota: Adquisicion en vivo. Los resultados dependen de permisos, bloqueo de ficheros y estado del sistema.'
 RL ''
}

function CollectSystem{
 $os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
 $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
 $bios=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
 $cpu=Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue|Select-Object -First 1
 $ram=0; if($cs -and $cs.TotalPhysicalMemory){ $ram=[math]::Round($cs.TotalPhysicalMemory/1GB,2) }
 $sum=[pscustomobject]@{Equipo=$env:COMPUTERNAME;SO=$(if($os){$os.Caption}else{'No disponible'});Version=$(if($os){$os.Version}else{'-'});Build=$(if($os){$os.BuildNumber}else{'-'});Arranque=$(if($os){$os.LastBootUpTime}else{'-'});Fabricante=$(if($cs){$cs.Manufacturer}else{'-'});Modelo=$(if($cs){$cs.Model}else{'-'});Dominio=$(if($cs){$cs.Domain}else{'-'});CPU=$(if($cpu){$cpu.Name}else{'-'});RAMGB=$ram;BIOS=$(if($bios){$bios.SMBIOSBIOSVersion}else{'-'});Serie=$(if($bios){$bios.SerialNumber}else{'-'});Zona=(Get-TimeZone).DisplayName}
 $vol=@(); try{ $vol=Get-Volume -ErrorAction Stop|Select-Object DriveLetter,FileSystemLabel,FileSystem,SizeRemaining,Size,HealthStatus }catch{ LG WARN "Get-Volume no disponible." }
 $disk=@(); try{ $disk=Get-Disk -ErrorAction Stop|Select-Object Number,FriendlyName,SerialNumber,PartitionStyle,HealthStatus,Size }catch{ LG WARN "Get-Disk no disponible." }
 $bl=@(); try{ $bl=Get-BitLockerVolume -ErrorAction Stop|Select-Object MountPoint,ProtectionStatus,EncryptionMethod,VolumeStatus }catch{ LG WARN "BitLocker no disponible." }
 ExportSet 'system_summary' $sum -NoCsv
 ExportSet 'volume_inventory' $vol
 ExportSet 'disk_inventory' $disk
 ExportSet 'bitlocker_status' $bl
 RT 'Sistema'
 Tbl @('Equipo','SO','Version','Build','Dominio','CPU','RAMGB','Zona') @($sum)
 ST 'Sistema' 'OK' "$($sum.SO) / Build $($sum.Build) / $($sum.RAMGB) GB"
}

function CollectUsers{
 $users=Get-LocalUser -ErrorAction SilentlyContinue|Select-Object Name,Enabled,LastLogon,PasswordLastSet,PrincipalSource
 $groups=Get-LocalGroup -ErrorAction SilentlyContinue|Select-Object Name,Description
 $admins=@(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue|Select-Object Name,ObjectClass,PrincipalSource)
 $profiles=Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue|Where-Object{$_.LocalPath}|Select-Object SID,LocalPath,Loaded,Special,LastUseTime
 $logons=Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue|Select-Object LogonId,LogonType,StartTime,AuthenticationPackage
 ExportSet 'local_users' $users
 ExportSet 'local_groups' $groups
 ExportSet 'administrators_members' $admins
 ExportSet 'user_profiles' $profiles
 ExportSet 'logon_sessions' $logons
 RT 'Usuarios y sesiones'
 Tbl @('Name','Enabled','LastLogon','PasswordLastSet') @($users)
 ST 'Usuarios' 'OK' ("{0} cuentas locales / {1} perfiles" -f (($users|Measure-Object).Count),(($profiles|Measure-Object).Count))
}

function CollectNetwork{
 $ip=@(); try{ $ip=Get-NetIPConfiguration -ErrorAction Stop|Select-Object InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer }catch{ LG WARN "Get-NetIPConfiguration no disponible." }
 $ad=@(); try{ $ad=Get-NetAdapter -ErrorAction Stop|Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed }catch{ LG WARN "Get-NetAdapter no disponible." }
 $tcp=@(); try{ $tcp=Get-NetTCPConnection -ErrorAction Stop|Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess }catch{ LG WARN "Get-NetTCPConnection no disponible." }
 $udp=@(); try{ $udp=Get-NetUDPEndpoint -ErrorAction Stop|Select-Object LocalAddress,LocalPort,OwningProcess }catch{ LG WARN "Get-NetUDPEndpoint no disponible." }
 $dns=@(); try{ $dns=Get-DnsClientCache -ErrorAction Stop|Select-Object Entry,Data,Type,Status,TimeToLive }catch{ LG WARN "Get-DnsClientCache no disponible." }
 $shares=@(); try{ $shares=Get-SmbShare -ErrorAction Stop|Select-Object Name,Path,Description,FolderEnumerationMode }catch{ LG WARN "Get-SmbShare no disponible." }
 $sess=@(); try{ $sess=Get-SmbSession -ErrorAction Stop|Select-Object ClientComputerName,ClientUserName,NumOpens,ConnectedTime }catch{ LG WARN "Get-SmbSession no disponible." }
 $rdp=[pscustomobject]@{fDenyTSConnections=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections;PortNumber=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).PortNumber}
 $wifi=@(); try{ $wifi=netsh wlan show profiles 2>$null|Where-Object{$_ -match 'All User Profile|Perfil de todos los usuarios'}|ForEach-Object{($_ -split ':\s*',2)[1].Trim()}|Where-Object{$_} }catch{}
 ExportSet 'network_ip_configuration' $ip
 ExportSet 'network_adapters' $ad
 ExportSet 'network_tcp_connections' $tcp
 ExportSet 'network_udp_endpoints' $udp
 ExportSet 'network_dns_cache' $dns
 ExportSet 'network_shares' $shares
 ExportSet 'network_smb_sessions' $sess
 ExportSet 'network_rdp' $rdp -NoCsv
 ExportSet 'network_wifi_profiles' ($wifi|ForEach-Object{[pscustomobject]@{Profile=$_}})
 CmdOut 'ipconfig_all' { ipconfig /all }|Out-Null
 CmdOut 'arp_a' { arp -a }|Out-Null
 CmdOut 'route_print' { route print }|Out-Null
 CmdOut 'netstat_ano' { netstat -ano }|Out-Null
 CmdOut 'wlan_profiles' { netsh wlan show profiles }|Out-Null
 CmdOut 'firewall_profiles_raw' { netsh advfirewall show allprofiles }|Out-Null
 RT 'Red'
 Tbl @('Name','Status','MacAddress','LinkSpeed') @($ad)
 ST 'Red' 'OK' ("{0} adaptadores / {1} conexiones TCP" -f (($ad|Measure-Object).Count),(($tcp|Measure-Object).Count))
}

function CollectRuntime{
 $proc=Get-Process -ErrorAction SilentlyContinue|Select-Object ProcessName,Id,Path,Company,StartTime,CPU,Handles
 $svc=Get-Service -ErrorAction SilentlyContinue|Select-Object Name,DisplayName,Status,StartType
 $drv=Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue|Select-Object Name,DisplayName,State,StartMode,PathName
 $tasks=Get-ScheduledTask -ErrorAction SilentlyContinue|Select-Object TaskName,TaskPath,State,Author,Description
 $run=@(RegVals 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')+@(RegVals 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')+@(RegVals 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')+@(RegVals 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')
 $pref=Get-ChildItem -LiteralPath "$env:SystemRoot\Prefetch" -File -ErrorAction SilentlyContinue|Select-Object Name,Length,LastWriteTime
 ExportSet 'processes' $proc
 ExportSet 'services' $svc
 ExportSet 'drivers' $drv
 ExportSet 'scheduled_tasks' $tasks
 ExportSet 'autoruns_registry' $run
 ExportSet 'prefetch_listing' $pref
 CmdOut 'tasklist_v' { tasklist /v }|Out-Null
 CmdOut 'schtasks_query' { schtasks /query /fo LIST /v }|Out-Null
 CmdOut 'wmic_startup' { wmic startup get Caption,Command,Location,User /format:list }|Out-Null
 CopyIf "$env:SystemRoot\Prefetch" $script:Dirs.Raw -Rec|Out-Null
 RT 'Procesos, servicios y persistencia'
 Tbl @('ProcessName','Id','Path','StartTime') @($proc|Select-Object -First 20)
 ST 'Ejecucion' 'OK' ("{0} procesos / {1} tareas programadas" -f (($proc|Measure-Object).Count),(($tasks|Measure-Object).Count))
}

function CollectSecurity{
 $fw=@(); try{ $fw=Get-NetFirewallProfile -ErrorAction Stop|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }catch{ LG WARN "Firewall profile no disponible." }
 $mp=$null; if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){ $mp=Get-MpComputerStatus -ErrorAction SilentlyContinue|Select-Object AMServiceEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion }
 $av=@(); try{ $av=Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop|Select-Object displayName,pathToSignedProductExe,productState,timestamp }catch{ LG WARN "SecurityCenter2 no disponible o acceso denegado." }
 $hf=@(); try{ $hf=Get-HotFix -ErrorAction Stop|Select-Object HotFixID,Description,InstalledBy,InstalledOn }catch{ LG WARN "Get-HotFix no disponible." }
 $soft=@(); foreach($p in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')){ try{ $soft+=Get-ItemProperty -Path $p -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName}|Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation }catch{} }
 ExportSet 'firewall_profiles' $fw
 ExportSet 'windows_defender_status' $mp -NoCsv
 ExportSet 'antivirus_products' $av
 ExportSet 'hotfixes' $hf
 ExportSet 'installed_software' ($soft|Sort-Object DisplayName -Unique)
 CmdOut 'auditpol' { auditpol /get /category:* }|Out-Null
 CmdOut 'whoami_all' { whoami /all }|Out-Null
 CmdOut 'gpresult_r' { gpresult /r }|Out-Null
 CmdOut 'net_accounts' { net accounts }|Out-Null
 RT 'Seguridad'
 Tbl @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction') @($fw)
 ST 'Seguridad' 'OK' ("{0} hotfixes / {1} productos AV" -f (($hf|Measure-Object).Count),(($av|Measure-Object).Count))
}

function CollectRegistryDevices{
 $usbStor=RegKeys 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
 $usb=RegKeys 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
 $mounted=RegVals 'HKLM:\SYSTEM\MountedDevices'
 $bam=RegKeys 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
 $userAssist=RegKeys 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
 $recentDocs=RegKeys 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
 $shellBags=RegKeys 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU'
 $filt=Get-CimInstance -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue|Select-Object Name,Query,EventNamespace
 $cons=Get-CimInstance -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue|Select-Object Name,CommandLineTemplate,ExecutablePath
 $bind=Get-CimInstance -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue|Select-Object Filter,Consumer
 ExportSet 'registry_usbstor' $usbStor
 ExportSet 'registry_usb' $usb
 ExportSet 'registry_mounted_devices' $mounted
 ExportSet 'registry_bam' $bam
 ExportSet 'registry_userassist' $userAssist
 ExportSet 'registry_recentdocs' $recentDocs
 ExportSet 'registry_shellbags' $shellBags
 ExportSet 'wmi_event_filters' $filt
 ExportSet 'wmi_event_consumers' $cons
 ExportSet 'wmi_bindings' $bind
 CmdOut 'mountvol' { mountvol }|Out-Null
 CopyIf "$env:SystemRoot\INF\setupapi.dev.log" $script:Dirs.Raw|Out-Null
 CopyIf "$env:SystemRoot\appcompat\Programs\Amcache.hve" $script:Dirs.Raw|Out-Null
 CopyIf "$env:SystemRoot\System32\sru\SRUDB.dat" $script:Dirs.Raw|Out-Null
 RT 'Registro, dispositivos y persistencia WMI'
 Tbl @('PSChildName','Name') @($usbStor|Select-Object -First 15)
 ST 'Dispositivos' 'OK' ("USBSTOR: {0} / filtros WMI: {1}" -f (($usbStor|Measure-Object).Count),(($filt|Measure-Object).Count))
}

function CollectUserActivity{
 $hist=@(); try{ Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue|ForEach-Object{ $h=Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'; if(Test-Path $h){ $dst=Join-Path $script:Dirs.Raw (Safe ("PSReadLine_"+$_.Name+'.txt')); Copy-Item -LiteralPath $h -Destination $dst -Force -ErrorAction Stop; $hist+=[pscustomobject]@{User=$_.Name;HistoryPath=$h;CopiedTo=$dst} } } }catch{ LG WARN "PSReadLine: $($_.Exception.Message)" }
 $recent=Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Microsoft\Windows\Recent') -Force -ErrorAction SilentlyContinue|Select-Object Name,FullName,Length,LastWriteTime
 $jump=Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations') -Force -ErrorAction SilentlyContinue|Select-Object Name,FullName,Length,LastWriteTime
 $down=Get-ChildItem -LiteralPath (Join-Path $env:USERPROFILE 'Downloads') -Force -ErrorAction SilentlyContinue|Select-Object Name,FullName,Length,CreationTime,LastWriteTime
 $temp=Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue|Select-Object Name,FullName,Length,CreationTime,LastWriteTime
 ExportSet 'powershell_history_files' $hist
 ExportSet 'recent_shortcuts' $recent
 ExportSet 'jumplists' $jump
 ExportSet 'downloads_listing' $down
 ExportSet 'temp_listing' $temp
 CopyIf (Join-Path $env:APPDATA 'Microsoft\Windows\Recent') $script:Dirs.Raw -Rec|Out-Null
 RT 'Actividad de usuario'
 Tbl @('User','HistoryPath','CopiedTo') @($hist)
 ST 'Actividad usuario' 'OK' ("PSReadLine: {0} / Recent: {1}" -f (($hist|Measure-Object).Count),(($recent|Measure-Object).Count))
}

function ExportEvents{
 $logs=@('Application','System','Security','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-Windows Defender/Operational')
 $rows=@(); $i=0; foreach($log in $logs){ $i++; ShowProg -status ("Avanzado: exportando eventos {0}/{1} - {2}" -f $i,$logs.Count,$log) -step $script:ProgressCurrent -total $script:ProgressTotal -sub ([int](($i/$logs.Count)*20)); $safe=Safe $log; $evtx=Join-Path $script:Dirs.Events ($safe+'.evtx'); $csv=Join-Path $script:Dirs.Events ($safe+'-recent.csv'); $ok=$false; try{ & wevtutil.exe epl $log $evtx 2>$null | Out-Null; $ok=($LASTEXITCODE -eq 0); if($ok){ AddStat 'Events' } }catch{ LG WARN ("Export EVTX {0}: {1}" -f $log,$_.Exception.Message) }; try{ $ev=Get-WinEvent -LogName $log -MaxEvents 500 -ErrorAction Stop|Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,UserId,Message; $ev|Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding utf8; AddStat 'Events'; $cnt=($ev|Measure-Object).Count }catch{ $cnt=0; LG WARN ("Eventos {0}: {1}" -f $log,$_.Exception.Message) }; $rows+=[pscustomobject]@{Log=$log;EVTX=$(if($ok){'Si'}else{'No'});Recientes=$cnt} }
 ExportSet 'event_logs_index' $rows
 return $rows
}

function ExportHives{
 $items=@(@{Key='HKLM\SAM';Name='HKLM_SAM.hiv'},@{Key='HKLM\SYSTEM';Name='HKLM_SYSTEM.hiv'},@{Key='HKLM\SOFTWARE';Name='HKLM_SOFTWARE.hiv'},@{Key='HKLM\SECURITY';Name='HKLM_SECURITY.hiv'})
 $rows=@(); $i=0; foreach($h in $items){ $i++; ShowProg -status ("Avanzado: exportando hive {0}/{1} - {2}" -f $i,$items.Count,$h.Key) -step $script:ProgressCurrent -total $script:ProgressTotal -sub (60 + [int](($i/$items.Count)*15)); $t=Join-Path $script:Dirs.Registry $h.Name; $ok=$false; try{ & reg.exe save $h.Key $t /y 2>$null | Out-Null; $ok=($LASTEXITCODE -eq 0); if($ok){ AddStat 'Registry' } }catch{ LG WARN ("Hive {0}: {1}" -f $h.Key,$_.Exception.Message) }; $rows+=[pscustomobject]@{Hive=$h.Key;Ruta=$t;Estado=$(if($ok){'Exportado'}else{'No disponible'})} }
 ExportSet 'registry_hives' $rows
 return $rows
}

function ExportUserHives{
 $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue|Where-Object{$_.LocalPath})
 $rows=@(); $i=0; foreach($p in $profiles){ $i++; if($profiles.Count -gt 0){ ShowProg -status ("Avanzado: copiando hives de usuario {0}/{1}" -f $i,$profiles.Count) -step $script:ProgressCurrent -total $script:ProgressTotal -sub (20 + [int](($i/$profiles.Count)*20)) }; $dst=Join-Path $script:Dirs.Registry (Safe ([IO.Path]::GetFileName($p.LocalPath))); New-Item -ItemType Directory -Path $dst -Force|Out-Null; $a=CopyIf (Join-Path $p.LocalPath 'NTUSER.DAT') $dst; $b=CopyIf (Join-Path $p.LocalPath 'AppData\Local\Microsoft\Windows\UsrClass.dat') $dst; if($a){ AddStat 'Registry' }; if($b){ AddStat 'Registry' }; $rows+=[pscustomobject]@{Perfil=$p.LocalPath;SID=$p.SID;NTUSER=$(if($a){'Copiado'}else{'No'});UsrClass=$(if($b){'Copiado'}else{'No'})} }
 ExportSet 'user_hives' $rows
 return $rows
}

function CopyBrowsers{
 $defs=@(
  @{N='Chrome';B=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data');Type='Chromium'},
  @{N='Edge';B=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data');Type='Chromium'},
  @{N='Brave';B=(Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data');Type='Chromium'},
  @{N='Opera';B=(Join-Path $env:APPDATA 'Opera Software');Type='Chromium';Profiles=@('Opera Stable','Opera GX Stable','Opera Beta','Opera Developer')},
  @{N='Firefox';B=(Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles');Type='Firefox'}
 )
 $rows=@(); $i=0; foreach($d in $defs){ $i++; ShowProg -status ("Avanzado: artefactos navegador {0}/{1} - {2}" -f $i,$defs.Count,$d.N) -step $script:ProgressCurrent -total $script:ProgressTotal -sub (40 + [int](($i/$defs.Count)*20)); $dir=Join-Path $script:Dirs.Browser $d.N; New-Item -ItemType Directory -Path $dir -Force|Out-Null; $c=0; if(Test-Path $d.B){ if($d.Type -eq 'Chromium'){ if($d.ContainsKey('Profiles') -and $d.Profiles){ $profiles=@(Get-ChildItem -LiteralPath $d.B -Directory -ErrorAction SilentlyContinue|Where-Object{ $name=$_.Name; @($d.Profiles|Where-Object{ $name -like $_ }).Count -gt 0 }) } else { $profiles=@(Get-ChildItem -LiteralPath $d.B -Directory -ErrorAction SilentlyContinue|Where-Object{ $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) }; foreach($p in $profiles){ foreach($rel in @('History','Network\Cookies','Login Data','Bookmarks','Preferences')){ $src=Join-Path $p.FullName $rel; if(Test-Path -LiteralPath $src){ try{ Copy-Item -LiteralPath $src -Destination (Join-Path $dir (Safe ($p.Name+'_'+$rel))) -Force -ErrorAction Stop; $c++; AddStat 'Browser' }catch{ LG WARN ("Browser {0}: {1}" -f $d.N,$_.Exception.Message) } } } } } else { $profiles=@(Get-ChildItem -LiteralPath $d.B -Directory -ErrorAction SilentlyContinue); foreach($p in $profiles){ foreach($name in @('places.sqlite','favicons.sqlite','extensions.json','cookies.sqlite','logins.json','key4.db')){ $src=Join-Path $p.FullName $name; if(Test-Path -LiteralPath $src){ try{ Copy-Item -LiteralPath $src -Destination (Join-Path $dir (Safe ($p.Name+'_'+$name))) -Force -ErrorAction Stop; $c++; AddStat 'Browser' }catch{ LG WARN ("Browser {0}: {1}" -f $d.N,$_.Exception.Message) } } } } } }; $rows+=[pscustomobject]@{Navegador=$d.N;BasePath=$d.B;Copias=$c;Estado=$(if($c -gt 0){'Recolectado'}elseif(Test-Path $d.B){'Detectado con bloqueos o sin ficheros objetivo'}else{'No detectado'})} }
 ExportSet 'browser_artifacts' $rows
 return $rows
}

function TimelineSeed{
 ShowProg -status 'Avanzado: construyendo timeline inicial' -step $script:ProgressCurrent -total $script:ProgressTotal -sub 85
 $rows=@(); try{ $rows+=Get-ChildItem -LiteralPath "$env:SystemRoot\Prefetch" -File -ErrorAction Stop|Select-Object Name,Length,CreationTimeUtc,LastWriteTimeUtc,FullName }catch{}
 try{ $rows+=Get-ChildItem -LiteralPath (Join-Path $env:APPDATA 'Microsoft\Windows\Recent') -File -Force -ErrorAction Stop|Select-Object Name,Length,CreationTimeUtc,LastWriteTimeUtc,FullName }catch{}
 try{ $rows+=Get-ChildItem -LiteralPath 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue|Select-Object Name,Length,CreationTimeUtc,LastWriteTimeUtc,FullName }catch{}
 $rows|Export-Csv -LiteralPath (Join-Path $script:Dirs.Timeline 'timeline_seed.csv') -NoTypeInformation -Encoding utf8
 AddStat 'Timeline'
 return $rows
}

function CollectAdvanced{
 ShowProg -status 'Avanzado: preparando exportaciones pesadas' -step $script:ProgressCurrent -total $script:ProgressTotal -sub 1
 $ev=ExportEvents
 $uh=ExportUserHives
 $bh=CopyBrowsers
 $tl=TimelineSeed
 if($script:IsAdmin){ $hh=ExportHives } else { Warn 'Sin admin no se exportan hives HKLM.'; LG WARN 'HKLM hives omitidos por falta de admin.' }
 ShowProg -status 'Avanzado: finalizando resumen' -step $script:ProgressCurrent -total $script:ProgressTotal -sub 95
 RT 'Artefactos avanzados'
 Tbl @('Log','EVTX','Recientes') @($ev)
 ST 'Artefactos avanzados' 'OK' ("Logs: {0} / hives usuario: {1} / timeline: {2}" -f (($ev|Measure-Object).Count),(($uh|Measure-Object).Count),(($tl|Measure-Object).Count))
}

function WriteMeta{
 RT 'Resumen Ejecutivo'
 Tbl @('Area','Estado','Detalle') $script:Summary.ToArray()
 RT 'Estado de ejecucion'
 Tbl @('Nombre','Estado','Segundos','Minutos') $script:Results.ToArray()
 RT 'Estadisticas de artefactos'
 $artifactRows=@(); foreach($k in $script:ArtifactStats.Keys){ $artifactRows+=[pscustomobject]@{Tipo=$k;Cantidad=$script:ArtifactStats[$k]} }
 Tbl @('Tipo','Cantidad') @($artifactRows)
 RT 'Metricas de ejecucion'
 $okCount=@($script:Results.ToArray()|Where-Object{$_.Estado -eq 'OK'}).Count
 $errCount=@($script:Results.ToArray()|Where-Object{$_.Estado -eq 'ERROR'}).Count
 $metrics=@([pscustomobject]@{
  Equipo=$env:COMPUTERNAME
  Perfil=$script:Profile
  Elevado=$(if($script:IsAdmin){'Si'}else{'No'})
  FasesOK=$okCount
  FasesError=$errCount
  TiempoTotalSegundos=[math]::Round($script:RunTimer.Elapsed.TotalSeconds,2)
  TiempoTotalMinutos=[math]::Round($script:RunTimer.Elapsed.TotalMinutes,2)
 })
 Tbl @('Equipo','Perfil','Elevado','FasesOK','FasesError','TiempoTotalSegundos','TiempoTotalMinutos') $metrics
 RT 'Estructura de salida'
 $rows=@(); foreach($k in $script:Dirs.Keys){ $rows+=[pscustomobject]@{Elemento=$k;Ruta=$script:Dirs[$k]} }
 Tbl @('Elemento','Ruta') @($rows)
}

function SaveReport{ WriteMeta; SaveLines $script:ReportPath $script:Report }
function Hashes{ $rows=Get-ChildItem -LiteralPath $script:CaseRoot -Recurse -File -ErrorAction SilentlyContinue|Where-Object{$_.FullName -ne $script:HashPath}|ForEach-Object{ try{ $h=Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop; [pscustomobject]@{RelativePath=$_.FullName.Substring($script:CaseRoot.Length).TrimStart('\');Length=$_.Length;SHA256=$h.Hash;LastWriteTimeUtc=$_.LastWriteTimeUtc} }catch{ AddStat 'HashFailures'; [pscustomobject]@{RelativePath=$_.FullName.Substring($script:CaseRoot.Length).TrimStart('\');Length=$_.Length;SHA256='ERROR';LastWriteTimeUtc=$_.LastWriteTimeUtc} } }; $rows|Export-Csv -LiteralPath $script:HashPath -NoTypeInformation -Encoding utf8 }
function Done{ Write-Host ''; C '============================================================' Green; C '                    ADQUISICION COMPLETADA                   ' Yellow; C '============================================================' Green; Write-Host " Caso    : $script:CaseRoot"; Write-Host " Informe : $script:ReportPath"; Write-Host " Log     : $script:LogPath"; Write-Host " Hashes  : $script:HashPath"; Write-Host (" Tiempo  : {0}s ({1} min)" -f [math]::Round($script:RunTimer.Elapsed.TotalSeconds,2),[math]::Round($script:RunTimer.Elapsed.TotalMinutes,2)); Write-Host ''; foreach($r in $script:Summary){ Write-Host (" - {0}: {1}" -f $r.Area,$r.Detalle) }; Write-Host ''; Write-Host ' Artefactos:' -ForegroundColor Cyan; foreach($k in $script:ArtifactStats.Keys){ Write-Host ("   {0}: {1}" -f $k,$script:ArtifactStats[$k]) } }

Setup
InitReport
LG INFO "Inicio de adquisicion en $script:CaseRoot"
$script:RunTimer=[Diagnostics.Stopwatch]::StartNew()
$script:ProgressTotal = 7
if($script:Profile -notlike 'Rapido*'){ $script:ProgressTotal = 8 }
$script:ProgressCurrent = 0
RunCollect 'Sistema' { CollectSystem }
RunCollect 'Usuarios y sesiones' { CollectUsers }
RunCollect 'Red' { CollectNetwork }
RunCollect 'Procesos y persistencia' { CollectRuntime }
RunCollect 'Seguridad' { CollectSecurity }
RunCollect 'Registro y dispositivos' { CollectRegistryDevices }
RunCollect 'Actividad de usuario' { CollectUserActivity }
if($script:Profile -notlike 'Rapido*'){ RunCollect 'Artefactos avanzados' { CollectAdvanced } } else { ST 'Perfil' 'INFO' 'Rapido: sin exportacion de EVTX completos ni hives.'; LG INFO 'Perfil rapido: se omite adquisicion avanzada.' }
ShowProg -status 'Calculando hashes y cerrando informe' -step ($script:ProgressTotal + 1) -total ($script:ProgressTotal + 1)
Hashes
$script:RunTimer.Stop()
SaveReport
LG INFO 'Adquisicion finalizada correctamente.'
EndProg
Done
