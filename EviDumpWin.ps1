<#
 EviDumpWin 5.1 - Recolector forense en vivo para Windows
 Autor : Mayky
 Uso   : .\EviDumpWin.ps1   (asistente interactivo, sin parametros)
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$global:LASTEXITCODE = 0

$script:Version = '5.1'
$script:Now = Get-Date
$script:IsAdmin = $false
try{ $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }catch{}
$script:Interactive = [Environment]::UserInteractive -and -not ([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^[-/]noni' })
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:CsvEnc = 'UTF8'; if($PSVersionTable.PSVersion.Major -ge 6){ $script:CsvEnc = 'utf8BOM' }
$script:Blocks = New-Object System.Collections.Generic.List[object]
$script:SetPreview = [ordered]@{}
$script:CaseInfo = @()
$script:Summary = New-Object System.Collections.Generic.List[object]
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Copies = New-Object System.Collections.Generic.List[object]
$script:SetIndex = New-Object System.Collections.Generic.List[object]
$script:Data = @{}
$script:SidCache = @{}
$script:Dirs = [ordered]@{}
$script:CaseRoot = ''
$script:ReportPath = ''
$script:PdfPath = ''
$script:JsonReportPath = ''
$script:CsvReportDir = ''
$script:PdfMethod = ''
$script:PdfBrowser = $null
$script:LogPath = ''
$script:HashPath = ''
$script:CopyLogPath = ''
$script:AcqProfile = 'Completo'
$script:Level = 2
$script:Investigator = ''
$script:CaseDesc = ''
$script:ProgressTotal = 0
$script:ProgressCurrent = 0
$script:PhaseWarnings = 0
$script:RunTimer = $null
$script:HasRegLW = $false
$script:UserProfiles = @()
$script:ArtifactStats = [ordered]@{
 Json = 0
 Csv = 0
 Raw = 0
 Registry = 0
 Events = 0
 Browser = 0
 Files = 0
 Timeline = 0
 CopyFailures = 0
 Warnings = 0
 HashFailures = 0
}
$script:SkipProps = @('CimClass','CimInstanceProperties','CimSystemProperties','PSComputerName','PSShowComputerName')

# ---------------------------------------------------------------- utilidades de consola, log e informe
function C([string]$m,[string]$c='Gray'){ Write-Host $m -ForegroundColor $c }
function Info([string]$m){ C "[*] $m" 'Cyan' }
function Ok([string]$m){ C "[+] $m" 'Green' }
function Warn([string]$m){ C "[!] $m" 'Yellow' }
function Fail([string]$m){ C "[-] $m" 'Red' }
function RL([string]$t=''){
 if([string]::IsNullOrWhiteSpace($t)){ return }
 if($t.StartsWith('> ')){ $script:Blocks.Add([pscustomobject]@{K='N';T=$t.Substring(2)}); return }
 if($t.StartsWith('- ')){ $script:Blocks.Add([pscustomobject]@{K='LI';T=$t.Substring(2)}); return }
 $script:Blocks.Add([pscustomobject]@{K='P';T=$t})
}
function RT([string]$t,[int]$l=2){ $script:Blocks.Add([pscustomobject]@{K='H';L=$l;T=$t}) }
function ST([string]$a,[string]$e,[string]$d){ $script:Summary.Add([pscustomobject]@{Area=$a;Estado=$e;Detalle=$d}) }
function AddStat([string]$key,[int]$delta=1){ if($script:ArtifactStats.Contains($key)){ $script:ArtifactStats[$key]+=$delta } }
function LG([string]$lvl,[string]$msg){
 if($lvl -eq 'WARN'){ $script:PhaseWarnings++; AddStat 'Warnings' }
 if(-not $script:LogPath){ return }
 try{ Add-Content -LiteralPath $script:LogPath -Value ("[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'),$lvl.ToUpper(),$msg) -Encoding utf8 }catch{}
}
function Finding([string]$area,[string]$sev,[string]$detail){ $script:Findings.Add([pscustomobject]@{Severidad=$sev;Area=$area;Detalle=$detail}); LG INFO "Hallazgo [$sev] $area - $detail" }
function HtmlEnc([string]$s){ [System.Net.WebUtility]::HtmlEncode($s) }
function Safe([string]$n){
 $s = (($n -replace '[\\/:*?"<>|\[\]]','_') -replace '\s+','_').Trim([char[]]'. ')
 if([string]::IsNullOrWhiteSpace($s)){ $s = 'sin_nombre' }
 if($s -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'){ $s = '_'+$s }
 if($s.Length -gt 120){ $s = $s.Substring(0,120) }
 $s
}
function P($o,[string]$n){
 if($null -eq $o){ return $null }
 if($o -is [System.Collections.IDictionary]){ if($o.Contains($n)){ return $o[$n] }; return $null }
 $pp = $o.PSObject.Properties[$n]
 if($null -eq $pp){ return $null }
 try{ $pp.Value }catch{ $null }
}
function UtcStr($d){ if($null -eq $d -or -not ($d -is [datetime])){ return '' }; $d.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }
function SumOf($rows,[string]$prop){ $t = 0; foreach($r in @($rows)){ $v = P $r $prop; if($null -ne $v){ $t += [double]$v } }; $t }
function JP([string]$a,[string]$b){ if([string]::IsNullOrEmpty($b)){ return $a }; Join-Path $a $b }
function Rel([string]$p){ if($p -and $script:CaseRoot -and $p.StartsWith($script:CaseRoot,[StringComparison]::OrdinalIgnoreCase)){ return $p.Substring($script:CaseRoot.Length).TrimStart([char[]]'\/') }; $p }
function Hex([byte[]]$b,[int]$max=4096){
 if($null -eq $b -or $b.Length -eq 0){ return '' }
 $n = [math]::Min($b.Length,$max)
 $s = [BitConverter]::ToString($b,0,$n).Replace('-','')
 if($b.Length -gt $max){ $s += '...(+' + ($b.Length-$max) + ' bytes)' }
 $s
}
function TryUtf16([byte[]]$b){
 if($null -eq $b -or $b.Length -lt 4 -or ($b.Length % 2) -ne 0){ return '' }
 $s = [Text.Encoding]::Unicode.GetString($b)
 $i = $s.IndexOf([char]0); if($i -ge 0){ $s = $s.Substring(0,$i) }
 if($s.Length -ge 2 -and $s -match '^[\x20-\x7E]+$'){ return $s }
 ''
}
function FileTimeStr([byte[]]$b,[int]$off=0){
 if($null -eq $b -or $b.Length -lt ($off+8)){ return '' }
 $ft = [BitConverter]::ToInt64($b,$off)
 if($ft -le 0){ return '' }
 try{ [DateTime]::FromFileTimeUtc($ft).ToString('yyyy-MM-dd HH:mm:ss') }catch{ '' }
}
function BinStrings([byte[]]$b){
 if($null -eq $b -or $b.Length -lt 4){ return '' }
 $r = New-Object System.Collections.Generic.List[string]
 foreach($o in 0,1){
  $len = ($b.Length-$o) - (($b.Length-$o) % 2)
  if($len -ge 8){ foreach($m in [regex]::Matches([Text.Encoding]::Unicode.GetString($b,$o,$len),'[\x20-\x7E]{4,}')){ if(-not $r.Contains($m.Value)){ $r.Add($m.Value) } } }
 }
 foreach($m in [regex]::Matches([Text.Encoding]::ASCII.GetString($b),'[\x20-\x7E]{4,}')){ if(-not $r.Contains($m.Value)){ $r.Add($m.Value) } }
 ($r.ToArray()) -join ' | '
}
function SysTimeStr([byte[]]$b){
 if($null -eq $b -or $b.Length -lt 16){ return '' }
 try{ (New-Object DateTime ([BitConverter]::ToUInt16($b,0)),([BitConverter]::ToUInt16($b,2)),([BitConverter]::ToUInt16($b,6)),([BitConverter]::ToUInt16($b,8)),([BitConverter]::ToUInt16($b,10)),([BitConverter]::ToUInt16($b,12))).ToString('yyyy-MM-dd HH:mm:ss') }catch{ '' }
}
function Rot13([string]$s){
 $sb = New-Object System.Text.StringBuilder
 foreach($ch in $s.ToCharArray()){
  $c = [int]$ch
  if($c -ge 65 -and $c -le 90){ [void]$sb.Append([char]((($c-65+13)%26)+65)) }
  elseif($c -ge 97 -and $c -le 122){ [void]$sb.Append([char]((($c-97+13)%26)+97)) }
  else{ [void]$sb.Append($ch) }
 }
 $sb.ToString()
}
function SidName([string]$sid){
 if(-not $sid){ return '' }
 if($script:SidCache.ContainsKey($sid)){ return $script:SidCache[$sid] }
 $n = ''
 try{ $n = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value }catch{}
 $script:SidCache[$sid] = $n
 $n
}
function Ask([string]$prompt,[string]$def){
 if(-not $script:Interactive){ return $def }
 $v = $null
 try{ $v = Read-Host "$prompt [$def]" }catch{ return $def }
 if([string]::IsNullOrWhiteSpace($v)){ return $def }
 $v.Trim().Trim('"').Trim()
}
function YesNo([string]$prompt,[bool]$def=$true){
 $d = 'S/n'; if(-not $def){ $d = 's/N' }
 $v = Ask "$prompt ($d)" ''
 if([string]::IsNullOrWhiteSpace($v)){ return $def }
 return ($v -match '^(?i)(s|si|y|yes)$')
}
function Menu([string]$title,[string[]]$opts,[int]$def=0){
 if(-not $script:Interactive){ return $def }
 while($true){
  Write-Host ''; C $title Yellow
  for($i=0;$i -lt $opts.Count;$i++){ $m=' '; if($i -eq $def){ $m='*' }; Write-Host (" [{0}] {1} {2}" -f ($i+1),$m,$opts[$i]) }
  $raw = $null
  try{ $raw = Read-Host ("Selecciona opcion [{0}]" -f ($def+1)) }catch{ return $def }
  if([string]::IsNullOrWhiteSpace($raw)){ return $def }
  $n = 0
  if([int]::TryParse($raw,[ref]$n) -and $n -ge 1 -and $n -le $opts.Count){ return ($n-1) }
  Warn 'Opcion no valida.'
 }
}
function Tbl([string[]]$h,[object[]]$rows,[int]$max=0,[string]$cls=''){
 if(-not $h){ return }
 $all = @($rows | Where-Object { $null -ne $_ })
 $out = New-Object System.Collections.Generic.List[object]
 foreach($r in $all){
  if($max -gt 0 -and $out.Count -ge $max){ break }
  $cells = New-Object System.Collections.Generic.List[string]
  foreach($x in $h){ $v = P $r $x; if($null -eq $v){ $cells.Add('') } else { $cells.Add([string]$v) } }
  $out.Add($cells.ToArray())
 }
 $script:Blocks.Add([pscustomobject]@{K='T';H=$h;R=$out.ToArray();Total=$all.Count;Cls=$cls})
}
function ToObj($o,[int]$d=0){
 if($null -eq $o){ return $null }
 if($o -is [string]){ return $o }
 if($o -is [datetime]){ return $o.ToString('o') }
 if($o -is [enum] -or $o -is [char] -or $o -is [timespan] -or $o -is [guid]){ return [string]$o }
 if($o -is [ValueType]){ return $o }
 if($o -is [byte[]]){ return (Hex $o) }
 if($o -is [System.Net.IPAddress] -or $o -is [System.Security.Principal.IdentityReference] -or $o -is [version] -or $o -is [type] -or $o -is [scriptblock]){ return [string]$o }
 if($d -ge 4){ return [string]$o }
 if($o -is [System.Collections.IDictionary]){
  $p=[ordered]@{}; foreach($k in $o.Keys){ $p[[string]$k] = ToObj $o[$k] ($d+1) }; return [pscustomobject]$p
 }
 if($o -is [System.Collections.IEnumerable]){
  $a = New-Object System.Collections.Generic.List[object]
  foreach($i in $o){ $a.Add((ToObj $i ($d+1))) }
  return ,($a.ToArray())
 }
 $p=[ordered]@{}
 foreach($x in $o.PSObject.Properties){
  if($x.MemberType -notmatch 'Property' -or $script:SkipProps -contains $x.Name){ continue }
  try{ $p[$x.Name] = ToObj $x.Value ($d+1) }catch{ $p[$x.Name] = '[no disponible]' }
 }
 [pscustomobject]$p
}
function Flat($r){
 if($null -eq $r -or $r -is [string] -or $r -is [ValueType]){ return [pscustomobject]@{Valor=$r} }
 $p=[ordered]@{}
 foreach($x in $r.PSObject.Properties){
  $v = $x.Value
  if($v -is [System.Management.Automation.PSCustomObject]){ $v = ConvertTo-Json -InputObject $v -Compress -Depth 3 }
  elseif($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){
   $v = (@($v) | ForEach-Object { if($_ -is [System.Management.Automation.PSCustomObject]){ ConvertTo-Json -InputObject $_ -Compress -Depth 3 } else { [string]$_ } }) -join '; '
  }
  $p[$x.Name] = $v
 }
 [pscustomobject]$p
}
function ExportSet([string]$name,$data,[switch]$NoCsv,[switch]$Single){
 $s = Safe $name
 $rows = @(); if($null -ne $data){ $rows = @($data | Where-Object { $null -ne $_ }) }
 $obj = $null
 try{
  if($Single){ if($rows.Count -gt 0){ $obj = ToObj $rows[0] } } else { $obj = ToObj $rows }
  if($null -eq $obj -and -not $Single){ $obj = @() }
  $json = ConvertTo-Json -InputObject $obj -Depth 6
  [IO.File]::WriteAllText((Join-Path $script:Dirs.Json "$s.json"),[string]$json,$script:Utf8NoBom)
  AddStat 'Json'
 }catch{ LG WARN ("JSON {0}: {1}" -f $name,$_.Exception.Message) }
 try{
  $prev = @(); if($rows.Count -gt 0 -and $null -ne $obj){ $prev = @(@($obj) | Select-Object -First 150 | ForEach-Object { Flat $_ }) }
  $script:SetPreview[$s] = [pscustomobject]@{Filas=$rows.Count;Vista=$prev}
 }catch{ LG WARN ("Vista previa {0}: {1}" -f $name,$_.Exception.Message) }
 $csv = 'No'
 if(-not $NoCsv -and $rows.Count -gt 0){
  try{
   $flat = @(); if($null -ne $obj){ $flat = @(@($obj) | ForEach-Object { Flat $_ }) }
   $flat | Export-Csv -LiteralPath (Join-Path $script:Dirs.Csv "$s.csv") -NoTypeInformation -Encoding $script:CsvEnc
   AddStat 'Csv'; $csv = 'Si'
  }catch{ LG WARN ("CSV {0}: {1}" -f $name,$_.Exception.Message) }
 }
 $script:SetIndex.Add([pscustomobject]@{Conjunto=$s;Filas=$rows.Count;CSV=$csv})
}
function CmdOut([string]$name,[scriptblock]$sb){
 $ErrorActionPreference = 'Continue'
 $p = Join-Path $script:Dirs.Raw ((Safe $name)+'.txt')
 $global:LASTEXITCODE = 0
 $code = 0
 $txt = ''
 try{
  $out = & $sb 2>&1 | ForEach-Object { if($_ -is [System.Management.Automation.ErrorRecord]){ "[stderr] " + $_.Exception.Message } else { $_ } }
  $code = $global:LASTEXITCODE
  $txt = ($out | Out-String -Width 4096)
 }catch{ $txt = "ERROR: $($_.Exception.Message)"; $code = -1 }
 $head = "# Comando : {0}`r`n# Fecha   : {1}`r`n# Salida  : {2}`r`n`r`n" -f $sb.ToString().Trim(),(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'),$code
 try{ [IO.File]::WriteAllText($p,$head+$txt,$script:Utf8Bom); AddStat 'Raw' }catch{ LG WARN ("Raw {0}: {1}" -f $name,$_.Exception.Message) }
 if($code -ne 0){ LG WARN ("Comando {0}: codigo de salida {1}" -f $name,$code) }
}

# ---------------------------------------------------------------- copias con registro de custodia
function AcqLog([string]$src,[string]$dst,[string]$method,[string]$status,[string]$detail=''){
 $fi = $null
 try{ if($src -and $src -match '^[A-Za-z]:\\|^\\\\' -and (Test-Path -LiteralPath $src -PathType Leaf)){ $fi = Get-Item -LiteralPath $src -Force } }catch{}
 $script:Copies.Add([pscustomobject]@{
  FechaUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
  Origen=$src
  Destino=(Rel $dst)
  Metodo=$method
  Estado=$status
  Bytes=$(if($fi){ $fi.Length }else{ $null })
  OrigenCreacionUtc=$(if($fi){ UtcStr $fi.CreationTime }else{ '' })
  OrigenModificacionUtc=$(if($fi){ UtcStr $fi.LastWriteTime }else{ '' })
  OrigenAccesoUtc=$(if($fi){ UtcStr $fi.LastAccessTime }else{ '' })
  Detalle=$detail
 })
 if($status -ne 'OK'){ AddStat 'CopyFailures' }
}
function CopyFile([string]$src,[string]$dstDir,[string]$dstName='',[switch]$NoVss,[string]$Stat='Files'){
 $ErrorActionPreference = 'Continue'
 if(-not $src -or -not (Test-Path -LiteralPath $src -PathType Leaf)){ return $false }
 if(-not $dstName){ $dstName = [IO.Path]::GetFileName($src) }
 try{ if(-not (Test-Path -LiteralPath $dstDir)){ New-Item -ItemType Directory -Path $dstDir -Force | Out-Null } }catch{ LG WARN ("Directorio {0}: {1}" -f $dstDir,$_.Exception.Message); return $false }
 $dst = Join-Path $dstDir (Safe $dstName)
 $method = 'Copy-Item'; $err = ''; $ok = $false
 try{ Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop; $ok = $true }catch{ $err = $_.Exception.Message }
 if(-not $ok -and -not $NoVss -and $script:IsAdmin){
  $method = 'esentutl /vss'
  try{
   if(Test-Path -LiteralPath $dst){ Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue }
   $global:LASTEXITCODE = 0
   $o = & esentutl.exe /y $src /vss /d $dst 2>&1 | Out-String
   if($global:LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dst)){ $ok = $true } else { $err += ' | esentutl: ' + (($o -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -Last 2) -join ' ') }
  }catch{ $err += ' | esentutl: ' + $_.Exception.Message }
 }
 if($ok){
  try{ $fi = Get-Item -LiteralPath $src -Force; $di = Get-Item -LiteralPath $dst -Force; $di.CreationTimeUtc = $fi.CreationTimeUtc; $di.LastWriteTimeUtc = $fi.LastWriteTimeUtc }catch{}
  AddStat $Stat
  AcqLog $src $dst $method 'OK'
 } else {
  LG WARN ("Copia {0}: {1}" -f $src,$err)
  AcqLog $src $dst $method 'ERROR' $err
 }
 return $ok
}
function CopyTree([string]$src,[string]$dst,[switch]$NoVss,[string[]]$Include=@('*'),[int]$Max=20000,[string]$Stat='Files'){
 $r = [pscustomobject]@{Copiados=0;Fallidos=0}
 if(-not $src -or -not (Test-Path -LiteralPath $src -PathType Container)){ return $r }
 $base = (Get-Item -LiteralPath $src -Force).FullName.TrimEnd('\')
 $files = @()
 try{ $files = @(Get-ChildItem -LiteralPath $base -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $n=$_.Name; @($Include | Where-Object { $n -like $_ }).Count -gt 0 } | Select-Object -First $Max) }catch{ LG WARN ("Listado {0}: {1}" -f $src,$_.Exception.Message) }
 foreach($f in $files){
  $d = $dst
  if($f.DirectoryName.Length -gt $base.Length -and $f.DirectoryName.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){ $d = Join-Path $dst $f.DirectoryName.Substring($base.Length).TrimStart('\') }
  if(CopyFile $f.FullName $d -NoVss:$NoVss -Stat $Stat){ $r.Copiados++ } else { $r.Fallidos++ }
 }
 $r
}
function RegSave([string]$key,[string]$dst){
 $ErrorActionPreference = 'Continue'
 $global:LASTEXITCODE = 0
 $o = ''
 try{ $o = & reg.exe save $key $dst /y 2>&1 | Out-String }catch{ $o = $_.Exception.Message }
 if($global:LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dst)){ AddStat 'Registry'; AcqLog $key $dst 'reg save' 'OK'; return $true }
 $msg = (($o -split "`r?`n" | Where-Object { $_ -match '\S' }) -join ' ')
 LG WARN ("reg save {0}: {1}" -f $key,$msg)
 AcqLog $key $dst 'reg save' 'ERROR' $msg
 return $false
}

# ---------------------------------------------------------------- registro
$script:RegLWCode = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
namespace EviDump {
 public static class Reg {
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern int RegQueryInfoKey(SafeRegistryHandle hKey, IntPtr c, IntPtr cc, IntPtr r, IntPtr sk, IntPtr msk, IntPtr mc, IntPtr v, IntPtr mvn, IntPtr mvl, IntPtr sd, out long ft);
  public static string LastWrite(RegistryKey k) {
   long ft;
   if (RegQueryInfoKey(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out ft) == 0 && ft > 0)
    return DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd HH:mm:ss");
   return "";
  }
 }
}
'@
function InitRegLW{
 try{
  if(-not ('EviDump.Reg' -as [type])){ Add-Type -TypeDefinition $script:RegLWCode -ErrorAction Stop }
  $script:HasRegLW = $true
 }catch{ LG WARN "No se pudo compilar el lector de LastWrite del registro: $($_.Exception.Message)" }
}
function KeyLW($k){ if(-not $script:HasRegLW -or $null -eq $k){ return '' }; try{ return [string]([type]'EviDump.Reg')::LastWrite($k) }catch{ return '' } }
function OpenKey([string]$path){ try{ return (Get-Item -LiteralPath $path -ErrorAction Stop) }catch{ return $null } }
function RegValue([string]$path,[string]$name){ $k = OpenKey $path; if($null -eq $k){ return $null }; try{ return $k.GetValue($name,$null,'DoNotExpandEnvironmentNames') }catch{ return $null } }
function ValText($v){
 if($null -eq $v){ return '' }
 if($v -is [byte[]]){ return (Hex $v) }
 if($v -is [string[]]){ return ($v -join ' ; ') }
 [string]$v
}
function RegRowsFromKey($k,[string]$extra='',[switch]$Strings){
 $out = New-Object System.Collections.Generic.List[object]
 if($null -eq $k){ return }
 $lw = KeyLW $k
 $names = @(); try{ $names = @($k.GetValueNames()) }catch{}
 foreach($n in $names){
  $kind = ''; try{ $kind = [string]$k.GetValueKind($n) }catch{}
  $v = $null; try{ $v = $k.GetValue($n,$null,'DoNotExpandEnvironmentNames') }catch{}
  $txt = ''; if($v -is [byte[]]){ if($Strings){ $txt = BinStrings $v } else { $txt = TryUtf16 $v } }
  $out.Add([pscustomobject]@{Origen=$extra;Key=$k.Name;KeyLastWriteUtc=$lw;Name=$(if($n -eq ''){ '(Default)' }else{ $n });Type=$kind;Value=(ValText $v);Texto=$txt})
 }
 $out.ToArray()
}
function RegVals([string]$path,[string]$extra=''){
 $k = OpenKey $path
 if($null -eq $k){ return }
 RegRowsFromKey $k $extra
}
function RegTree([string]$path,[int]$maxDepth=3,[int]$maxRows=50000,[string]$extra='',[switch]$Strings){
 $out = New-Object System.Collections.Generic.List[object]
 $root = OpenKey $path
 if($null -eq $root){ return }
 $stack = New-Object System.Collections.Stack
 $stack.Push(@($root,0))
 while($stack.Count -gt 0 -and $out.Count -lt $maxRows){
  $it = $stack.Pop(); $k = $it[0]; $d = [int]$it[1]
  $rows = @(RegRowsFromKey $k $extra -Strings:$Strings)
  if($rows.Count -eq 0){ $out.Add([pscustomobject]@{Origen=$extra;Key=$k.Name;KeyLastWriteUtc=(KeyLW $k);Name='';Type='';Value='';Texto=''}) }
  foreach($r in $rows){ $out.Add($r) }
  if($d -lt $maxDepth){
   $subs = @(); try{ $subs = @($k.GetSubKeyNames()) }catch{}
   foreach($s in ($subs | Sort-Object -Descending)){
    try{ $sk = $k.OpenSubKey($s); if($null -ne $sk){ $stack.Push(@($sk,($d+1))) } }catch{ LG WARN ("Subclave {0}\{1}: {2}" -f $k.Name,$s,$_.Exception.Message) }
   }
  }
 }
 $out.ToArray()
}
function LoadedUserSids{
 $r = @()
 try{ $r = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-[\d-]+$' } | ForEach-Object { $_.PSChildName }) }catch{ LG WARN "HKEY_USERS: $($_.Exception.Message)" }
 $r
}
function ExePath([string]$cmd){
 if([string]::IsNullOrWhiteSpace($cmd)){ return $null }
 $c = [Environment]::ExpandEnvironmentVariables($cmd.Trim())
 if($c.StartsWith('"')){ $c = $c.Substring(1); $i = $c.IndexOf('"'); if($i -gt 0){ $c = $c.Substring(0,$i) } }
 else{ $m = [regex]::Match($c,'^(.+?\.(exe|dll|sys|com|scr|cpl|ocx|bat|cmd|ps1|vbs|js))(\s|,|$)','IgnoreCase'); if($m.Success){ $c = $m.Groups[1].Value } }
 $c = $c -replace '^\\\?\?\\',''
 if($c -match '^(?i)\\SystemRoot\\'){ $c = Join-Path $env:SystemRoot $c.Substring(12) }
 elseif($c -match '^(?i)system32\\'){ $c = Join-Path $env:SystemRoot $c }
 if($c -notmatch '^[A-Za-z]:\\'){
  $w = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if($w){ $c = [string](P $w 'Source') } else { return $null }
 }
 $c
}
function UserWritable([string]$path){ $path = ([string]$path).Trim().TrimStart('"'); return ($path -match '(?i)\\(AppData|Temp|Downloads|Descargas|Desktop|Escritorio)\\|^(?i)[A-Z]:\\(Users\\Public|ProgramData|Windows\\Temp|PerfLogs)\\|\\\$Recycle\.Bin\\') }

# ---------------------------------------------------------------- progreso y fases
function ShowProg([string]$status,[int]$step,[int]$total,[double]$sub=-1){
 $pct = 0
 if($total -gt 0){
  $pct = [math]::Floor((($step-1)/$total)*100)
  if($sub -ge 0){ $pct = [math]::Min(99,[math]::Floor((($step-1 + ($sub/100))/$total)*100)) }
 }
 try{ Write-Progress -Activity "EviDumpWin $($script:Version) - Adquisicion Forense" -Status $status -PercentComplete $pct }catch{}
}
function SubProg([string]$status,[int]$i,[int]$n){ if($n -le 0){ $n = 1 }; ShowProg -status $status -step $script:ProgressCurrent -total $script:ProgressTotal -sub ([math]::Min(99,(($i/$n)*100))) }
function EndProg{ try{ Write-Progress -Activity "EviDumpWin $($script:Version) - Adquisicion Forense" -Completed }catch{} }
function RunCollect([string]$name,[scriptblock]$sb){
 $script:ProgressCurrent++
 ShowProg -status ("Fase {0}/{1}: {2}" -f $script:ProgressCurrent,$script:ProgressTotal,$name) -step $script:ProgressCurrent -total $script:ProgressTotal
 Info ("[{0}/{1}] {2}" -f $script:ProgressCurrent,$script:ProgressTotal,$name)
 LG INFO "Inicio fase: $name"
 $script:PhaseWarnings = 0
 $sw = [Diagnostics.Stopwatch]::StartNew()
 $estado = 'OK'; $det = ''
 try{
  & $sb | Out-Null
  if($script:PhaseWarnings -gt 0){ $estado = 'OK con avisos'; $det = "$($script:PhaseWarnings) avisos en el log" }
 }catch{
  $estado = 'ERROR'; $det = $_.Exception.Message
  LG ERROR ("{0}: {1} (linea {2})" -f $name,$_.Exception.Message,$_.InvocationInfo.ScriptLineNumber)
 }
 $sw.Stop()
 $script:Results.Add([pscustomobject]@{Nombre=$name;Estado=$estado;Avisos=$script:PhaseWarnings;Segundos=[math]::Round($sw.Elapsed.TotalSeconds,2);Detalle=$det})
 LG INFO ("Fin fase: {0} -> {1} ({2}s)" -f $name,$estado,[math]::Round($sw.Elapsed.TotalSeconds,2))
 if($estado -eq 'ERROR'){ Fail "$name fallo: $det" } elseif($estado -eq 'OK'){ Ok ("{0} completado en {1}s" -f $name,[math]::Round($sw.Elapsed.TotalSeconds,2)) } else { Warn ("{0} completado con {1} avisos en {2}s" -f $name,$script:PhaseWarnings,[math]::Round($sw.Elapsed.TotalSeconds,2)) }
}

# ---------------------------------------------------------------- asistente y preparacion del caso
function Banner{
 try{ if($script:Interactive){ Clear-Host } }catch{}
 C '============================================================' Cyan
 C ("      EviDumpWin Forensic Collector {0}  - By: Mayky" -f $script:Version) Yellow
 C '============================================================' Cyan
 Write-Host ''
 Write-Host " Equipo        : $env:COMPUTERNAME"
 Write-Host " Usuario       : $env:USERDOMAIN\$env:USERNAME"
 Write-Host " Fecha         : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss zzz')"
 Write-Host " Administrador : $(if($script:IsAdmin){'Si'}else{'No'})"
 Write-Host " PowerShell    : $($PSVersionTable.PSVersion)"
 Write-Host ''
}
function TryElevate{
 if($script:IsAdmin -or -not $script:Interactive){ return }
 Warn 'No se esta ejecutando como administrador: hives HKLM, EVTX de Seguridad, Prefetch y ficheros bloqueados no se podran adquirir.'
 if(-not $PSCommandPath){ return }
 if(-not (YesNo 'Relanzar EviDumpWin elevado (UAC)?' $true)){ return }
 try{
  $exe = (Get-Process -Id $PID).Path
  Start-Process -FilePath $exe -Verb RunAs -WorkingDirectory (Split-Path -Parent $PSCommandPath) -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath)) | Out-Null
  Ok 'Se ha abierto una nueva consola elevada. Esta ventana se cerrara.'
  exit 0
 }catch{ Warn "No se pudo elevar: $($_.Exception.Message). Se continua sin privilegios." }
}
function FullPath([string]$p){ try{ return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($p) }catch{ return [IO.Path]::GetFullPath($p) } }
function ProtectCase{
 $ErrorActionPreference = 'Continue'
 $sid = ''; try{ $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }catch{}
 $args2 = @($script:CaseRoot,'/inheritance:r','/grant:r','*S-1-5-32-544:(OI)(CI)F','*S-1-5-18:(OI)(CI)F')
 if($sid){ $args2 += "*$($sid):(OI)(CI)F" }
 $global:LASTEXITCODE = 0
 $o = ''
 try{ $o = & icacls.exe @args2 2>&1 | Out-String }catch{ $o = $_.Exception.Message; $global:LASTEXITCODE = -1 }
 if($global:LASTEXITCODE -eq 0){ LG INFO 'Permisos del caso restringidos a Administradores, SYSTEM y operador.'; Ok 'Permisos de la carpeta del caso restringidos.' }
 else{ LG WARN ("No se pudieron restringir permisos del caso (FAT/exFAT o sin permisos): {0}" -f ($o -replace '\s+',' ')); Warn 'No se pudieron restringir los permisos del caso (ver log).' }
}
function Setup{
 Banner
 TryElevate
 $defRoot = $null
 if($PSScriptRoot){ $defRoot = Join-Path $PSScriptRoot 'EviDumpWin-Cases' } else { $defRoot = Join-Path (Get-Location).ProviderPath 'EviDumpWin-Cases' }
 if($defRoot -match '(?i)\\Windows\\(System32|SysWOW64)\\'){ $defRoot = Join-Path $env:SystemDrive 'EviDumpWin-Cases' }
 while($true){
  $root = FullPath (Ask 'Ruta base del caso (recomendado: unidad externa)' $defRoot)
  $drive = ''; try{ $drive = [IO.Path]::GetPathRoot($root) }catch{}
  if($drive -and $env:SystemDrive -and $drive.TrimEnd('\') -ieq $env:SystemDrive){
   Warn "La ruta esta en la unidad del sistema ($env:SystemDrive): se escribira sobre el disco investigado."
   if(-not (YesNo 'Continuar igualmente?' $true)){ continue }
  }
  try{
   if(-not $root.StartsWith('\\')){ $di = New-Object IO.DriveInfo($drive); $free = [math]::Round($di.AvailableFreeSpace/1GB,2); Info "Espacio libre en destino: $free GB"; if($free -lt 5){ Warn 'Menos de 5 GB libres: la adquisicion Completa/Pro puede no caber.' } }
  }catch{}
  break
 }
 $case = Safe (Ask 'Nombre del caso' ("{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss')))
 $script:Investigator = Ask 'Investigador / operador' "$env:USERDOMAIN\$env:USERNAME"
 $script:CaseDesc = Ask 'Motivo o referencia del caso' 'Sin especificar'
 $opts = @('Rapido   - evidencia volatil, configuracion y actividad (sin copias pesadas)','Completo - recomendado: + EVTX, hives, navegadores, ficheros de sistema y timeline','Pro      - todo lo posible: + todos los EVTX, firmas/hash de binarios y extras')
 $idx = Menu 'Perfil de adquisicion' $opts 1
 $script:Level = $idx + 1
 $script:AcqProfile = @('Rapido','Completo','Pro')[$idx]
 $script:CaseRoot = Join-Path $root $case
 if(Test-Path -LiteralPath $script:CaseRoot){
  $script:CaseRoot = $script:CaseRoot + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
  Warn "El caso ya existia; se usara una carpeta nueva: $script:CaseRoot"
 }
 $script:Dirs = [ordered]@{}
 foreach($d in @(@('Reports','Reports'),@('Logs','Logs'),@('Json','Artifacts\Json'),@('Csv','Artifacts\Csv'),@('Raw','Artifacts\Raw'),@('Files','Artifacts\Files'),@('Registry','Artifacts\Registry'),@('Events','Artifacts\Events'),@('Browser','Artifacts\Browser'),@('Timeline','Artifacts\Timeline'))){ $script:Dirs[$d[0]] = Join-Path $script:CaseRoot $d[1] }
 foreach($p in $script:Dirs.Values){ New-Item -ItemType Directory -Path $p -Force | Out-Null }
 $script:ReportPath = Join-Path $script:Dirs.Reports 'Informe_Forense.html'
 $script:PdfPath = Join-Path $script:Dirs.Reports 'Informe_Forense.pdf'
 $script:JsonReportPath = Join-Path $script:Dirs.Reports 'Informe_Forense.json'
 $script:CsvReportDir = Join-Path $script:Dirs.Reports 'CSV'
 $script:LogPath = Join-Path $script:Dirs.Logs 'EviDumpWin.log'
 $script:CopyLogPath = Join-Path $script:Dirs.Logs 'acquisition_log.csv'
 $script:HashPath = Join-Path $script:Dirs.Reports 'hash_manifest_sha256.csv'
 [IO.File]::WriteAllText($script:LogPath,'',$script:Utf8Bom)
 LG INFO ("EviDumpWin {0} | Caso: {1} | Perfil: {2} | Operador: {3} | Admin: {4} | PS {5}" -f $script:Version,$script:CaseRoot,$script:AcqProfile,$script:Investigator,$script:IsAdmin,$PSVersionTable.PSVersion)
 LG INFO "Motivo: $script:CaseDesc"
 if(YesNo 'Restringir permisos de la carpeta del caso? (contendra hives y credenciales de navegador)' $true){ ProtectCase }
}
function InitReport{
 $tz = Get-TimeZone
 $off = $tz.GetUtcOffset($script:Now); $sign = '+'; if($off -lt [timespan]::Zero){ $sign = '-' }
 $script:CaseInfo = @(
  [pscustomobject]@{Campo='Version';Valor=$script:Version}
  [pscustomobject]@{Campo='Equipo';Valor=$env:COMPUTERNAME}
  [pscustomobject]@{Campo='Usuario ejecutor';Valor="$env:USERDOMAIN\$env:USERNAME"}
  [pscustomobject]@{Campo='Investigador';Valor=$script:Investigator}
  [pscustomobject]@{Campo='Motivo / referencia';Valor=$script:CaseDesc}
  [pscustomobject]@{Campo='Perfil';Valor=$script:AcqProfile}
  [pscustomobject]@{Campo='Elevado';Valor=$(if($script:IsAdmin){ 'Si' }else{ 'No' })}
  [pscustomobject]@{Campo='Inicio (local)';Valor=$script:Now.ToString('yyyy-MM-dd HH:mm:ss zzz')}
  [pscustomobject]@{Campo='Inicio (UTC)';Valor=$script:Now.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')}
  [pscustomobject]@{Campo='Zona horaria';Valor=("{0} (UTC{1}{2:hh\:mm})" -f $tz.DisplayName,$sign,$off.Duration())}
  [pscustomobject]@{Campo='PowerShell';Valor=[string]$PSVersionTable.PSVersion}
  [pscustomobject]@{Campo='Ruta del caso';Valor=$script:CaseRoot}
 )
 RT 'Datos del caso'
 Tbl @('Campo','Valor') $script:CaseInfo 0 'kv'
 RL '> Adquisicion en vivo: los resultados dependen de permisos, bloqueos y del estado del sistema. Las marcas de tiempo de artefactos se expresan en UTC salvo que se indique lo contrario.'
}
function LoadProfiles{
 $list = @()
 try{
  $list = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -and -not $_.Special } | ForEach-Object {
   [pscustomobject]@{SID=$_.SID;Usuario=(SidName $_.SID);Nombre=(Split-Path -Leaf $_.LocalPath);LocalPath=$_.LocalPath;Loaded=[bool]$_.Loaded;LastUseUtc=(UtcStr $_.LastUseTime)}
  })
 }catch{ LG WARN "Win32_UserProfile: $($_.Exception.Message)" }
 if($list.Count -eq 0 -and $env:USERPROFILE){
  $list = @([pscustomobject]@{SID='';Usuario="$env:USERDOMAIN\$env:USERNAME";Nombre=$env:USERNAME;LocalPath=$env:USERPROFILE;Loaded=$true;LastUseUtc=''})
 }
 $script:UserProfiles = @($list | Where-Object { Test-Path -LiteralPath $_.LocalPath })
}

# ---------------------------------------------------------------- fase: sistema
function CollectSystem{
 $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
 $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
 $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
 $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
 $tz = Get-TimeZone
 $ram = 0; if($cs -and $cs.TotalPhysicalMemory){ $ram = [math]::Round($cs.TotalPhysicalMemory/1GB,2) }
 $sb = 'Desconocido'; try{ if(Confirm-SecureBootUEFI -ErrorAction Stop){ $sb = 'Activo' } else { $sb = 'Inactivo' } }catch{ $sb = 'No disponible (BIOS legacy o sin admin)' }
 $sum = [pscustomobject]@{
  Equipo=$env:COMPUTERNAME
  SO=$(if($os){ $os.Caption }else{ 'No disponible' })
  Version=$(if($os){ $os.Version }else{ '-' })
  Build=$(if($os){ $os.BuildNumber }else{ '-' })
  DisplayVersion=(RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
  Arquitectura=$(if($os){ $os.OSArchitecture }else{ '-' })
  InstalacionUtc=$(if($os){ UtcStr $os.InstallDate }else{ '' })
  ArranqueUtc=$(if($os){ UtcStr $os.LastBootUpTime }else{ '' })
  HoraLocal=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
  HoraUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
  Zona=$tz.DisplayName
  ZonaId=$tz.Id
  Fabricante=$(if($cs){ $cs.Manufacturer }else{ '-' })
  Modelo=$(if($cs){ $cs.Model }else{ '-' })
  Dominio=$(if($cs){ $cs.Domain }else{ '-' })
  EnDominio=$(if($cs){ $cs.PartOfDomain }else{ '-' })
  CPU=$(if($cpu){ $cpu.Name }else{ '-' })
  RAMGB=$ram
  BIOS=$(if($bios){ $bios.SMBIOSBIOSVersion }else{ '-' })
  Serie=$(if($bios){ $bios.SerialNumber }else{ '-' })
  SecureBoot=$sb
  PowerShell=[string]$PSVersionTable.PSVersion
 }
 $script:Data['system'] = $sum
 $vol=@(); try{ $vol=@(Get-Volume -ErrorAction Stop | Select-Object DriveLetter,FileSystemLabel,FileSystem,DriveType,SizeRemaining,Size,HealthStatus) }catch{ LG WARN "Get-Volume: $($_.Exception.Message)" }
 $disk=@(); try{ $disk=@(Get-Disk -ErrorAction Stop | Select-Object Number,FriendlyName,SerialNumber,BusType,PartitionStyle,HealthStatus,Size) }catch{ LG WARN "Get-Disk: $($_.Exception.Message)" }
 $part=@(); try{ $part=@(Get-Partition -ErrorAction Stop | Select-Object DiskNumber,PartitionNumber,DriveLetter,Type,GptType,Size,Offset) }catch{ LG WARN "Get-Partition: $($_.Exception.Message)" }
 $bl=@(); try{ $bl=@(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,ProtectionStatus,EncryptionMethod,VolumeStatus,EncryptionPercentage,@{n='Protectores';e={ (@($_.KeyProtector) | ForEach-Object { [string](P $_ 'KeyProtectorType') }) -join ', ' }}) }catch{ LG WARN "BitLocker: $($_.Exception.Message)" }
 $shadow=@(); try{ $shadow=@(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object ID,VolumeName,DeviceObject,@{n='InstallDateUtc';e={ UtcStr $_.InstallDate }}) }catch{ LG WARN "Shadow copies: $($_.Exception.Message)" }
 $envv=@(Get-ChildItem Env: | Select-Object Name,Value)
 ExportSet 'system_summary' $sum -Single -NoCsv
 ExportSet 'volume_inventory' $vol
 ExportSet 'disk_inventory' $disk
 ExportSet 'partition_inventory' $part
 ExportSet 'bitlocker_status' $bl
 ExportSet 'shadow_copies' $shadow
 ExportSet 'environment_variables' $envv
 CmdOut 'systeminfo' { systeminfo }
 CmdOut 'w32tm_status' { w32tm /query /status }
 CmdOut 'vssadmin_shadows' { vssadmin list shadows }
 CmdOut 'manage_bde_status' { manage-bde -status }
 RT 'Sistema'
 Tbl @('Equipo','SO','DisplayVersion','Build','Dominio','CPU','RAMGB','Zona','ArranqueUtc','SecureBoot') @($sum)
 RL ("Volumenes: {0} / Discos: {1} / Shadow copies: {2}" -f $vol.Count,$disk.Count,$shadow.Count); RL ''
 ST 'Sistema' 'OK' ("{0} / Build {1} / {2} GB" -f ((@($sum.SO,$sum.DisplayVersion) | Where-Object { $_ }) -join ' '),$sum.Build,$sum.RAMGB)
}

# ---------------------------------------------------------------- fase: usuarios y sesiones
function CollectUsers{
 $users=@(); try{ $users=@(Get-LocalUser -ErrorAction Stop | Select-Object Name,Enabled,@{n='SID';e={ [string]$_.SID }},Description,@{n='LastLogonUtc';e={ UtcStr $_.LastLogon }},@{n='PasswordLastSetUtc';e={ UtcStr $_.PasswordLastSet }},PasswordRequired,@{n='AccountExpires';e={ [string]$_.AccountExpires }},PrincipalSource) }catch{ LG WARN "Get-LocalUser: $($_.Exception.Message)"; CmdOut 'net_user' { net user } }
 $groups=@(); try{ $groups=@(Get-LocalGroup -ErrorAction Stop | Select-Object Name,@{n='SID';e={ [string]$_.SID }},Description) }catch{ LG WARN "Get-LocalGroup: $($_.Exception.Message)" }
 $adminName = SidName 'S-1-5-32-544'
 $adminShort = $adminName; if($adminShort -match '\\'){ $adminShort = $adminShort.Split('\')[-1] }
 if(-not $adminShort){ $adminShort = 'Administrators' }
 $admins=@()
 try{ $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object Name,ObjectClass,@{n='SID';e={ [string]$_.SID }},PrincipalSource) }
 catch{ LG WARN "Get-LocalGroupMember ($adminShort): $($_.Exception.Message). Se usa net localgroup." }
 CmdOut 'net_localgroup_administradores' ([scriptblock]::Create("net localgroup `"$adminShort`""))
 $profiles = $script:UserProfiles
 $logonUser = @{}
 try{
  foreach($lu in @(Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop)){
   $a = P $lu 'Antecedent'; $d = P $lu 'Dependent'
   $id = [string](P $d 'LogonId'); if($id){ $logonUser[$id] = ("{0}\{1}" -f (P $a 'Domain'),(P $a 'Name')) }
  }
 }catch{ LG WARN "Win32_LoggedOnUser: $($_.Exception.Message)" }
 $ltype = @{0='System';2='Interactive';3='Network';4='Batch';5='Service';7='Unlock';8='NetworkCleartext';9='NewCredentials';10='RemoteInteractive';11='CachedInteractive'}
 $logons=@(); try{ $logons=@(Get-CimInstance Win32_LogonSession -ErrorAction Stop | ForEach-Object { $t=[int]$_.LogonType; [pscustomobject]@{LogonId=$_.LogonId;Usuario=$(if($logonUser.ContainsKey([string]$_.LogonId)){ $logonUser[[string]$_.LogonId] }else{ '' });LogonType=$t;Tipo=$(if($ltype.ContainsKey($t)){ $ltype[$t] }else{ 'Otro' });StartTimeUtc=(UtcStr $_.StartTime);AuthenticationPackage=$_.AuthenticationPackage} } | Sort-Object StartTimeUtc -Descending) }catch{ LG WARN "Win32_LogonSession: $($_.Exception.Message)" }
 $script:Data['users'] = $users
 ExportSet 'local_users' $users
 ExportSet 'local_groups' $groups
 ExportSet 'administrators_members' $admins
 ExportSet 'user_profiles' $profiles
 ExportSet 'logon_sessions' $logons
 CmdOut 'quser' { quser }
 CmdOut 'qwinsta' { qwinsta }
 CmdOut 'klist' { klist }
 RT 'Usuarios y sesiones'
 Tbl @('Name','Enabled','SID','LastLogonUtc','PasswordLastSetUtc') $users
 RL "Miembros de $($adminShort):"; RL ''
 Tbl @('Name','ObjectClass','PrincipalSource') $admins
 RL 'Perfiles:'; RL ''
 Tbl @('Usuario','LocalPath','Loaded','LastUseUtc') $profiles
 RL 'Sesiones interactivas/remotas:'; RL ''
 Tbl @('Usuario','Tipo','StartTimeUtc','AuthenticationPackage') @($logons | Where-Object { $_.LogonType -in 2,10,11 }) 20
 ST 'Usuarios' 'OK' ("{0} cuentas locales / {1} administradores / {2} perfiles / {3} sesiones" -f $users.Count,$admins.Count,$profiles.Count,$logons.Count)
}

# ---------------------------------------------------------------- fase: red
function ProcMap{
 if($script:Data.ContainsKey('procmap')){ return $script:Data['procmap'] }
 $m = @{}
 try{ foreach($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)){ $m[[int]$p.ProcessId] = [pscustomobject]@{Name=$p.Name;Path=$p.ExecutablePath} } }catch{ LG WARN "Win32_Process: $($_.Exception.Message)" }
 $script:Data['procmap'] = $m
 $m
}
function CollectNetwork{
 $pm = ProcMap
 $pn = { param($id) if($pm.ContainsKey([int]$id)){ $pm[[int]$id].Name } else { '' } }
 $pp = { param($id) if($pm.ContainsKey([int]$id)){ $pm[[int]$id].Path } else { '' } }
 $ip=@(); try{ $ip=@(Get-NetIPConfiguration -All -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
   InterfaceAlias=(P $_ 'InterfaceAlias'); InterfaceDescription=(P $_ 'InterfaceDescription')
   IPv4=((@(P $_ 'IPv4Address') | Where-Object { $_ } | ForEach-Object { P $_ 'IPAddress' }) -join ', ')
   IPv6=((@(P $_ 'IPv6Address') | Where-Object { $_ } | ForEach-Object { P $_ 'IPAddress' }) -join ', ')
   Gateway=((@(P $_ 'IPv4DefaultGateway') | Where-Object { $_ } | ForEach-Object { P $_ 'NextHop' }) -join ', ')
   DNS=((@(P $_ 'DNSServer') | Where-Object { $_ } | ForEach-Object { @(P $_ 'ServerAddresses') -join ', ' }) -join ', ')
  } }) }catch{ LG WARN "Get-NetIPConfiguration: $($_.Exception.Message)" }
 $ad=@(); try{ $ad=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed,MediaType,@{n='Virtual';e={ P $_ 'Virtual' }}) }catch{ LG WARN "Get-NetAdapter: $($_.Exception.Message)" }
 $tcp=@(); try{ $tcp=@(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object { [pscustomobject]@{State=[string]$_.State;LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;OwningProcess=$_.OwningProcess;Proceso=(& $pn $_.OwningProcess);Ruta=(& $pp $_.OwningProcess);CreationTimeUtc=(UtcStr (P $_ 'CreationTime'))} }) }catch{ LG WARN "Get-NetTCPConnection: $($_.Exception.Message)" }
 $udp=@(); try{ $udp=@(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object { [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess;Proceso=(& $pn $_.OwningProcess);Ruta=(& $pp $_.OwningProcess)} }) }catch{ LG WARN "Get-NetUDPEndpoint: $($_.Exception.Message)" }
 $dns=@(); try{ $dns=@(Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Name,Data,Type,Status,Section,TimeToLive) }catch{ LG WARN "Get-DnsClientCache: $($_.Exception.Message)" }
 $arp=@(); try{ $arp=@(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' } | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State) }catch{ LG WARN "Get-NetNeighbor: $($_.Exception.Message)" }
 $routes=@(); try{ $routes=@(Get-NetRoute -ErrorAction Stop | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,Protocol) }catch{ LG WARN "Get-NetRoute: $($_.Exception.Message)" }
 $shares=@(); try{ $shares=@(Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description,ShareType,FolderEnumerationMode) }catch{ LG WARN "Get-SmbShare: $($_.Exception.Message)" }
 $sess=@(); try{ $sess=@(Get-SmbSession -ErrorAction Stop | Select-Object ClientComputerName,ClientUserName,NumOpens,SecondsExists,Dialect) }catch{ LG WARN "Get-SmbSession: $($_.Exception.Message)" }
 $mapped=@(); try{ $mapped=@(Get-SmbMapping -ErrorAction Stop | Select-Object LocalPath,RemotePath,Status) }catch{ LG WARN "Get-SmbMapping: $($_.Exception.Message)" }
 $rdp = [pscustomobject]@{
  fDenyTSConnections=(RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')
  PortNumber=(RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber')
  UserAuthentication_NLA=(RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication')
  SecurityLayer=(RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer')
 }
 $script:Data['rdp'] = $rdp
 $wifi=@()
 try{
  $ErrorActionPreference = 'Continue'
  $wifi=@(netsh wlan show profiles 2>$null | Where-Object { $_ -match '(All User Profile|Perfil de todos los usuarios)\s*:' } | ForEach-Object { $parts = $_ -split ':\s*',2; if($parts.Count -eq 2){ $parts[1].Trim() } } | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{Perfil=$_} })
  $ErrorActionPreference = 'Stop'
 }catch{ $ErrorActionPreference = 'Stop'; LG WARN "netsh wlan: $($_.Exception.Message)" }
 $proxy = @(RegVals 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'HKLM')
 foreach($sid in LoadedUserSids){ $proxy += @(RegVals "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings" (SidName $sid) | Where-Object { $_.Name -match '(?i)proxy|autoconfig' }) }
 $portproxy = @(RegTree 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy' 3 | Where-Object { $_.Name })
 $script:Data['portproxy'] = $portproxy
 $script:Data['tcp'] = $tcp
 ExportSet 'network_ip_configuration' $ip
 ExportSet 'network_adapters' $ad
 ExportSet 'network_tcp_connections' $tcp
 ExportSet 'network_udp_endpoints' $udp
 ExportSet 'network_dns_cache' $dns
 ExportSet 'network_arp_cache' $arp
 ExportSet 'network_routes' $routes
 ExportSet 'network_shares' $shares
 ExportSet 'network_smb_sessions' $sess
 ExportSet 'network_smb_mappings' $mapped
 ExportSet 'network_rdp' $rdp -Single -NoCsv
 ExportSet 'network_wifi_profiles' $wifi
 ExportSet 'network_proxy_settings' $proxy
 ExportSet 'network_portproxy' $portproxy
 CopyFile (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') $script:Dirs.Files 'hosts' -NoVss | Out-Null
 CmdOut 'ipconfig_all' { ipconfig /all }
 CmdOut 'ipconfig_displaydns' { ipconfig /displaydns }
 CmdOut 'arp_a' { arp -a }
 CmdOut 'route_print' { route print }
 CmdOut 'netstat_anob' { netstat -anob }
 CmdOut 'netstat_ano' { netstat -ano }
 CmdOut 'nbtstat_c' { nbtstat -c }
 CmdOut 'net_use' { net use }
 CmdOut 'net_session' { net session }
 CmdOut 'net_share' { net share }
 CmdOut 'wlan_profiles' { netsh wlan show profiles }
 CmdOut 'winhttp_proxy' { netsh winhttp show proxy }
 CmdOut 'portproxy' { netsh interface portproxy show all }
 CmdOut 'firewall_profiles_raw' { netsh advfirewall show allprofiles }
 $est = @($tcp | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' })
 $lis = @($tcp | Where-Object { $_.State -eq 'Listen' })
 RT 'Red'
 Tbl @('InterfaceAlias','IPv4','Gateway','DNS') $ip
 RL 'Conexiones TCP establecidas (remotas):'; RL ''
 Tbl @('LocalPort','RemoteAddress','RemotePort','Proceso','OwningProcess') ($est | Sort-Object Proceso) 40
 RL 'Puertos TCP en escucha:'; RL ''
 Tbl @('LocalAddress','LocalPort','Proceso','OwningProcess') ($lis | Sort-Object { [int]$_.LocalPort }) 40
 ST 'Red' 'OK' ("{0} adaptadores / {1} TCP ({2} establecidas, {3} en escucha) / {4} DNS cache" -f $ad.Count,$tcp.Count,$est.Count,$lis.Count,$dns.Count)
}

# ---------------------------------------------------------------- fase: procesos, servicios y drivers
function CollectRuntime{
 $gp = @{}
 try{
  $src = $null
  if($script:IsAdmin){ $src = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue) } else { $src = @(Get-Process -ErrorAction SilentlyContinue) }
  foreach($p in $src){ $gp[[int]$p.Id] = $p }
 }catch{ LG WARN "Get-Process: $($_.Exception.Message)" }
 $proc=@()
 try{
  $proc=@(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
   $g = $null; if($gp.ContainsKey([int]$_.ProcessId)){ $g = $gp[[int]$_.ProcessId] }
   [pscustomobject]@{
    ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name
    Usuario=[string](P $g 'UserName'); ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine
    CreationUtc=(UtcStr $_.CreationDate); Company=[string](P $g 'Company'); FileVersion=[string](P $g 'FileVersion')
    SessionId=$_.SessionId; Handles=$_.HandleCount; Threads=$_.ThreadCount; WorkingSetMB=[math]::Round($_.WorkingSetSize/1MB,1)
   }
  } | Sort-Object ProcessId)
 }catch{ LG WARN "Win32_Process: $($_.Exception.Message)" }
 $pidName = @{}; foreach($p in $proc){ $pidName[[int]$p.ProcessId] = $p.Name }
 foreach($p in $proc){ $p | Add-Member -NotePropertyName ParentName -NotePropertyValue $(if($pidName.ContainsKey([int]$p.ParentProcessId)){ $pidName[[int]$p.ParentProcessId] }else{ '(no activo)' }) }
 $svc=@(); try{ $svc=@(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,ProcessId,PathName,Description | Sort-Object Name) }catch{ LG WARN "Win32_Service: $($_.Exception.Message)" }
 $drv=@(); try{ $drv=@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,PathName | Sort-Object Name) }catch{ LG WARN "Win32_SystemDriver: $($_.Exception.Message)" }
 $pipes=@(); try{ $pipes=@([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [pscustomobject]@{Pipe=$_.Replace('\\.\pipe\','')} }) }catch{ LG WARN "Named pipes: $($_.Exception.Message)" }
 $pref=@(); try{ $pref=@(Get-ChildItem -LiteralPath "$env:SystemRoot\Prefetch" -File -Force -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object Name,Length,@{n='CreationUtc';e={ UtcStr $_.CreationTime }},@{n='LastWriteUtc';e={ UtcStr $_.LastWriteTime }}) }catch{ LG WARN "Prefetch (requiere admin): $($_.Exception.Message)" }
 $script:Data['procs'] = $proc
 $script:Data['services'] = $svc
 $script:Data['drivers'] = $drv
 ExportSet 'processes' $proc
 ExportSet 'services' $svc
 ExportSet 'drivers' $drv
 ExportSet 'named_pipes' $pipes
 ExportSet 'prefetch_listing' $pref
 CmdOut 'tasklist_v' { tasklist /v }
 CmdOut 'tasklist_svc' { tasklist /svc }
 CmdOut 'driverquery_v' { driverquery /v }
 $sus = @($proc | Where-Object { $_.ExecutablePath -and (UserWritable $_.ExecutablePath) })
 RT 'Procesos, servicios y drivers'
 Tbl @('ProcessId','Name','ParentName','Usuario','CreationUtc','CommandLine') ($proc | Sort-Object CreationUtc -Descending) 30
 if($sus.Count -gt 0){ RL 'Procesos ejecutandose desde rutas escribibles por usuario:'; RL ''; Tbl @('ProcessId','Name','ExecutablePath','CommandLine') $sus 30 }
 ST 'Ejecucion' 'OK' ("{0} procesos / {1} servicios / {2} drivers / {3} prefetch" -f $proc.Count,$svc.Count,$drv.Count,$pref.Count)
}

# ---------------------------------------------------------------- fase: persistencia
function CollectPersistence{
 $run=@()
 $machineKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
 )
 foreach($k in $machineKeys){ $run += @(RegVals $k 'Maquina') }
 foreach($sid in LoadedUserSids){
  $u = SidName $sid; if(-not $u){ $u = $sid }
  foreach($rel in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce','Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run','Software\Microsoft\Windows NT\CurrentVersion\Windows')){
   $rows = @(RegVals "Registry::HKEY_USERS\$sid\$rel" $u)
   if($rel -like '*NT\CurrentVersion\Windows'){ $rows = @($rows | Where-Object { $_.Name -in 'Load','Run' }) }
   $run += $rows
  }
 }
 $other=@()
 $other += @(RegVals 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Winlogon' | Where-Object { $_.Name -in 'Shell','Userinit','Taskman','AppSetup','GinaDLL','VmApplet' })
 $other += @(RegVals 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit' | Where-Object { $_.Name -in 'AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs' })
 $other += @(RegVals 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit32' | Where-Object { $_.Name -in 'AppInit_DLLs','LoadAppInit_DLLs' })
 $other += @(RegVals 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LSA' | Where-Object { $_.Name -in 'Authentication Packages','Security Packages','Notification Packages','RunAsPPL','LsaCfgFlags' })
 $other += @(RegVals 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SessionManager' | Where-Object { $_.Name -in 'BootExecute','SetupExecute','Execute','S0InitialCommand' })
 $other += @(RegVals 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDlls' 'KnownDlls')
 $other += @(RegTree 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' 1 20000 'IFEO' | Where-Object { $_.Name -in 'Debugger','GlobalFlag','VerifierDlls' })
 $other += @(RegTree 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' 1 2000 'SilentProcessExit' | Where-Object { $_.Name })
 $other += @(RegTree 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' 1 20000 'ActiveSetup' | Where-Object { $_.Name -eq 'StubPath' })
 $other += @(RegTree 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects' 1 2000 'BHO')
 $other += @(RegVals 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' 'PrintMonitors')
 $other += @(RegTree 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' 1 2000 'PrintMonitors' | Where-Object { $_.Name -eq 'Driver' })
 $tasks=@()
 try{
  $tasks=@(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
   $t = $_
   $info = $null; try{ $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction Stop }catch{}
   [pscustomobject]@{
    TaskPath=$t.TaskPath; TaskName=$t.TaskName; State=[string]$t.State; Author=(P $t 'Author')
    Acciones=((@(P $t 'Actions') | Where-Object { $_ } | ForEach-Object { (("{0} {1}" -f (P $_ 'Execute'),(P $_ 'Arguments')).Trim()) + $(if(P $_ 'ClassId'){ ' COM:' + (P $_ 'ClassId') }else{ '' }) }) -join ' || ')
    Usuario=(P (P $t 'Principal') 'UserId'); RunLevel=[string](P (P $t 'Principal') 'RunLevel')
    Disparadores=((@(P $t 'Triggers') | Where-Object { $_ } | ForEach-Object { ([string](P (P $_ 'CimClass') 'CimClassName') -replace '^MSFT_Task','' -replace 'Trigger$','') }) -join ', ')
    UltimaEjecucion=$(if($info){ UtcStr (P $info 'LastRunTime') }else{ '' }); UltimoResultado=$(if($info){ P $info 'LastTaskResult' }else{ '' })
    Descripcion=(P $t 'Description')
   }
  })
 }catch{ LG WARN "Get-ScheduledTask: $($_.Exception.Message)" }
 $startup=@()
 $folders = @(,@('Todos los usuarios',(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')))
 foreach($p in $script:UserProfiles){ $folders += ,@($p.Usuario,(Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) }
 foreach($f in $folders){ try{ $startup += @(Get-ChildItem -LiteralPath $f[1] -Force -File -ErrorAction Stop | Where-Object { $_.Name -ne 'desktop.ini' } | Select-Object @{n='Usuario';e={ $f[0] }},Name,FullName,Length,@{n='CreationUtc';e={ UtcStr $_.CreationTime }},@{n='LastWriteUtc';e={ UtcStr $_.LastWriteTime }}) }catch{} }
 $wmiF=@(); try{ $wmiF=@(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | Select-Object Name,Query,QueryLanguage,EventNamespace) }catch{ LG WARN "WMI filtros: $($_.Exception.Message)" }
 $wmiC=@(); try{ $wmiC=@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop | ForEach-Object { [pscustomobject]@{Clase=$_.CimClass.CimClassName;Name=(P $_ 'Name');CommandLineTemplate=(P $_ 'CommandLineTemplate');ExecutablePath=(P $_ 'ExecutablePath');ScriptingEngine=(P $_ 'ScriptingEngine');ScriptText=(P $_ 'ScriptText');ScriptFileName=(P $_ 'ScriptFileName')} }) }catch{ LG WARN "WMI consumidores: $($_.Exception.Message)" }
 $wmiB=@(); try{ $wmiB=@(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { [pscustomobject]@{Filter=[string](P $_ 'Filter');Consumer=[string](P $_ 'Consumer')} }) }catch{ LG WARN "WMI bindings: $($_.Exception.Message)" }
 $startCmd=@(); try{ $startCmd=@(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name,Command,Location,User) }catch{ LG WARN "Win32_StartupCommand: $($_.Exception.Message)" }
 $script:Data['autoruns'] = $run
 $script:Data['persist_other'] = $other
 $script:Data['tasks'] = $tasks
 $script:Data['wmi'] = @($wmiF.Count,$wmiC.Count,$wmiB.Count)
 $script:Data['wmiConsumers'] = $wmiC
 ExportSet 'autoruns_registry' $run
 ExportSet 'persistence_registry_other' $other
 ExportSet 'scheduled_tasks' $tasks
 ExportSet 'startup_folders' $startup
 ExportSet 'startup_commands' $startCmd
 ExportSet 'wmi_event_filters' $wmiF
 ExportSet 'wmi_event_consumers' $wmiC
 ExportSet 'wmi_bindings' $wmiB
 CmdOut 'schtasks_query' { schtasks /query /fo LIST /v }
 RT 'Persistencia'
 Tbl @('Origen','Key','Name','Value') $run 40
 RL 'Otros puntos de persistencia (Winlogon, AppInit, LSA, IFEO, Active Setup...):'; RL ''
 Tbl @('Origen','Name','Value','KeyLastWriteUtc') $other 40
 RL 'Tareas programadas fuera de \Microsoft\:'; RL ''
 Tbl @('TaskPath','TaskName','State','Acciones','UltimaEjecucion') @($tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) 40
 RL 'Carpetas de inicio:'; RL ''
 Tbl @('Usuario','Name','LastWriteUtc') $startup
 RL ("WMI: {0} filtros / {1} consumidores / {2} bindings" -f $wmiF.Count,$wmiC.Count,$wmiB.Count); RL ''
 if($wmiC.Count -gt 0){ Tbl @('Clase','Name','CommandLineTemplate','ScriptText') $wmiC }
 ST 'Persistencia' 'OK' ("{0} entradas Run / {1} tareas / {2} inicio / WMI {3}-{4}-{5}" -f $run.Count,$tasks.Count,$startup.Count,$wmiF.Count,$wmiC.Count,$wmiB.Count)
}

# ---------------------------------------------------------------- fase: seguridad
function CollectSecurity{
 $fw=@(); try{ $fw=@(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked,LogFileName) }catch{ LG WARN "Firewall: $($_.Exception.Message)" }
 $mp=$null; $mpPref=$null; $mpDet=@()
 if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){
  try{ $mp = Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,AMProductVersion,AntivirusSignatureVersion,@{n='AntivirusSignatureLastUpdatedUtc';e={ UtcStr $_.AntivirusSignatureLastUpdated }},@{n='QuickScanEndTimeUtc';e={ UtcStr $_.QuickScanEndTime }} }catch{ LG WARN "Get-MpComputerStatus: $($_.Exception.Message)" }
  try{ $mpPref = Get-MpPreference -ErrorAction Stop | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,ExclusionPath,ExclusionExtension,ExclusionProcess,ExclusionIpAddress,PUAProtection,EnableControlledFolderAccess,MAPSReporting,SubmitSamplesConsent }catch{ LG WARN "Get-MpPreference: $($_.Exception.Message)" }
  try{ $mpDet = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID,@{n='InitialDetectionUtc';e={ UtcStr $_.InitialDetectionTime }},@{n='RemediationUtc';e={ UtcStr $_.RemediationTime }},ActionSuccess,ProcessName,DomainUser,@{n='Recursos';e={ @($_.Resources) -join ' ; ' }}) }catch{ LG WARN "Get-MpThreatDetection: $($_.Exception.Message)" }
 } else { LG WARN 'Modulo Defender no disponible.' }
 $av=@(); try{ $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName,pathToSignedProductExe,productState,timestamp) }catch{ LG WARN "SecurityCenter2 (no existe en Windows Server): $($_.Exception.Message)" }
 $hf=@(); try{ $hf=@(Get-HotFix -ErrorAction Stop | Select-Object HotFixID,Description,InstalledBy,@{n='InstalledOn';e={ if($_.InstalledOn){ $_.InstalledOn.ToString('yyyy-MM-dd') } }} | Sort-Object InstalledOn -Descending) }catch{ LG WARN "Get-HotFix: $($_.Exception.Message)" }
 $soft=@()
 $hives = @(@('HKLM 64','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),@('HKLM 32','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'))
 foreach($sid in LoadedUserSids){ $hives += ,@(("Usuario " + (SidName $sid)),"Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall") }
 foreach($h in $hives){
  $root = OpenKey $h[1]; if($null -eq $root){ continue }
  foreach($sub in @($root.GetSubKeyNames())){
   try{
    $k = $root.OpenSubKey($sub); if($null -eq $k){ continue }
    $dn = $k.GetValue('DisplayName'); if(-not $dn){ continue }
    $soft += [pscustomobject]@{DisplayName=[string]$dn;DisplayVersion=[string]$k.GetValue('DisplayVersion');Publisher=[string]$k.GetValue('Publisher');InstallDate=[string]$k.GetValue('InstallDate');InstallLocation=[string]$k.GetValue('InstallLocation');UninstallString=[string]$k.GetValue('UninstallString');Origen=$h[0];Clave=$sub;KeyLastWriteUtc=(KeyLW $k)}
   }catch{ LG WARN ("Software {0}\{1}: {2}" -f $h[1],$sub,$_.Exception.Message) }
  }
 }
 $soft = @($soft | Sort-Object DisplayName,DisplayVersion)
 $cfg = New-Object System.Collections.Generic.List[object]
 $chk = @(
  @('UAC','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA'),
  @('UAC','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','ConsentPromptBehaviorAdmin'),
  @('UAC','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy'),
  @('Credenciales','HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential'),
  @('Credenciales','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL'),
  @('Credenciales','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','DisableRestrictedAdmin'),
  @('Credenciales','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel'),
  @('Credenciales','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','NoLMHash'),
  @('Credenciales','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','CachedLogonsCount'),
  @('Credenciales','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','AutoAdminLogon'),
  @('Credenciales','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultUserName'),
  @('SMB','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','SMB1'),
  @('SMB','HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature'),
  @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging'),
  @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging'),
  @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription','EnableTranscripting'),
  @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription','OutputDirectory'),
  @('Defender','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','DisableAntiSpyware'),
  @('Defender','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection','DisableRealtimeMonitoring'),
  @('Auditoria','HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','SCENoApplyLegacyAuditPolicy'),
  @('Auditoria','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled')
 )
 foreach($c in $chk){ $v = RegValue $c[1] $c[2]; $cfg.Add([pscustomobject]@{Area=$c[0];Clave=$c[1];Valor=$c[2];Dato=$(if($null -eq $v){ '(no definido)' }else{ ValText $v })}) }
 $roots=@(); try{ $roots=@(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Root' -ErrorAction Stop | Select-Object Subject,Issuer,Thumbprint,@{n='NotBefore';e={ $_.NotBefore.ToString('yyyy-MM-dd') }},@{n='NotAfter';e={ $_.NotAfter.ToString('yyyy-MM-dd') }}) }catch{ LG WARN "Certificados raiz: $($_.Exception.Message)" }
 $script:Data['firewall'] = $fw
 $script:Data['defender'] = $mp
 $script:Data['defenderPref'] = $mpPref
 $script:Data['defenderDet'] = $mpDet
 $script:Data['secconfig'] = $cfg.ToArray()
 ExportSet 'firewall_profiles' $fw
 ExportSet 'windows_defender_status' $mp -Single -NoCsv
 ExportSet 'windows_defender_preferences' $mpPref -Single -NoCsv
 ExportSet 'windows_defender_detections' $mpDet
 ExportSet 'antivirus_products' $av
 ExportSet 'hotfixes' $hf
 ExportSet 'installed_software' $soft
 ExportSet 'security_configuration' $cfg.ToArray()
 ExportSet 'certificates_root_machine' $roots
 CmdOut 'auditpol' { auditpol /get /category:* }
 CmdOut 'whoami_all' { whoami /all }
 CmdOut 'gpresult_r' { gpresult /r }
 CmdOut 'net_accounts' { net accounts }
 RT 'Seguridad'
 Tbl @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction') $fw
 if($mp){ Tbl @('AntivirusEnabled','RealTimeProtectionEnabled','IsTamperProtected','AntivirusSignatureVersion','AntivirusSignatureLastUpdatedUtc') @($mp) }
 RL 'Configuracion de seguridad relevante:'; RL ''
 Tbl @('Area','Valor','Dato') $cfg.ToArray()
 if($mpDet.Count -gt 0){ RL 'Detecciones de Defender:'; RL ''; Tbl @('InitialDetectionUtc','ProcessName','DomainUser','Recursos') $mpDet 20 }
 ST 'Seguridad' 'OK' ("{0} hotfixes / {1} productos AV / {2} programas / {3} detecciones Defender" -f $hf.Count,$av.Count,$soft.Count,$mpDet.Count)
}

# ---------------------------------------------------------------- fase: registro y dispositivos
function CollectRegistryDevices{
 $usbStor = @(RegTree 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' 2 20000 'USBSTOR' | Where-Object { $_.Name -in '','FriendlyName','DeviceDesc','Mfg','ContainerID','HardwareID' })
 $usb = @(RegTree 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB' 2 20000 'USB' | Where-Object { $_.Name -in '','FriendlyName','DeviceDesc','Mfg','LocationInformation','ContainerID' })
 $wpd = @(RegTree 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices' 1 5000 'WPD' | Where-Object { $_.Name -in '','FriendlyName' })
 $emd = @(RegTree 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt' 1 5000 'EMDMgmt')
 $mounted = @(RegVals 'HKLM:\SYSTEM\MountedDevices' 'MountedDevices')
 $bam = New-Object System.Collections.Generic.List[object]
 foreach($base in @('HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings','HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')){
  $root = OpenKey $base; if($null -eq $root){ continue }
  foreach($sid in @($root.GetSubKeyNames())){
   $k = $null; try{ $k = $root.OpenSubKey($sid) }catch{}
   if($null -eq $k){ continue }
   foreach($n in @($k.GetValueNames())){
    if($n -in 'Version','SequenceNumber'){ continue }
    $v = $k.GetValue($n)
    if($v -is [byte[]]){ $bam.Add([pscustomobject]@{SID=$sid;Usuario=(SidName $sid);Ejecutable=$n;UltimaEjecucionUtc=(FileTimeStr $v 0)}) }
   }
  }
 }
 $netProf = New-Object System.Collections.Generic.List[object]
 $nl = OpenKey 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
 if($nl){
  foreach($g in @($nl.GetSubKeyNames())){
   try{ $k = $nl.OpenSubKey($g); if($null -eq $k){ continue }
    $cat = $k.GetValue('Category'); $nt = $k.GetValue('NameType')
    $netProf.Add([pscustomobject]@{Perfil=[string]$k.GetValue('ProfileName');Descripcion=[string]$k.GetValue('Description');Categoria=$(if($null -eq $cat){ '' }else{ switch([int]$cat){0{'Publica'}1{'Privada'}2{'Dominio'}default{[string]$cat}} });Tipo=$(if($null -eq $nt){ '' }else{ switch([int]$nt){6{'Cable'}23{'VPN'}71{'Wi-Fi'}243{'Movil'}default{[string]$nt}} });CreadaLocal=(SysTimeStr ($k.GetValue('DateCreated')));UltimaConexionLocal=(SysTimeStr ($k.GetValue('DateLastConnected')));Guid=$g})
   }catch{ LG WARN "NetworkList $($g): $($_.Exception.Message)" }
  }
 }
 $ua = New-Object System.Collections.Generic.List[object]
 $rd = New-Object System.Collections.Generic.List[object]
 $mru = New-Object System.Collections.Generic.List[object]
 $bags = New-Object System.Collections.Generic.List[object]
 $sids = @(LoadedUserSids)
 $i = 0
 foreach($sid in $sids){
  $i++; SubProg ("Registro de usuario {0}/{1}" -f $i,$sids.Count) $i $sids.Count
  $u = SidName $sid; if(-not $u){ $u = $sid }
  $hk = "Registry::HKEY_USERS\$sid"
  $uaRoot = OpenKey "$hk\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
  if($uaRoot){
   foreach($g in @($uaRoot.GetSubKeyNames())){
    $ck = $null; try{ $ck = $uaRoot.OpenSubKey("$g\Count") }catch{}
    if($null -eq $ck){ continue }
    $lw = KeyLW $ck
    foreach($n in @($ck.GetValueNames())){
     $b = $ck.GetValue($n); if(-not ($b -is [byte[]])){ continue }
     $cnt = $null; $focus = $null; $last = ''
     if($b.Length -ge 72){ $cnt = [BitConverter]::ToInt32($b,4); $focus = [BitConverter]::ToInt32($b,12); $last = FileTimeStr $b 60 }
     elseif($b.Length -ge 16){ $cnt = [BitConverter]::ToInt32($b,4) - 5; $last = FileTimeStr $b 8 }
     $ua.Add([pscustomobject]@{Usuario=$u;Guid=$g;Programa=(Rot13 $n);Ejecuciones=$cnt;FocoMs=$focus;UltimaEjecucionUtc=$last;KeyLastWriteUtc=$lw})
    }
   }
  }
  $rdRoot = "$hk\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
  $rk = OpenKey $rdRoot
  if($rk){
   $keys = @(,@('',$rk)); foreach($s in @($rk.GetSubKeyNames())){ try{ $sk = $rk.OpenSubKey($s); if($sk){ $keys += ,@($s,$sk) } }catch{} }
   foreach($pair in $keys){
    $k = $pair[1]; $lw = KeyLW $k
    $order = @{}; $ml = $k.GetValue('MRUListEx')
    if($ml -is [byte[]]){ for($o=0;$o -le $ml.Length-4;$o+=4){ $idx = [BitConverter]::ToInt32($ml,$o); if($idx -lt 0){ break }; $order[[string]$idx] = $o/4 } }
    foreach($n in @($k.GetValueNames())){
     if($n -eq 'MRUListEx'){ continue }
     $b = $k.GetValue($n); if(-not ($b -is [byte[]])){ continue }
     $name = [Text.Encoding]::Unicode.GetString($b); $z = $name.IndexOf([char]0); if($z -ge 0){ $name = $name.Substring(0,$z) }
     $pos = $null; if($order.ContainsKey($n)){ $pos = $order[$n] }
     $rd.Add([pscustomobject]@{Usuario=$u;Extension=$(if($pair[0]){ $pair[0] }else{ '(todas)' });Orden=$pos;Nombre=$name;KeyLastWriteUtc=$(if($pos -eq 0){ $lw }else{ '' })})
    }
   }
  }
  foreach($m in @(
   @('RunMRU','Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',0),
   @('TypedPaths','Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths',0),
   @('WordWheelQuery','Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery',0),
   @('ComDlg32','Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32',2),
   @('MountPoints2','Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2',1),
   @('TypedURLs','Software\Microsoft\Internet Explorer\TypedURLs',0),
   @('RDP Servers','Software\Microsoft\Terminal Server Client\Servers',1),
   @('RDP Default','Software\Microsoft\Terminal Server Client\Default',0),
   @('Sysinternals','Software\Sysinternals',1),
   @('MapNetworkDrive','Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU',0)
  )){
   foreach($r in @(RegTree "$hk\$($m[1])" ([int]$m[2]) 5000 ("{0} | {1}" -f $u,$m[0]) -Strings)){ if($r.Name -ne 'MRUListEx'){ $mru.Add($r) } }
  }
  foreach($b in @("$hk\Software\Microsoft\Windows\Shell\BagMRU","Registry::HKEY_USERS\$($sid)_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU")){
   foreach($r in @(RegTree $b 30 20000 $u -Strings)){ if($r.Name -and $r.Name -notin 'MRUListEx','NodeSlot','NodeSlots'){ $bags.Add($r) } }
  }
 }
 $script:Data['bam'] = $bam.ToArray()
 $script:Data['userassist'] = $ua.ToArray()
 ExportSet 'registry_usbstor' $usbStor
 ExportSet 'registry_usb' $usb
 ExportSet 'registry_portable_devices' $wpd
 ExportSet 'registry_emdmgmt' $emd
 ExportSet 'registry_mounted_devices' $mounted
 ExportSet 'registry_bam' $bam.ToArray()
 ExportSet 'registry_network_profiles' $netProf.ToArray()
 ExportSet 'registry_userassist' $ua.ToArray()
 ExportSet 'registry_recentdocs' $rd.ToArray()
 ExportSet 'registry_user_mru' $mru.ToArray()
 ExportSet 'registry_shellbags_raw' $bags.ToArray()
 CmdOut 'mountvol' { mountvol }
 $usbDev = @($usbStor | Where-Object { $_.Name -eq 'FriendlyName' })
 RT 'Registro y dispositivos'
 RL 'Dispositivos de almacenamiento USB (USBSTOR):'; RL ''
 Tbl @('Value','Key','KeyLastWriteUtc') $usbDev 30
 RL 'Ultimas ejecuciones (BAM):'; RL ''
 Tbl @('Usuario','Ejecutable','UltimaEjecucionUtc') ($bam.ToArray() | Sort-Object UltimaEjecucionUtc -Descending) 25
 RL 'Programas mas usados (UserAssist):'; RL ''
 Tbl @('Usuario','Programa','Ejecuciones','UltimaEjecucionUtc') ($ua.ToArray() | Where-Object { $_.UltimaEjecucionUtc } | Sort-Object UltimaEjecucionUtc -Descending) 25
 RL 'Redes conocidas:'; RL ''
 Tbl @('Perfil','Tipo','Categoria','CreadaLocal','UltimaConexionLocal') ($netProf.ToArray() | Sort-Object UltimaConexionLocal -Descending) 25
 RL ("Usuarios con hive cargada analizados: {0}. Los usuarios sin sesion se cubren con la copia de NTUSER.DAT/UsrClass.dat (perfil Completo/Pro)." -f $sids.Count); RL ''
 ST 'Dispositivos' 'OK' ("USB: {0} / BAM: {1} / UserAssist: {2} / RecentDocs: {3} / ShellBags: {4}" -f $usbDev.Count,$bam.Count,$ua.Count,$rd.Count,$bags.Count)
}

# ---------------------------------------------------------------- fase: actividad de usuario
function ListDir([string]$path,[string]$user,[string]$src,[int]$depth=0,[int]$max=5000){
 if(-not $path -or -not (Test-Path -LiteralPath $path -PathType Container)){ return }
 $items = @()
 try{
  if($depth -gt 0){ $items = @(Get-ChildItem -LiteralPath $path -Force -Recurse -Depth $depth -ErrorAction SilentlyContinue | Select-Object -First $max) }
  else{ $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Select-Object -First $max) }
 }catch{ LG WARN ("Listado {0}: {1}" -f $path,$_.Exception.Message) }
 $out = New-Object System.Collections.Generic.List[object]
 foreach($f in $items){
  $out.Add([pscustomobject]@{Usuario=$user;Fuente=$src;Nombre=$f.Name;Ruta=$f.FullName;Directorio=$f.PSIsContainer;Tamano=$(if($f.PSIsContainer){ $null }else{ $f.Length });CreacionUtc=(UtcStr $f.CreationTime);ModificacionUtc=(UtcStr $f.LastWriteTime);AccesoUtc=(UtcStr $f.LastAccessTime)})
 }
 $out.ToArray()
}
function ZoneInfo([string]$file){
 $z = [pscustomobject]@{ZoneId='';ReferrerUrl='';HostUrl=''}
 try{
  $lines = @(Get-Content -LiteralPath $file -Stream Zone.Identifier -ErrorAction Stop)
  foreach($l in $lines){ if($l -match '^(ZoneId|ReferrerUrl|HostUrl)=(.*)$'){ $z.($matches[1]) = $matches[2].Trim() } }
 }catch{}
 $z
}
function ParseRecycleI([string]$path){
 $b = $null; try{ $b = [IO.File]::ReadAllBytes($path) }catch{ LG WARN ("Papelera {0}: {1}" -f $path,$_.Exception.Message); return $null }
 if($b.Length -lt 24){ return $null }
 $ver = [BitConverter]::ToInt64($b,0)
 $orig = ''
 if($ver -eq 2 -and $b.Length -ge 28){ $len = [BitConverter]::ToInt32($b,24); $n = [math]::Min($len*2,$b.Length-28); if($n -gt 0){ $orig = [Text.Encoding]::Unicode.GetString($b,28,$n) } }
 elseif($ver -eq 1){ $n = [math]::Min(520,$b.Length-24); $orig = [Text.Encoding]::Unicode.GetString($b,24,$n) }
 $z = $orig.IndexOf([char]0); if($z -ge 0){ $orig = $orig.Substring(0,$z) }
 $rName = Join-Path (Split-Path -Parent $path) ('$R' + (Split-Path -Leaf $path).Substring(2))
 [pscustomobject]@{Fichero=$path;SID=(Split-Path -Leaf (Split-Path -Parent $path));Usuario=(SidName (Split-Path -Leaf (Split-Path -Parent $path)));RutaOriginal=$orig;TamanoOriginal=[BitConverter]::ToInt64($b,8);BorradoUtc=(FileTimeStr $b 16);ContenidoPresente=(Test-Path -LiteralPath $rName);Version=$ver}
}
function CollectUserActivity{
 $hist=@(); $recent=@(); $jump=@(); $down=@(); $desk=@(); $temp=@()
 $i = 0
 foreach($p in $script:UserProfiles){
  $i++; SubProg ("Actividad de {0} ({1}/{2})" -f $p.Nombre,$i,$script:UserProfiles.Count) $i ($script:UserProfiles.Count+1)
  $u = $p.Usuario; if(-not $u){ $u = $p.Nombre }
  $psrl = Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
  if(Test-Path -LiteralPath $psrl){
   foreach($h in @(Get-ChildItem -LiteralPath $psrl -Filter '*_history.txt' -File -Force -ErrorAction SilentlyContinue)){
    try{
     $ok = CopyFile $h.FullName (Join-Path $script:Dirs.Files ('PSReadLine\'+(Safe $p.Nombre))) -NoVss
     $lines = 0; try{ $lines = @(Get-Content -LiteralPath $h.FullName -ErrorAction Stop).Count }catch{}
     $hist += [pscustomobject]@{Usuario=$u;Fichero=$h.FullName;Lineas=$lines;ModificacionUtc=(UtcStr $h.LastWriteTime);Copiado=$ok}
    }catch{ LG WARN ("PSReadLine {0}: {1}" -f $h.FullName,$_.Exception.Message) }
   }
  }
  $rec = Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent'
  $recent += @(ListDir $rec $u 'Recent' 0 | Where-Object { -not $_.Directorio })
  $jump += @(ListDir (Join-Path $rec 'AutomaticDestinations') $u 'JumpList-Auto' 0)
  $jump += @(ListDir (Join-Path $rec 'CustomDestinations') $u 'JumpList-Custom' 0)
  foreach($f in @(ListDir (Join-Path $p.LocalPath 'Downloads') $u 'Downloads' 3)){
   if(-not $f.Directorio){ $z = ZoneInfo $f.Ruta; $f | Add-Member -NotePropertyName ZoneId -NotePropertyValue $z.ZoneId; $f | Add-Member -NotePropertyName HostUrl -NotePropertyValue $z.HostUrl; $f | Add-Member -NotePropertyName ReferrerUrl -NotePropertyValue $z.ReferrerUrl }
   $down += $f
  }
  $desk += @(ListDir (Join-Path $p.LocalPath 'Desktop') $u 'Desktop' 1)
  $temp += @(ListDir (Join-Path $p.LocalPath 'AppData\Local\Temp') $u 'Temp' 1 3000)
 }
 $temp += @(ListDir (Join-Path $env:SystemRoot 'Temp') 'SYSTEM' 'Windows\Temp' 1 3000)
 $recycle=@()
 $drives=@(); try{ $drives=@(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -in 2,3 } | ForEach-Object { $_.DeviceID }) }catch{ $drives=@($env:SystemDrive) }
 foreach($d in $drives){
  $rb = "$d\`$Recycle.Bin"
  if(-not (Test-Path -LiteralPath $rb)){ continue }
  foreach($f in @(Get-ChildItem -LiteralPath $rb -Recurse -Force -File -Filter '$I*' -ErrorAction SilentlyContinue)){ $r = ParseRecycleI $f.FullName; if($r){ $recycle += $r } }
 }
 $script:Data['fs_user'] = @($recent) + @($jump) + @($down) + @($desk) + @($temp)
 $script:Data['recycle'] = $recycle
 $script:Data['downloads'] = $down
 ExportSet 'powershell_history_files' $hist
 ExportSet 'recent_items' $recent
 ExportSet 'jumplists' $jump
 ExportSet 'downloads_listing' $down
 ExportSet 'desktop_listing' $desk
 ExportSet 'temp_listing' $temp
 ExportSet 'recycle_bin' $recycle
 RT 'Actividad de usuario'
 Tbl @('Usuario','Fichero','Lineas','ModificacionUtc') $hist
 RL 'Descargas recientes (con origen Mark-of-the-Web):'; RL ''
 Tbl @('Usuario','Nombre','ModificacionUtc','ZoneId','HostUrl') ($down | Where-Object { -not $_.Directorio } | Sort-Object ModificacionUtc -Descending) 25
 RL 'Papelera de reciclaje:'; RL ''
 Tbl @('Usuario','RutaOriginal','BorradoUtc','TamanoOriginal','ContenidoPresente') ($recycle | Sort-Object BorradoUtc -Descending) 25
 ST 'Actividad usuario' 'OK' ("{0} perfiles / PSReadLine: {1} / Recent: {2} / Descargas: {3} / Papelera: {4}" -f $script:UserProfiles.Count,$hist.Count,$recent.Count,@($down).Count,$recycle.Count)
}

# ---------------------------------------------------------------- fase: eventos
$script:EventLogs = @('Application','System','Security','Setup','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TerminalServices-LocalSessionManager/Operational','Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational','Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-Windows Defender/Operational','Microsoft-Windows-WMI-Activity/Operational','Microsoft-Windows-Bits-Client/Operational','Microsoft-Windows-SMBServer/Security','Microsoft-Windows-Windows Firewall With Advanced Security/Firewall','Microsoft-Windows-Sysmon/Operational')
$script:KeyEvents = @(
 @('Security',@(4624,4625,4648,4672,4688,4697,4698,4702,4719,4720,4722,4724,4728,4732,4738,4740,4756,1102)),
 @('System',@(7045,7040,104,6005,6006,6008,1074)),
 @('Microsoft-Windows-PowerShell/Operational',@(4103,4104)),
 @('Windows PowerShell',@(400,403,600)),
 @('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',@(21,22,23,24,25)),
 @('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',@(1149)),
 @('Microsoft-Windows-TaskScheduler/Operational',@(106,140,141,200,201)),
 @('Microsoft-Windows-Windows Defender/Operational',@(1116,1117,5001,5007,5010,5012)),
 @('Microsoft-Windows-WMI-Activity/Operational',@(5857,5858,5860,5861)),
 @('Microsoft-Windows-Bits-Client/Operational',@(59,60)),
 @('Microsoft-Windows-Sysmon/Operational',@(1,3,8,10,11,13,22))
)
$script:EventDesc = @{
 'Security|4624'='Inicio de sesion correcto';'Security|4625'='Inicio de sesion fallido';'Security|4648'='Logon con credenciales explicitas';'Security|4672'='Privilegios especiales asignados'
 'Security|4688'='Creacion de proceso';'Security|4697'='Servicio instalado';'Security|4698'='Tarea programada creada';'Security|4702'='Tarea programada modificada';'Security|4719'='Politica de auditoria cambiada'
 'Security|4720'='Cuenta creada';'Security|4722'='Cuenta habilitada';'Security|4724'='Reseteo de contrasena';'Security|4728'='Alta en grupo global';'Security|4732'='Alta en grupo local'
 'Security|4738'='Cuenta modificada';'Security|4740'='Cuenta bloqueada';'Security|4756'='Alta en grupo universal';'Security|1102'='Log de Seguridad borrado'
 'System|7045'='Servicio instalado';'System|7040'='Tipo de inicio de servicio cambiado';'System|104'='Log borrado';'System|6005'='Inicio del servicio de eventos';'System|6006'='Parada del servicio de eventos';'System|6008'='Apagado inesperado';'System|1074'='Apagado/reinicio solicitado'
 'Microsoft-Windows-PowerShell/Operational|4104'='Script block';'Microsoft-Windows-PowerShell/Operational|4103'='Ejecucion de modulo'
 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational|1149'='RDP autenticacion de red correcta';'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|21'='RDP logon';'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational|25'='RDP reconexion'
 'Microsoft-Windows-Windows Defender/Operational|1116'='Malware detectado';'Microsoft-Windows-Windows Defender/Operational|1117'='Accion contra malware';'Microsoft-Windows-Windows Defender/Operational|5001'='Proteccion en tiempo real desactivada';'Microsoft-Windows-Windows Defender/Operational|5007'='Configuracion de Defender cambiada'
}
function EvP($e,[int]$i){ try{ $ps = $e.Properties; if($ps -and $ps.Count -gt $i){ return [string]$ps[$i].Value } }catch{}; '' }
function EvDetail($e){
 $k = "$($e.LogName)|$($e.Id)"
 switch($k){
  'Security|4624' { return ("Usuario={0}\{1} Tipo={2} IP={3} Proceso={4}" -f (EvP $e 6),(EvP $e 5),(EvP $e 8),(EvP $e 18),(EvP $e 17)) }
  'Security|4625' { return ("Usuario={0}\{1} Tipo={2} IP={3} Estado={4}" -f (EvP $e 6),(EvP $e 5),(EvP $e 10),(EvP $e 19),(EvP $e 7)) }
  'Security|4648' { return ("Usuario={0} -> {1}\{2} Destino={3} Proceso={4}" -f (EvP $e 1),(EvP $e 6),(EvP $e 5),(EvP $e 8),(EvP $e 11)) }
  'Security|4688' { return ("Proceso={0} Linea={1} Padre={2} Usuario={3}" -f (EvP $e 5),(EvP $e 8),(EvP $e 13),(EvP $e 1)) }
  'Security|4720' { return ("Cuenta={0}\{1} Por={2}" -f (EvP $e 1),(EvP $e 0),(EvP $e 4)) }
  'Security|4697' { return ("Servicio={0} Ruta={1}" -f (EvP $e 4),(EvP $e 5)) }
  'Security|4698' { return ("Tarea={0} Por={1}" -f (EvP $e 4),(EvP $e 1)) }
  'System|7045' { return ("Servicio={0} Ruta={1} Cuenta={2}" -f (EvP $e 0),(EvP $e 1),(EvP $e 4)) }
 }
 ''
}
function ExportLog([string]$log,[string]$dir){
 $ErrorActionPreference = 'Continue'
 $evtx = Join-Path $dir ((Safe $log)+'.evtx')
 $global:LASTEXITCODE = 0
 $o = ''
 try{ $o = & wevtutil.exe epl $log $evtx /ow:true 2>&1 | Out-String }catch{ $o = $_.Exception.Message; $global:LASTEXITCODE = -1 }
 if($global:LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $evtx)){ AddStat 'Events'; AcqLog "EventLog:$log" $evtx 'wevtutil epl' 'OK'; return $true }
 LG WARN ("EVTX {0}: {1}" -f $log,($o -replace '\s+',' ').Trim())
 AcqLog "EventLog:$log" $evtx 'wevtutil epl' 'ERROR' (($o -replace '\s+',' ').Trim())
 return $false
}
function CollectEvents{
 $recentMax = 500; $keyMax = 2000; $days = 30
 if($script:Level -ge 3){ $recentMax = 2000; $keyMax = 10000; $days = 90 }
 $existing = @{}
 try{ foreach($l in @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue)){ $existing[$l.LogName] = $l } }catch{}
 $rows=@(); $i=0
 foreach($log in $script:EventLogs){
  $i++; SubProg ("Exportando {0} ({1}/{2})" -f $log,$i,$script:EventLogs.Count) $i ($script:EventLogs.Count*2)
  if($existing.Count -gt 0 -and -not $existing.ContainsKey($log)){ LG INFO "Log no presente en el sistema: $log"; continue }
  $ok = ExportLog $log $script:Dirs.Events
  $cnt = 0
  try{
   $ev = @(Get-WinEvent -LogName $log -MaxEvents $recentMax -ErrorAction Stop | Select-Object @{n='TimeCreatedUtc';e={ UtcStr $_.TimeCreated }},Id,LevelDisplayName,ProviderName,RecordId,MachineName,UserId,Message)
   $ev | Export-Csv -LiteralPath (Join-Path $script:Dirs.Events ((Safe $log)+'-recent.csv')) -NoTypeInformation -Encoding $script:CsvEnc
   AddStat 'Events'; $cnt = $ev.Count
  }catch{ if($_.Exception.Message -notmatch 'No events were found|No se encontraron eventos'){ LG WARN ("Eventos {0}: {1}" -f $log,$_.Exception.Message) } }
  $info = $null; if($existing.ContainsKey($log)){ $info = $existing[$log] }
  $rows += [pscustomobject]@{Log=$log;EVTX=$(if($ok){ 'Si' }else{ 'No' });Recientes=$cnt;RegistrosTotales=(P $info 'RecordCount');TamanoMB=$(if($info -and (P $info 'FileSize')){ [math]::Round((P $info 'FileSize')/1MB,1) }else{ $null });Modo=[string](P $info 'LogMode')}
 }
 $key = New-Object System.Collections.Generic.List[object]
 $start = (Get-Date).AddDays(-$days)
 $i = 0
 foreach($ke in $script:KeyEvents){
  $i++; SubProg ("Eventos clave {0}" -f $ke[0]) ($script:EventLogs.Count+$i) ($script:EventLogs.Count*2)
  if($existing.Count -gt 0 -and -not $existing.ContainsKey($ke[0])){ continue }
  try{
   foreach($e in @(Get-WinEvent -FilterHashtable @{LogName=$ke[0];Id=$ke[1];StartTime=$start} -MaxEvents $keyMax -ErrorAction Stop)){
    $msg = [string]$e.Message; if($msg.Length -gt 4000){ $msg = $msg.Substring(0,4000)+'...' }
    $key.Add([pscustomobject]@{TimeCreatedUtc=(UtcStr $e.TimeCreated);Log=$e.LogName;Id=$e.Id;RecordId=$e.RecordId;Descripcion=[string]$script:EventDesc["$($e.LogName)|$($e.Id)"];Detalle=(EvDetail $e);Mensaje=$msg})
   }
  }catch{ if($_.Exception.Message -notmatch 'No events were found|No se encontraron eventos'){ LG WARN ("Eventos clave {0}: {1}" -f $ke[0],$_.Exception.Message) } }
 }
 $keyArr = @($key.ToArray() | Sort-Object TimeCreatedUtc -Descending)
 $sum = @($keyArr | Group-Object Log,Id | ForEach-Object { $f = $_.Group[0]; [pscustomobject]@{Log=$f.Log;Id=$f.Id;Descripcion=$f.Descripcion;Total=$_.Count;PrimeroUtc=($_.Group | Select-Object -Last 1).TimeCreatedUtc;UltimoUtc=$f.TimeCreatedUtc} } | Sort-Object Total -Descending)
 $script:Data['keyevents'] = $keyArr
 $script:Data['keysummary'] = $sum
 ExportSet 'event_logs_index' $rows
 ExportSet 'key_events' $keyArr
 ExportSet 'key_events_summary' $sum
 RT 'Registros de eventos'
 Tbl @('Log','EVTX','Recientes','RegistrosTotales','TamanoMB','Modo') $rows
 RL ("Eventos clave de los ultimos {0} dias:" -f $days); RL ''
 Tbl @('Log','Id','Descripcion','Total','PrimeroUtc','UltimoUtc') $sum 40
 RL 'Ultimos inicios de sesion fallidos / cuentas creadas / servicios instalados:'; RL ''
 Tbl @('TimeCreatedUtc','Id','Descripcion','Detalle') @($keyArr | Where-Object { $_.Id -in 4625,4720,7045,4697,1102,104 }) 30
 ST 'Eventos' 'OK' ("{0} logs exportados / {1} eventos clave ({2} dias)" -f @($rows | Where-Object { $_.EVTX -eq 'Si' }).Count,$keyArr.Count,$days)
}
function CollectAllEvents{
 $dir = Join-Path $script:Dirs.Events 'All'
 New-Item -ItemType Directory -Path $dir -Force | Out-Null
 $logs = @(); try{ $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { (P $_ 'RecordCount') -gt 0 -and $script:EventLogs -notcontains $_.LogName } | ForEach-Object { $_.LogName }) }catch{ LG WARN "ListLog: $($_.Exception.Message)" }
 $ok = 0; $i = 0
 foreach($l in $logs){ $i++; SubProg ("EVTX {0}/{1}: {2}" -f $i,$logs.Count,$l) $i $logs.Count; if(ExportLog $l $dir){ $ok++ } }
 RT 'Exportacion completa de EVTX (Pro)'
 RL ("Logs adicionales con registros: {0} / exportados: {1}. Ruta: Artifacts\Events\All" -f $logs.Count,$ok); RL ''
 ST 'EVTX completos' 'OK' ("{0}/{1} logs adicionales exportados" -f $ok,$logs.Count)
}

# ---------------------------------------------------------------- fase: hives del registro
function CollectHives{
 $rows=@()
 if($script:IsAdmin){
  $items = @(@('HKLM\SAM','SAM'),@('HKLM\SYSTEM','SYSTEM'),@('HKLM\SOFTWARE','SOFTWARE'),@('HKLM\SECURITY','SECURITY'),@('HKU\.DEFAULT','DEFAULT'))
  $i = 0
  foreach($h in $items){
   $i++; SubProg ("Hive {0}" -f $h[0]) $i ($items.Count + $script:UserProfiles.Count)
   $ok = RegSave $h[0] (Join-Path $script:Dirs.Registry ($h[1]+'.hiv'))
   $rows += [pscustomobject]@{Hive=$h[0];Usuario='';Metodo='reg save';Estado=$(if($ok){ 'Exportado' }else{ 'Error' })}
  }
 } else { Warn 'Sin admin no se exportan hives HKLM.'; LG WARN 'Hives HKLM omitidos por falta de privilegios.' }
 $loaded = @(LoadedUserSids)
 $i = 0
 foreach($p in $script:UserProfiles){
  $i++; SubProg ("Hives de {0}" -f $p.Nombre) (5+$i) (5 + $script:UserProfiles.Count)
  $dst = Join-Path $script:Dirs.Registry ('Users\' + (Safe $p.Nombre) + $(if($p.SID){ '_' + $p.SID }else{ '' }))
  New-Item -ItemType Directory -Path $dst -Force | Out-Null
  if($p.SID -and $loaded -contains $p.SID -and $script:IsAdmin){
   $a = RegSave "HKU\$($p.SID)" (Join-Path $dst 'NTUSER.DAT')
   $b = RegSave "HKU\$($p.SID)_Classes" (Join-Path $dst 'UsrClass.dat')
   $rows += [pscustomobject]@{Hive='NTUSER.DAT';Usuario=$p.Usuario;Metodo='reg save (hive cargada)';Estado=$(if($a){ 'Exportado' }else{ 'Error' })}
   $rows += [pscustomobject]@{Hive='UsrClass.dat';Usuario=$p.Usuario;Metodo='reg save (hive cargada)';Estado=$(if($b){ 'Exportado' }else{ 'Error' })}
  } else {
   foreach($f in @(@('NTUSER.DAT',''),@('UsrClass.dat','AppData\Local\Microsoft\Windows'))){
    $dir = $p.LocalPath; if($f[1]){ $dir = Join-Path $p.LocalPath $f[1] }
    $srcHive = Join-Path $dir $f[0]
    if(-not (Test-Path -LiteralPath $srcHive)){ $rows += [pscustomobject]@{Hive=$f[0];Usuario=$p.Usuario;Metodo='-';Estado='No existe'}; continue }
    $ok = CopyFile $srcHive $dst -Stat 'Registry'
    foreach($lg in @('.LOG1','.LOG2')){ CopyFile (Join-Path $dir ($f[0]+$lg)) $dst -Stat 'Registry' | Out-Null }
    $rows += [pscustomobject]@{Hive=$f[0];Usuario=$p.Usuario;Metodo='Copia de fichero (+LOG1/LOG2)';Estado=$(if($ok){ 'Copiado' }else{ 'Error' })}
   }
  }
 }
 ExportSet 'registry_hives' $rows
 RT 'Hives del registro'
 Tbl @('Hive','Usuario','Metodo','Estado') $rows
 ST 'Hives' 'OK' ("{0}/{1} hives adquiridas" -f @($rows | Where-Object { $_.Estado -in 'Exportado','Copiado' }).Count,@($rows | Where-Object { $_.Estado -ne 'No existe' }).Count)
}

# ---------------------------------------------------------------- fase: ficheros del sistema
function CollectSystemFiles{
 $res=@()
 $sr = $env:SystemRoot
 $plan = @(
  @('Prefetch',(Join-Path $sr 'Prefetch'),'Prefetch',@('*.pf','*.db'),$true),
  @('Amcache',(Join-Path $sr 'appcompat\Programs'),'Amcache',@('Amcache.hve*','RecentFileCache.bcf'),$false),
  @('SRUM',(Join-Path $sr 'System32\sru'),'SRUM',@('*'),$false),
  @('Tareas XML',(Join-Path $sr 'System32\Tasks'),'Tasks',@('*'),$true),
  @('setupapi',(Join-Path $sr 'INF'),'setupapi',@('setupapi.dev*.log','setupapi.setup.log'),$true),
  @('WMI repositorio',(Join-Path $sr 'System32\wbem\Repository'),'WMI_Repository',@('OBJECTS.DATA','INDEX.BTR','MAPPING*.MAP'),$false),
  @('Firewall log',(Join-Path $sr 'System32\LogFiles\Firewall'),'FirewallLogs',@('*.log'),$false)
 )
 $i = 0
 foreach($it in $plan){
  $i++; SubProg ("Copiando {0}" -f $it[0]) $i ($plan.Count + $script:UserProfiles.Count)
  $r = CopyTree $it[1] (Join-Path $script:Dirs.Files $it[2]) -Include $it[3] -NoVss:$it[4]
  $res += [pscustomobject]@{Artefacto=$it[0];Origen=$it[1];Copiados=$r.Copiados;Fallidos=$r.Fallidos}
 }
 foreach($p in $script:UserProfiles){
  $i++; SubProg ("Ficheros de {0}" -f $p.Nombre) $i ($plan.Count + $script:UserProfiles.Count)
  $base = Join-Path $script:Dirs.Files ('Users\' + (Safe $p.Nombre))
  $r1 = CopyTree (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Recent') (Join-Path $base 'Recent') -NoVss
  $r2 = CopyTree (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') (Join-Path $base 'Startup') -NoVss
  $r3 = CopyTree (Join-Path $p.LocalPath 'AppData\Local\ConnectedDevicesPlatform') (Join-Path $base 'ConnectedDevicesPlatform') -Include @('ActivitiesCache.db*')
  $r4 = CopyTree (Join-Path $p.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine') (Join-Path $base 'PSReadLine') -NoVss
  $res += [pscustomobject]@{Artefacto="Usuario $($p.Nombre): Recent/JumpLists, Startup, Timeline, PSReadLine";Origen=$p.LocalPath;Copiados=($r1.Copiados+$r2.Copiados+$r3.Copiados+$r4.Copiados);Fallidos=($r1.Fallidos+$r2.Fallidos+$r3.Fallidos+$r4.Fallidos)}
 }
 $r = CopyTree (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') (Join-Path $script:Dirs.Files 'Startup_AllUsers') -NoVss
 $res += [pscustomobject]@{Artefacto='Startup (todos los usuarios)';Origen=$env:ProgramData;Copiados=$r.Copiados;Fallidos=$r.Fallidos}
 ExportSet 'system_files_copied' $res
 RT 'Ficheros de sistema copiados'
 Tbl @('Artefacto','Copiados','Fallidos') $res
 RL '> Los ficheros bloqueados (Amcache, SRUM, ActivitiesCache, NTUSER no cargados) se intentan copiar via Volume Shadow Copy temporal (esentutl /vss) cuando hay privilegios. Ver Logs\acquisition_log.csv.'; RL ''
 ST 'Ficheros sistema' 'OK' ("{0} ficheros copiados / {1} fallidos" -f (SumOf $res 'Copiados'),(SumOf $res 'Fallidos'))
}

# ---------------------------------------------------------------- fase: navegadores
function CollectBrowsers{
 $chromium = @(
  @('Chrome','AppData\Local\Google\Chrome\User Data'),@('Chrome Beta','AppData\Local\Google\Chrome Beta\User Data'),
  @('Edge','AppData\Local\Microsoft\Edge\User Data'),@('Brave','AppData\Local\BraveSoftware\Brave-Browser\User Data'),
  @('Vivaldi','AppData\Local\Vivaldi\User Data'),@('Chromium','AppData\Local\Chromium\User Data'),
  @('Opera','AppData\Roaming\Opera Software\Opera Stable'),@('Opera GX','AppData\Roaming\Opera Software\Opera GX Stable')
 )
 $chFiles = @('History','Network\Cookies','Cookies','Login Data','Login Data For Account','Web Data','Bookmarks','Preferences','Secure Preferences','Shortcuts','Top Sites','Visited Links','Favicons')
 $ffFiles = @('places.sqlite','favicons.sqlite','cookies.sqlite','formhistory.sqlite','downloads.sqlite','logins.json','key4.db','key3.db','cert9.db','extensions.json','addons.json','prefs.js','sessionstore.jsonlz4','sessionstore-backups\recovery.jsonlz4','sessionstore-backups\previous.jsonlz4')
 $side = @('','-wal','-shm','-journal')
 $rows=@(); $i=0
 foreach($p in $script:UserProfiles){
  $i++; SubProg ("Navegadores de {0}" -f $p.Nombre) $i $script:UserProfiles.Count
  $ubase = Join-Path $script:Dirs.Browser (Safe $p.Nombre)
  foreach($b in $chromium){
   $root = Join-Path $p.LocalPath $b[1]
   if(-not (Test-Path -LiteralPath $root)){ continue }
   $profDirs = @()
   if($b[0] -like 'Opera*'){ $profDirs = @(Get-Item -LiteralPath $root -Force) + @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like '_side_profiles' }) }
   else{ $profDirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' }) }
   $c = 0; $f = 0
   $dstB = Join-Path $ubase (Safe $b[0])
   if(CopyFile (Join-Path $root 'Local State') $dstB -Stat 'Browser'){ $c++ }
   foreach($pd in $profDirs){
    foreach($rel in $chFiles){ foreach($sx in $side){
     $src = Join-Path $pd.FullName ($rel+$sx)
     if(Test-Path -LiteralPath $src -PathType Leaf){ $d = JP (Join-Path $dstB (Safe $pd.Name)) (Split-Path -Parent $rel); if(CopyFile $src $d -Stat 'Browser'){ $c++ } else { $f++ } }
    } }
   }
   $rows += [pscustomobject]@{Usuario=$p.Usuario;Navegador=$b[0];Perfiles=$profDirs.Count;Copias=$c;Fallos=$f;Ruta=$root}
  }
  $ffRoot = Join-Path $p.LocalPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
  if(Test-Path -LiteralPath $ffRoot){
   $c = 0; $f = 0
   $profDirs = @(Get-ChildItem -LiteralPath $ffRoot -Directory -Force -ErrorAction SilentlyContinue)
   CopyFile (Join-Path $p.LocalPath 'AppData\Roaming\Mozilla\Firefox\profiles.ini') (Join-Path $ubase 'Firefox') -NoVss -Stat 'Browser' | Out-Null
   foreach($pd in $profDirs){
    foreach($rel in $ffFiles){ foreach($sx in $side){
     $src = Join-Path $pd.FullName ($rel+$sx)
     if(Test-Path -LiteralPath $src -PathType Leaf){ $d = JP (Join-Path (Join-Path $ubase 'Firefox') (Safe $pd.Name)) (Split-Path -Parent $rel); if(CopyFile $src $d -Stat 'Browser'){ $c++ } else { $f++ } }
    } }
   }
   $rows += [pscustomobject]@{Usuario=$p.Usuario;Navegador='Firefox';Perfiles=$profDirs.Count;Copias=$c;Fallos=$f;Ruta=$ffRoot}
  }
 }
 ExportSet 'browser_artifacts' $rows
 RT 'Navegadores'
 Tbl @('Usuario','Navegador','Perfiles','Copias','Fallos') $rows
 RL '> Incluye ficheros auxiliares SQLite (-wal, -shm, -journal) para no perder la actividad reciente. Contiene datos sensibles (cookies, credenciales cifradas, Local State).'; RL ''
 ST 'Navegadores' 'OK' ("{0} navegadores detectados / {1} ficheros copiados" -f $rows.Count,(SumOf $rows 'Copias'))
}

# ---------------------------------------------------------------- fase: timeline
function TL($list,[string]$ts,[string]$tipo,[string]$fuente,[string]$usuario,[string]$ruta,$tam=$null){ if($ts){ $list.Add([pscustomobject]@{TimestampUtc=$ts;Tipo=$tipo;Fuente=$fuente;Usuario=$usuario;Ruta=$ruta;Tamano=$tam}) } }
function CollectTimeline{
 $t = New-Object System.Collections.Generic.List[object]
 $fs = @(); if($script:Data.ContainsKey('fs_user')){ $fs = @($script:Data['fs_user']) }
 SubProg 'Timeline: ficheros de usuario' 1 6
 if($script:Level -ge 3){
  foreach($p in $script:UserProfiles){
   foreach($d in @('Desktop','Documents','Downloads','Pictures','Videos','AppData\Roaming')){ try{ $fs += @(ListDir (Join-Path $p.LocalPath $d) $p.Usuario ("Pro:"+$d) 4 20000) }catch{ LG WARN ("Timeline {0}: {1}" -f $d,$_.Exception.Message) } }
  }
  foreach($d in @($env:ProgramData,"$env:SystemDrive\Users\Public","$env:SystemRoot\Temp","$env:SystemDrive\PerfLogs")){ try{ $fs += @(ListDir $d 'SYSTEM' ("Pro:"+$d) 3 20000) }catch{ LG WARN ("Timeline {0}: {1}" -f $d,$_.Exception.Message) } }
 }
 foreach($f in $fs){
  if($null -eq $f){ continue }
  TL $t $f.CreacionUtc 'Fichero creado' $f.Fuente $f.Usuario $f.Ruta $f.Tamano
  TL $t $f.ModificacionUtc 'Fichero modificado' $f.Fuente $f.Usuario $f.Ruta $f.Tamano
 }
 SubProg 'Timeline: Prefetch, tareas y papelera' 2 6
 foreach($f in @(ListDir (Join-Path $env:SystemRoot 'Prefetch') 'SYSTEM' 'Prefetch' 0)){ if(-not $f.Directorio){ TL $t $f.CreacionUtc 'Prefetch creado (1a ejecucion aprox.)' 'Prefetch' '' $f.Nombre $f.Tamano; TL $t $f.ModificacionUtc 'Prefetch modificado (ultima ejecucion)' 'Prefetch' '' $f.Nombre $f.Tamano } }
 foreach($f in @(ListDir (Join-Path $env:SystemRoot 'System32\Tasks') 'SYSTEM' 'Tasks' 5)){ if(-not $f.Directorio){ TL $t $f.CreacionUtc 'Tarea creada' 'Tasks' '' $f.Ruta $f.Tamano; TL $t $f.ModificacionUtc 'Tarea modificada' 'Tasks' '' $f.Ruta $f.Tamano } }
 foreach($r in @($script:Data['recycle'])){ if($r){ TL $t $r.BorradoUtc 'Fichero borrado (papelera)' 'RecycleBin' $r.Usuario $r.RutaOriginal $r.TamanoOriginal } }
 SubProg 'Timeline: registro y eventos' 4 6
 foreach($r in @($script:Data['bam'])){ if($r){ TL $t $r.UltimaEjecucionUtc 'Ejecucion (BAM)' 'BAM' $r.Usuario $r.Ejecutable } }
 foreach($r in @($script:Data['userassist'])){ if($r){ TL $t $r.UltimaEjecucionUtc ("Ejecucion (UserAssist x{0})" -f $r.Ejecuciones) 'UserAssist' $r.Usuario $r.Programa } }
 foreach($r in @($script:Data['keyevents'])){ if($r){ TL $t $r.TimeCreatedUtc ("Evento {0} {1}" -f $r.Id,$r.Descripcion) $r.Log '' $r.Detalle } }
 foreach($r in @($script:Data['procs'])){ if($r){ TL $t $r.CreationUtc 'Proceso iniciado (activo)' 'Procesos' $r.Usuario ([string]$(if($r.CommandLine){ $r.CommandLine }else{ $r.ExecutablePath })) } }
 SubProg 'Timeline: ordenando' 5 6
 $arr = @($t.ToArray() | Sort-Object TimestampUtc -Descending)
 $path = Join-Path $script:Dirs.Timeline 'timeline.csv'
 $arr | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding $script:CsvEnc
 AddStat 'Timeline'
 RT 'Timeline'
 RL ("Eventos en timeline: {0}. Fichero: Artifacts\Timeline\timeline.csv (UTC, ordenado del mas reciente al mas antiguo)." -f $arr.Count); RL ''
 Tbl @('TimestampUtc','Tipo','Usuario','Ruta') @($arr | Where-Object { $_.Fuente -ne 'Procesos' }) 30
 ST 'Timeline' 'OK' ("{0} entradas" -f $arr.Count)
}

# ---------------------------------------------------------------- fases Pro
function CollectBinaries{
 $src = @{}
 $add = { param($p,$o) if($p -and -not $src.ContainsKey($p)){ $src[$p] = $o } }
 foreach($r in @($script:Data['procs'])){ if($r -and $r.ExecutablePath){ & $add $r.ExecutablePath 'Proceso' } }
 foreach($r in @($script:Data['services'])){ if($r){ & $add (ExePath $r.PathName) 'Servicio' } }
 foreach($r in @($script:Data['drivers'])){ if($r){ & $add (ExePath $r.PathName) 'Driver' } }
 foreach($r in @($script:Data['autoruns'])){ if($r){ & $add (ExePath $r.Value) 'Autorun' } }
 foreach($r in @($script:Data['tasks'])){ if($r -and $r.Acciones){ & $add (ExePath (($r.Acciones -split ' \|\| ')[0])) 'Tarea' } }
 $rows = New-Object System.Collections.Generic.List[object]
 $keys = @($src.Keys | Sort-Object); $i = 0
 foreach($p in $keys){
  $i++; if(($i % 10) -eq 0){ SubProg ("Hash y firma {0}/{1}" -f $i,$keys.Count) $i $keys.Count }
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ $rows.Add([pscustomobject]@{Ruta=$p;Origen=$src[$p];SHA256='';Firma='No existe';Firmante='';Tamano=$null;ModificacionUtc='';RutaEscribible=(UserWritable $p)}); continue }
  $h = ''; try{ $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash }catch{ LG WARN ("Hash {0}: {1}" -f $p,$_.Exception.Message) }
  $sig = 'Desconocido'; $signer = ''
  try{ $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; $sig = [string]$s.Status; if($s.SignerCertificate){ $signer = $s.SignerCertificate.Subject } }catch{ LG WARN ("Firma {0}: {1}" -f $p,$_.Exception.Message) }
  $fi = Get-Item -LiteralPath $p -Force
  $rows.Add([pscustomobject]@{Ruta=$p;Origen=$src[$p];SHA256=$h;Firma=$sig;Firmante=$signer;Tamano=$fi.Length;ModificacionUtc=(UtcStr $fi.LastWriteTime);RutaEscribible=(UserWritable $p)})
 }
 $arr = $rows.ToArray()
 $script:Data['binaries'] = $arr
 ExportSet 'binaries_hash_signature' $arr
 $bad = @($arr | Where-Object { $_.Firma -notin 'Valid','No existe' })
 RT 'Binarios: hash y firma (Pro)'
 RL ("Binarios analizados: {0} / sin firma valida: {1}" -f $arr.Count,$bad.Count); RL ''
 Tbl @('Origen','Ruta','Firma','SHA256') $bad 50
 ST 'Binarios' 'OK' ("{0} binarios / {1} sin firma valida" -f $arr.Count,$bad.Count)
}
function CollectProExtras{
 $res = @()
 $r = CopyTree (Join-Path $env:ProgramData 'Microsoft\Windows\WER') (Join-Path $script:Dirs.Files 'WER') -Include @('*.wer') -NoVss
 $res += [pscustomobject]@{Artefacto='Informes WER (*.wer)';Copiados=$r.Copiados;Fallidos=$r.Fallidos}
 foreach($p in $script:UserProfiles){
  $r = CopyTree (Join-Path $p.LocalPath 'AppData\Local\Microsoft\Terminal Server Client\Cache') (Join-Path $script:Dirs.Files ('Users\'+(Safe $p.Nombre)+'\RDPCache')) -NoVss
  $res += [pscustomobject]@{Artefacto="Cache bitmap RDP $($p.Nombre)";Copiados=$r.Copiados;Fallidos=$r.Fallidos}
  $r = CopyTree (Join-Path $p.LocalPath 'AppData\Local\Microsoft\Windows\WebCache') (Join-Path $script:Dirs.Files ('Users\'+(Safe $p.Nombre)+'\WebCache')) -Include @('WebCacheV01.dat','*.log','*.jfm')
  $res += [pscustomobject]@{Artefacto="WebCache (IE/Edge legacy) $($p.Nombre)";Copiados=$r.Copiados;Fallidos=$r.Fallidos}
 }
 $sysPs = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
 $r = CopyTree $sysPs (Join-Path $script:Dirs.Files 'PSReadLine\SYSTEM') -NoVss
 $res += [pscustomobject]@{Artefacto='PSReadLine de SYSTEM';Copiados=$r.Copiados;Fallidos=$r.Fallidos}
 $n = 0
 foreach($rb in @($script:Data['recycle'])){ if($rb){ if(CopyFile $rb.Fichero (Join-Path $script:Dirs.Files ('RecycleBin\'+(Safe $rb.SID))) -NoVss){ $n++ } } }
 $res += [pscustomobject]@{Artefacto='Papelera: ficheros $I';Copiados=$n;Fallidos=(@($script:Data['recycle']).Count - $n)}
 CmdOut 'firewall_rules_verbose' { netsh advfirewall firewall show rule name=all verbose }
 CmdOut 'tasklist_modules' { tasklist /m }
 CmdOut 'sc_queryex' { sc.exe queryex type= all state= all }
 ExportSet 'pro_extras' $res
 RT 'Artefactos adicionales (Pro)'
 Tbl @('Artefacto','Copiados','Fallidos') $res
 ST 'Extras Pro' 'OK' ("{0} ficheros adicionales" -f (SumOf $res 'Copiados'))
}

# ---------------------------------------------------------------- analisis de indicadores
function CollectFindings{
 $mp = $script:Data['defender']; $pref = $script:Data['defenderPref']
 if($mp -and (P $mp 'RealTimeProtectionEnabled') -eq $false){ Finding 'Defender' 'Alta' 'Proteccion en tiempo real desactivada.' }
 if($pref){ foreach($n in 'ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress'){ $v = @(P $pref $n) | Where-Object { $_ -and $_ -notmatch '^N/A' }; if(@($v).Count -gt 0){ Finding 'Defender' 'Media' ("{0}: {1}" -f $n,(@($v) -join ', ')) } } }
 foreach($d in @($script:Data['defenderDet'])){ if($d){ Finding 'Defender' 'Alta' ("Deteccion {0}: {1} ({2})" -f $d.InitialDetectionUtc,$d.Recursos,$d.ProcessName) } }
 foreach($c in @($script:Data['secconfig'])){
  if(-not $c){ continue }
  if($c.Valor -eq 'UseLogonCredential' -and $c.Dato -eq '1'){ Finding 'Credenciales' 'Alta' 'WDigest UseLogonCredential=1: credenciales en claro en memoria (tecnica habitual de Mimikatz).' }
  if($c.Valor -eq 'LocalAccountTokenFilterPolicy' -and $c.Dato -eq '1'){ Finding 'UAC' 'Media' 'LocalAccountTokenFilterPolicy=1: administracion remota con cuentas locales sin filtrado UAC.' }
  if($c.Valor -eq 'EnableLUA' -and $c.Dato -eq '0'){ Finding 'UAC' 'Alta' 'UAC desactivado (EnableLUA=0).' }
  if($c.Valor -eq 'DisableAntiSpyware' -and $c.Dato -eq '1'){ Finding 'Defender' 'Alta' 'Defender desactivado por politica (DisableAntiSpyware=1).' }
  if($c.Valor -eq 'AutoAdminLogon' -and $c.Dato -eq '1'){ Finding 'Credenciales' 'Media' 'AutoAdminLogon activo: revisar DefaultPassword en Winlogon.' }
  if($c.Valor -eq 'EnableScriptBlockLogging' -and $c.Dato -ne '1'){ Finding 'Auditoria' 'Info' 'Script Block Logging de PowerShell no habilitado.' }
 }
 $w = $script:Data['wmiConsumers']
 foreach($c in @($w)){ if($c){ Finding 'Persistencia' 'Alta' ("Consumidor WMI {0} '{1}': {2}{3}" -f $c.Clase,$c.Name,$c.CommandLineTemplate,$c.ScriptText) } }
 foreach($r in @($script:Data['portproxy'])){ if($r){ Finding 'Red' 'Media' ("Regla portproxy {0} -> {1}" -f $r.Name,$r.Value) } }
 foreach($f in @($script:Data['firewall'])){ if($f -and -not $f.Enabled){ Finding 'Firewall' 'Media' ("Perfil de firewall {0} desactivado." -f $f.Name) } }
 $rdp = $script:Data['rdp']
 if($rdp -and (P $rdp 'fDenyTSConnections') -eq 0){
  Finding 'RDP' 'Info' ("Escritorio remoto habilitado (puerto {0})." -f (P $rdp 'PortNumber'))
  if((P $rdp 'UserAuthentication_NLA') -eq 0){ Finding 'RDP' 'Media' 'RDP sin autenticacion a nivel de red (NLA).' }
 }
 foreach($p in @($script:Data['procs'])){ if($p -and $p.ExecutablePath -and (UserWritable $p.ExecutablePath)){ Finding 'Procesos' 'Media' ("PID {0} {1} en ruta escribible: {2}" -f $p.ProcessId,$p.Name,$p.ExecutablePath) } }
 foreach($r in @($script:Data['autoruns'])){ if($r -and (UserWritable ([Environment]::ExpandEnvironmentVariables([string]$r.Value)))){ Finding 'Persistencia' 'Media' ("Autorun {0} '{1}' -> {2}" -f $r.Origen,$r.Name,$r.Value) } }
 foreach($s in @($script:Data['services'])){ if($s -and $s.PathName -and (UserWritable ([Environment]::ExpandEnvironmentVariables([string]$s.PathName)))){ Finding 'Servicios' 'Alta' ("Servicio {0} ejecuta desde ruta escribible: {1}" -f $s.Name,$s.PathName) } }
 foreach($t in @($script:Data['tasks'])){ if($t -and $t.TaskPath -notlike '\Microsoft\*' -and ((UserWritable ([Environment]::ExpandEnvironmentVariables([string]$t.Acciones))) -or ($t.Acciones -match '(?i)powershell.*(-enc|-e |frombase64|iex|downloadstring)|mshta|regsvr32.*/i:|rundll32.*javascript|certutil.*-urlcache|bitsadmin'))){ Finding 'Tareas' 'Media' ("Tarea {0}{1}: {2}" -f $t.TaskPath,$t.TaskName,$t.Acciones) } }
 foreach($p in @($script:Data['procs'])){ if($p -and $p.CommandLine -match '(?i)(-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-expression|iex\s*\(|-w(indowstyle)?\s+hidden|bypass\s+-nop|certutil.*-urlcache|mshta\s+http)'){ Finding 'Procesos' 'Alta' ("PID {0} con linea de comandos sospechosa: {1}" -f $p.ProcessId,$p.CommandLine) } }
 foreach($s in @($script:Data['keysummary'])){
  if(-not $s){ continue }
  switch("$($s.Log)|$($s.Id)"){
   'Security|1102' { Finding 'Eventos' 'Alta' ("Log de Seguridad borrado {0} veces (ultimo {1})." -f $s.Total,$s.UltimoUtc) }
   'System|104' { Finding 'Eventos' 'Alta' ("Logs borrados (104) {0} veces (ultimo {1})." -f $s.Total,$s.UltimoUtc) }
   'Security|4720' { Finding 'Cuentas' 'Media' ("{0} cuentas creadas (ultima {1})." -f $s.Total,$s.UltimoUtc) }
   'System|7045' { Finding 'Servicios' 'Info' ("{0} servicios instalados (ultimo {1})." -f $s.Total,$s.UltimoUtc) }
   'Security|4625' { if($s.Total -ge 20){ Finding 'Cuentas' 'Media' ("{0} inicios de sesion fallidos (posible fuerza bruta)." -f $s.Total) } }
   'Microsoft-Windows-Windows Defender/Operational|1116' { Finding 'Defender' 'Alta' ("{0} detecciones de malware en el log de Defender (ultima {1})." -f $s.Total,$s.UltimoUtc) }
   'Microsoft-Windows-Windows Defender/Operational|5001' { Finding 'Defender' 'Alta' ("Proteccion en tiempo real desactivada {0} veces (ultima {1})." -f $s.Total,$s.UltimoUtc) }
  }
 }
 foreach($u in @($script:Data['users'])){ if($u -and $u.Enabled -and $u.SID -match '-50[01]$'){ Finding 'Cuentas' 'Media' ("Cuenta integrada habilitada: {0}" -f $u.Name) } }
 foreach($b in @($script:Data['binaries'])){ if($b -and $b.Firma -notin 'Valid','No existe' -and $b.RutaEscribible){ Finding 'Binarios' 'Alta' ("{0} sin firma valida en ruta escribible: {1} ({2})" -f $b.Origen,$b.Ruta,$b.SHA256) } }
 $recentExe = @(@($script:Data['downloads']) | Where-Object { $_ -and -not $_.Directorio -and $_.Nombre -match '(?i)\.(exe|msi|dll|scr|ps1|vbs|js|jse|hta|bat|cmd|lnk|iso|img|vhdx?|one)$' -and $_.ModificacionUtc -ge (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-dd') })
 foreach($d in $recentExe){ Finding 'Descargas' 'Info' ("{0}: {1} ({2}) origen: {3}" -f $d.Usuario,$d.Nombre,$d.ModificacionUtc,$(if($d.HostUrl){ $d.HostUrl }else{ '(sin Zone.Identifier)' })) }
 $c = @($script:Findings | Group-Object Severidad | ForEach-Object { "{0}: {1}" -f $_.Name,$_.Count }) -join ' / '
 ST 'Indicadores' 'OK' $(if($c){ $c }else{ 'Sin indicadores destacables' })
}

# ---------------------------------------------------------------- informe, manifiesto y cierre
function BuildTop([switch]$Partial){
 $saved = $script:Blocks
 $script:Blocks = New-Object System.Collections.Generic.List[object]
 if($Partial){ RL '> **ADQUISICION INCOMPLETA**: el proceso se interrumpio antes de terminar. Los datos recogidos hasta ese momento se incluyen igualmente.' }
 RT 'Resumen Ejecutivo'
 Tbl @('Area','Estado','Detalle') $script:Summary.ToArray()
 RT 'Indicadores a revisar'
 RL '> Indicadores automaticos para priorizar el analisis. No son conclusiones: deben verificarse manualmente.'
 $ord = @{Alta=0;Media=1;Info=2}
 Tbl @('Severidad','Area','Detalle') @($script:Findings.ToArray() | Sort-Object { $ord[$_.Severidad] },Area) 150
 RT 'Estado de ejecucion'
 Tbl @('Nombre','Estado','Avisos','Segundos','Detalle') $script:Results.ToArray()
 $top = $script:Blocks
 $script:Blocks = $saved
 $top.ToArray()
}
function FindBrowser{
 $bases = @(${env:ProgramFiles(x86)},$env:ProgramFiles,$env:LOCALAPPDATA) | Where-Object { $_ }
 foreach($rel in @('Microsoft\Edge\Application\msedge.exe','Google\Chrome\Application\chrome.exe','BraveSoftware\Brave-Browser\Application\brave.exe')){
  foreach($b in $bases){ $p = Join-Path $b $rel; if(Test-Path -LiteralPath $p -PathType Leaf){ return $p } }
 }
 return $null
}
function WriteMeta{
 RT 'Indice de artefactos'
 Tbl @('Conjunto','Filas','CSV') $script:SetIndex.ToArray()
 RT 'Estadisticas de artefactos'
 $artifactRows=@(); foreach($k in $script:ArtifactStats.Keys){ $artifactRows += [pscustomobject]@{Tipo=$k;Cantidad=$script:ArtifactStats[$k]} }
 Tbl @('Tipo','Cantidad') $artifactRows
 RT 'Metricas de ejecucion'
 $end = Get-Date
 $metrics = [pscustomobject]@{
  Perfil=$script:AcqProfile; Elevado=$(if($script:IsAdmin){ 'Si' }else{ 'No' })
  FasesOK=@($script:Results | Where-Object { $_.Estado -like 'OK*' }).Count; FasesError=@($script:Results | Where-Object { $_.Estado -eq 'ERROR' }).Count
  FinUtc=$end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); TiempoTotalMinutos=[math]::Round($script:RunTimer.Elapsed.TotalMinutes,2)
 }
 $script:Data['metrics'] = $metrics
 Tbl @('Perfil','Elevado','FasesOK','FasesError','FinUtc','TiempoTotalMinutos') @($metrics)
 RT 'Huella de la adquisicion en el sistema'
 $vss = @($script:Copies | Where-Object { $_.Metodo -like 'esentutl*' }).Count
 $script:PdfBrowser = FindBrowser
 RL "- Copias via sombra de volumen temporal (esentutl /vss): $vss."
 RL "- Compilacion de un tipo .NET para leer LastWrite del registro (Add-Type, ficheros temporales en %TEMP%): $(if($script:HasRegLW){'Si'}else{'No'})."
 RL '- Ejecucion de utilidades nativas de solo lectura (ipconfig, netstat, wevtutil, reg save, etc.).'
 if($script:PdfBrowser){ RL ("- Generacion del PDF con {0} en modo headless, con un perfil temporal dentro de la carpeta del caso que se elimina al terminar." -f (Split-Path -Leaf $script:PdfBrowser)) }
 else{ RL '- Generacion del PDF con el generador interno (no se encontro Edge ni Chrome).' }
 RL "- Destino del caso: $script:CaseRoot"
 RT 'Informes e integridad'
 RL '- `Reports\Informe_Forense.html`: informe completo con estilos integrados y anexo con vista previa de cada conjunto de datos.'
 RL '- `Reports\Informe_Forense.pdf`: version imprimible del informe.'
 RL '- `Reports\Informe_Forense.json`: informe y todos los conjuntos de datos en un unico fichero JSON.'
 RL '- `Reports\CSV\`: tablas del informe en CSV (resumen, indicadores, fases, estadisticas e indice de artefactos).'
 RL '- `Artifacts\Json` y `Artifacts\Csv`: cada conjunto de datos por separado. `Artifacts\Raw`: salidas crudas de utilidades nativas.'
 RL '- `Reports\hash_manifest_sha256.csv`: SHA256 de todos los ficheros del caso (incluidos estos informes), calculado tras cerrar los informes y el log.'
 RL '- `Reports\hash_manifest_sha256.csv.sha256`: SHA256 del propio manifiesto (anotarlo en la cadena de custodia).'
 RL '- `Logs\acquisition_log.csv`: origen, metodo y marcas de tiempo originales (UTC) de cada fichero copiado.'
 RT 'Estructura de salida'
 $rows=@(); foreach($k in $script:Dirs.Keys){ $rows += [pscustomobject]@{Elemento=$k;Ruta=(Rel $script:Dirs[$k])} }
 Tbl @('Elemento','Ruta') $rows
}

# ---------------------------------------------------------------- render HTML
$script:Css = @'
:root{--bg:#f3f5f9;--card:#fff;--ink:#1e293b;--mut:#64748b;--line:#e2e8f0;--pri:#0f172a;--acc:#0ea5e9;--red:#dc2626;--amb:#d97706;--grn:#16a34a;--blu:#2563eb}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 "Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
header.top{background:linear-gradient(135deg,#0f172a 0%,#1e3a8a 55%,#0369a1 100%);color:#fff;padding:28px 40px 60px}
header.top .brand{font-size:11px;letter-spacing:.2em;text-transform:uppercase;opacity:.8}
header.top h1{margin:6px 0 6px;font-size:26px;font-weight:600}
header.top .sub{opacity:.88;font-size:13px}
header.top .sub span{margin-right:18px;white-space:nowrap}
main{max-width:1500px;margin:0 auto;padding:0 40px 30px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px;margin:-40px 0 20px}
.kpi{background:var(--card);border-radius:10px;padding:12px 16px;box-shadow:0 2px 6px rgba(15,23,42,.12);border-top:4px solid var(--acc)}
.kpi .v{font-size:24px;font-weight:700;line-height:1.2}
.kpi .l{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.kpi.red{border-top-color:var(--red)}.kpi.amb{border-top-color:var(--amb)}.kpi.grn{border-top-color:var(--grn)}.kpi.blu{border-top-color:var(--blu)}
.alert{background:#fef2f2;color:#991b1b;border:1px solid #fecaca;padding:10px 14px;border-radius:8px;margin:0 0 18px;font-weight:600}
nav.toc{background:var(--card);border-radius:10px;padding:14px 22px;box-shadow:0 1px 3px rgba(15,23,42,.08);margin-bottom:18px}
nav.toc h2{font-size:13px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
nav.toc ol{columns:3;column-gap:30px;margin:0;padding-left:20px}
nav.toc a{color:var(--blu);text-decoration:none}nav.toc a:hover{text-decoration:underline}
section{background:var(--card);border-radius:10px;padding:18px 22px;margin-bottom:16px;box-shadow:0 1px 3px rgba(15,23,42,.08)}
section h2{margin:0 0 12px;font-size:17px;color:var(--pri);border-bottom:2px solid var(--line);padding-bottom:8px}
h3{font-size:13px;margin:16px 0 6px;color:#334155}
p{margin:6px 0}
ul{margin:6px 0;padding-left:20px}li{margin:3px 0}
.note{background:#f0f9ff;border-left:4px solid var(--acc);padding:8px 12px;border-radius:4px;color:#0c4a6e;margin:8px 0}
.tw{overflow-x:auto;margin:6px 0 10px}
table{border-collapse:collapse;width:100%;font-size:12px}
th{background:#f1f5f9;color:#334155;text-align:left;font-weight:600;padding:6px 8px;border-bottom:2px solid var(--line);white-space:nowrap}
td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word;max-width:640px}
tbody tr:nth-child(even){background:#f8fafc}tbody tr:hover{background:#eef6ff}
table.kv td:first-child{font-weight:600;width:220px;color:#334155;background:#f8fafc}
.b{display:inline-block;padding:1px 9px;border-radius:999px;font-size:11px;font-weight:600;white-space:nowrap}
.b-red{background:#fee2e2;color:#991b1b}.b-amb{background:#fef3c7;color:#92400e}.b-grn{background:#dcfce7;color:#166534}.b-blu{background:#dbeafe;color:#1e40af}.b-gry{background:#e2e8f0;color:#334155}
.more,.empty{color:var(--mut);font-style:italic;margin:4px 0 10px}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-family:Consolas,"Courier New",monospace;font-size:12px}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:#fff}
summary{cursor:pointer;padding:8px 12px;font-weight:600}
summary .cnt{float:right;color:var(--mut);font-weight:400}
details .tw,details .empty{margin:0 12px 10px}
footer{color:var(--mut);font-size:11px;text-align:center;padding:6px 40px 30px}
@page{size:A4 landscape;margin:10mm}
@media print{
 body{background:#fff;font-size:10px}
 *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
 header.top{padding:16px 22px 48px}
 main{padding:0 4px;max-width:none}
 section,nav.toc,.kpi{box-shadow:none;border:1px solid var(--line)}
 section{padding:10px 12px}
 h2,h3{break-after:avoid}
 tr,footer,summary{break-inside:avoid}
 thead{display:table-header-group}
 td{max-width:none}
 .tw{overflow:visible}
 nav.toc ol{columns:4}
}
'@
function Inline([string]$t){
 $h = HtmlEnc $t
 $h = [regex]::Replace($h,'`([^`]+)`','<code>$1</code>')
 [regex]::Replace($h,'\*\*([^*]+)\*\*','<strong>$1</strong>')
}
function BadgeCls([string]$v){
 if($v -match '^(?i)(Alta|ERROR|NotSigned|HashMismatch|UnknownError)$'){ return 'b-red' }
 if($v -match '^(?i)(Media|OK con avisos|Parcial|No)$'){ return 'b-amb' }
 if($v -match '^(?i)(Info)$'){ return 'b-blu' }
 if($v -match '^(?i)(OK|Exportado|Copiado|Si|Valid)$'){ return 'b-grn' }
 'b-gry'
}
function TableHtml($sb,[string[]]$h,$rows,[int]$total,[string]$cls=''){
 $rows = @($rows)
 if($rows.Count -eq 0){ [void]$sb.Append('<p class="empty">Sin datos.</p>'); return }
 $badge = @(); for($i=0;$i -lt $h.Count;$i++){ if($h[$i] -in 'Severidad','Estado','EVTX','Firma'){ $badge += $i } }
 [void]$sb.Append('<div class="tw"><table')
 if($cls){ [void]$sb.Append(' class="'+$cls+'"') }
 [void]$sb.Append('>')
 if($cls -ne 'kv'){ [void]$sb.Append('<thead><tr>'); foreach($x in $h){ [void]$sb.Append('<th>'+(HtmlEnc $x)+'</th>') }; [void]$sb.Append('</tr></thead>') }
 [void]$sb.Append('<tbody>')
 foreach($r in $rows){
  [void]$sb.Append('<tr>')
  for($i=0;$i -lt $h.Count;$i++){
   $v = ''; if($i -lt @($r).Count){ $v = [string]@($r)[$i] }
   if($v.Length -gt 3000){ $v = $v.Substring(0,3000) + ' [...]' }
   if($v -eq ''){ [void]$sb.Append('<td>-</td>') }
   elseif($badge -contains $i){ [void]$sb.Append('<td><span class="b '+(BadgeCls $v)+'">'+(HtmlEnc $v)+'</span></td>') }
   else{ [void]$sb.Append('<td>'+(HtmlEnc $v)+'</td>') }
  }
  [void]$sb.Append('</tr>')
 }
 [void]$sb.Append('</tbody></table></div>')
 if($total -gt $rows.Count){ [void]$sb.Append(('<p class="more">Mostrando {0} de {1} filas. Datos completos en Artifacts\Json, Artifacts\Csv e Informe_Forense.json.</p>' -f $rows.Count,$total)) }
}
function RenderHtml([switch]$Partial){
 $sb = New-Object System.Text.StringBuilder
 $leaf = Split-Path -Leaf $script:CaseRoot
 $gen = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
 [void]$sb.Append('<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
 [void]$sb.Append('<title>EviDumpWin - '+(HtmlEnc $env:COMPUTERNAME)+' - '+(HtmlEnc $leaf)+'</title><style>'+$script:Css+'</style></head><body>')
 [void]$sb.Append('<header class="top"><div class="brand">EviDumpWin '+(HtmlEnc $script:Version)+' &middot; Adquisicion forense en vivo</div>')
 [void]$sb.Append('<h1>Informe forense &middot; '+(HtmlEnc $env:COMPUTERNAME)+'</h1><div class="sub">')
 foreach($kv in @(@('Caso',$leaf),@('Perfil',$script:AcqProfile),@('Investigador',$script:Investigator),@('Inicio UTC',$script:Now.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')),@('Generado UTC',$gen))){ [void]$sb.Append('<span><b>'+$kv[0]+':</b> '+(HtmlEnc ([string]$kv[1]))+'</span>') }
 [void]$sb.Append('</div></header><main>')
 $alta = @($script:Findings | Where-Object { $_.Severidad -eq 'Alta' }).Count
 $media = @($script:Findings | Where-Object { $_.Severidad -eq 'Media' }).Count
 $fOk = @($script:Results | Where-Object { $_.Estado -like 'OK*' }).Count
 $fErr = @($script:Results | Where-Object { $_.Estado -eq 'ERROR' }).Count
 $files = 0; foreach($k in 'Files','Registry','Browser','Events','Raw'){ $files += [int]$script:ArtifactStats[$k] }
 $min = 0; if($script:RunTimer){ $min = [math]::Round($script:RunTimer.Elapsed.TotalMinutes,1) }
 $kpis = @(
  @($alta,'Indicadores altos',$(if($alta -gt 0){ 'red' }else{ 'grn' })),
  @($media,'Indicadores medios',$(if($media -gt 0){ 'amb' }else{ 'grn' })),
  @(("{0}/{1}" -f $fOk,$script:Results.Count),'Fases correctas',$(if($fErr -gt 0){ 'red' }else{ 'grn' })),
  @($script:SetIndex.Count,'Conjuntos de datos','blu'),
  @($files,'Ficheros y salidas','blu'),
  @("$min min",'Duracion','blu')
 )
 [void]$sb.Append('<div class="kpis">')
 foreach($k in $kpis){ [void]$sb.Append('<div class="kpi '+$k[2]+'"><div class="v">'+(HtmlEnc ([string]$k[0]))+'</div><div class="l">'+$k[1]+'</div></div>') }
 [void]$sb.Append('</div>')
 if($Partial){ [void]$sb.Append('<div class="alert">ADQUISICION INCOMPLETA: el proceso se interrumpio antes de terminar.</div>') }
 $heads = @($script:Blocks | Where-Object { $_.K -eq 'H' -and $_.L -le 2 })
 [void]$sb.Append('<nav class="toc"><h2>Contenido</h2><ol>')
 for($i=0;$i -lt $heads.Count;$i++){ [void]$sb.Append('<li><a href="#s'+($i+1)+'">'+(HtmlEnc $heads[$i].T)+'</a></li>') }
 [void]$sb.Append('<li><a href="#anexo">Anexo: conjuntos de datos</a></li></ol></nav>')
 $sec = 0; $open = $false; $inList = $false
 foreach($b in $script:Blocks){
  if($b.K -ne 'LI' -and $inList){ [void]$sb.Append('</ul>'); $inList = $false }
  if($b.K -eq 'H'){
   if($b.L -le 2){ if($open){ [void]$sb.Append('</section>') }; $sec++; [void]$sb.Append('<section id="s'+$sec+'"><h2>'+(HtmlEnc $b.T)+'</h2>'); $open = $true }
   else{ [void]$sb.Append('<h3>'+(HtmlEnc $b.T)+'</h3>') }
  }
  elseif($b.K -eq 'P'){ $t = $b.T.TrimEnd(); if($t.EndsWith(':')){ [void]$sb.Append('<h3>'+(Inline $t.TrimEnd(':'))+'</h3>') } else { [void]$sb.Append('<p>'+(Inline $t)+'</p>') } }
  elseif($b.K -eq 'N'){ [void]$sb.Append('<div class="note">'+(Inline $b.T)+'</div>') }
  elseif($b.K -eq 'LI'){ if(-not $inList){ [void]$sb.Append('<ul>'); $inList = $true }; [void]$sb.Append('<li>'+(Inline $b.T)+'</li>') }
  elseif($b.K -eq 'T'){ TableHtml $sb $b.H $b.R $b.Total $b.Cls }
 }
 if($inList){ [void]$sb.Append('</ul>') }
 if($open){ [void]$sb.Append('</section>') }
 [void]$sb.Append('<section id="anexo"><h2>Anexo: conjuntos de datos</h2><p>Vista previa de hasta 150 filas por conjunto. Los datos completos estan en <code>Artifacts\Json</code>, <code>Artifacts\Csv</code> y <code>Reports\Informe_Forense.json</code>.</p>')
 foreach($k in $script:SetPreview.Keys){
  $pv = $script:SetPreview[$k]
  [void]$sb.Append('<details><summary>'+(HtmlEnc $k)+'<span class="cnt">'+$pv.Filas+' filas</span></summary>')
  $vista = @($pv.Vista)
  if($vista.Count -eq 0){ [void]$sb.Append('<p class="empty">Sin datos.</p>') }
  else{
   $cols = New-Object System.Collections.Generic.List[string]
   foreach($r in $vista){ foreach($pp in $r.PSObject.Properties){ if(-not $cols.Contains($pp.Name)){ $cols.Add($pp.Name) } } }
   $rl = New-Object System.Collections.Generic.List[object]
   foreach($r in $vista){ $cells = New-Object System.Collections.Generic.List[string]; foreach($c in $cols){ $v = P $r $c; if($null -eq $v){ $cells.Add('') } else { $cells.Add([string]$v) } }; $rl.Add($cells.ToArray()) }
   TableHtml $sb $cols.ToArray() $rl.ToArray() $pv.Filas
  }
  [void]$sb.Append('</details>')
 }
 [void]$sb.Append('</section></main>')
 [void]$sb.Append('<footer>Generado por EviDumpWin '+(HtmlEnc $script:Version)+' el '+$gen+' UTC. La integridad de este informe y del resto del caso se verifica con <code>Reports\hash_manifest_sha256.csv</code> y su fichero <code>.sha256</code>.</footer></body></html>')
 $sb.ToString()
}

# ---------------------------------------------------------------- render texto y PDF interno (respaldo sin navegador)
function Fit([string]$s,[int]$w){ $s = ($s -replace '\s+',' ').Trim(); if($s.Length -le $w){ return $s.PadRight($w) }; if($w -le 1){ return $s.Substring(0,$w) }; $s.Substring(0,$w-1) + '~' }
function RenderText([int]$width=180,[switch]$Partial){
 $out = New-Object System.Collections.Generic.List[string]
 $out.Add(("EVIDUMPWIN {0} - INFORME FORENSE - {1}" -f $script:Version,$env:COMPUTERNAME)); $out.Add(('=' * $width))
 if($Partial){ $out.Add('*** ADQUISICION INCOMPLETA: el proceso se interrumpio antes de terminar ***') }
 foreach($b in $script:Blocks){
  if($b.K -eq 'H'){ $out.Add(''); $out.Add($b.T.ToUpper()); $out.Add(('-' * [math]::Min($width,$b.T.Length))) }
  elseif($b.K -eq 'P'){ if($b.T.TrimEnd().EndsWith(':')){ $out.Add('') }; $out.Add(($b.T -replace '`','' -replace '\*\*','')) }
  elseif($b.K -eq 'N'){ $out.Add('NOTA: ' + ($b.T -replace '`','' -replace '\*\*','')) }
  elseif($b.K -eq 'LI'){ $out.Add('  * ' + ($b.T -replace '`','')) }
  elseif($b.K -eq 'T'){
   $h = @($b.H); $rows = @($b.R); $n = $h.Count
   if($rows.Count -eq 0){ $out.Add('  (sin datos)'); continue }
   $nat = @(); for($i=0;$i -lt $n;$i++){ $m = $h[$i].Length; foreach($r in $rows){ $l = ([string]@($r)[$i]).Length; if($l -gt $m){ $m = $l } }; $nat += [math]::Min($m,80) }
   $avail = $width - 3*($n-1); $sum = 0; foreach($x in $nat){ $sum += $x }
   $wd = @(); for($i=0;$i -lt $n;$i++){ $x = $nat[$i]; if($sum -le $avail){ $wd += $x } else { $wd += [math]::Min($x,[math]::Max([math]::Min($h[$i].Length,12),[math]::Floor($avail*$x/$sum))) } }
   $out.Add((@(for($i=0;$i -lt $n;$i++){ Fit $h[$i] $wd[$i] }) -join ' | '))
   $out.Add((@(for($i=0;$i -lt $n;$i++){ '-' * $wd[$i] }) -join '-+-'))
   foreach($r in $rows){ $out.Add((@(for($i=0;$i -lt $n;$i++){ Fit ([string]@($r)[$i]) $wd[$i] }) -join ' | ')) }
   if($b.Total -gt $rows.Count){ $out.Add(("  ... mostrando {0} de {1} filas" -f $rows.Count,$b.Total)) }
  }
 }
 $out.ToArray()
}
function PdfEsc([string]$s){
 $sb = New-Object System.Text.StringBuilder
 foreach($ch in $s.ToCharArray()){
  $c = [int]$ch
  if($ch -eq '\' -or $ch -eq '(' -or $ch -eq ')'){ [void]$sb.Append('\').Append($ch) }
  elseif($c -lt 32){ [void]$sb.Append(' ') }
  elseif($c -gt 255){ [void]$sb.Append('?') }
  else{ [void]$sb.Append($ch) }
 }
 $sb.ToString()
}
function WritePdfText([string[]]$lines,[string]$path){
 $enc = [Text.Encoding]::GetEncoding(28591)
 $W = 842; $H = 595; $M = 28; $fs = 6.5; $lead = 8
 $cpl = [int][math]::Floor(($W-2*$M)/($fs*0.6))
 $lpp = [int][math]::Floor(($H-2*$M-16)/$lead)
 $wr = New-Object System.Collections.Generic.List[string]
 foreach($l in $lines){ $t = [string]$l; if($t.Length -eq 0){ $wr.Add(''); continue }; while($t.Length -gt $cpl){ $wr.Add($t.Substring(0,$cpl)); $t = '    ' + $t.Substring($cpl) }; $wr.Add($t) }
 $pages = [int][math]::Max(1,[math]::Ceiling($wr.Count/$lpp))
 $ms = New-Object System.IO.MemoryStream
 $off = New-Object 'System.Collections.Generic.List[long]'
 $put = { param([string]$x) $bb = $enc.GetBytes($x); $ms.Write($bb,0,$bb.Length) }
 & $put "%PDF-1.4`n%"; $ms.Write([byte[]](0xE2,0xE3,0xCF,0xD3,0x0A),0,5)
 $off.Add($ms.Position); & $put "1 0 obj`n<< /Type /Catalog /Pages 2 0 R >>`nendobj`n"
 $kids = (@(for($i=0;$i -lt $pages;$i++){ "{0} 0 R" -f (4+2*$i) }) -join ' ')
 $off.Add($ms.Position); & $put ("2 0 obj`n<< /Type /Pages /Kids [{0}] /Count {1} >>`nendobj`n" -f $kids,$pages)
 $off.Add($ms.Position); & $put "3 0 obj`n<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>`nendobj`n"
 $ci = [Globalization.CultureInfo]::InvariantCulture
 for($p=0;$p -lt $pages;$p++){
  $cs = New-Object System.Text.StringBuilder
  [void]$cs.Append(("BT /F1 {0} Tf {1} TL {2} {3} Td " -f $fs.ToString($ci),$lead.ToString($ci),$M,($H-$M-$fs)))
  [void]$cs.Append('(' + (PdfEsc ("EviDumpWin {0} | {1} | Pagina {2} de {3}" -f $script:Version,$env:COMPUTERNAME,($p+1),$pages)) + ') Tj T* T* ')
  for($j=$p*$lpp;$j -lt [math]::Min($wr.Count,($p+1)*$lpp);$j++){ [void]$cs.Append('(' + (PdfEsc $wr[$j]) + ') Tj T* ') }
  [void]$cs.Append('ET')
  $content = $cs.ToString()
  $off.Add($ms.Position); & $put ("{0} 0 obj`n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {1} {2}] /Resources << /Font << /F1 3 0 R >> >> /Contents {3} 0 R >>`nendobj`n" -f (4+2*$p),$W,$H,(5+2*$p))
  $off.Add($ms.Position); & $put ("{0} 0 obj`n<< /Length {1} >>`nstream`n" -f (5+2*$p),$enc.GetByteCount($content)); & $put $content; & $put "`nendstream`nendobj`n"
 }
 $xref = $ms.Position
 & $put ("xref`n0 {0}`n0000000000 65535 f `n" -f ($off.Count+1))
 foreach($o in $off){ & $put ("{0:D10} 00000 n `n" -f $o) }
 & $put ("trailer`n<< /Size {0} /Root 1 0 R >>`nstartxref`n{1}`n%%EOF`n" -f ($off.Count+1),$xref)
 [IO.File]::WriteAllBytes($path,$ms.ToArray())
}
function MakePdf([switch]$Partial){
 $ErrorActionPreference = 'Continue'
 $exe = $script:PdfBrowser
 if($exe -and (Test-Path -LiteralPath $script:ReportPath)){
  $tmp = Join-Path $script:CaseRoot ('_pdf_tmp_' + [guid]::NewGuid().ToString('N'))
  try{
   New-Item -ItemType Directory -Path $tmp -Force | Out-Null
   if(Test-Path -LiteralPath $script:PdfPath){ Remove-Item -LiteralPath $script:PdfPath -Force -ErrorAction SilentlyContinue }
   $uri = [Uri]::new($script:ReportPath,[UriKind]::Absolute).AbsoluteUri
   $a = @('--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-extensions','--disable-sync','--disable-background-networking','--no-pdf-header-footer','--print-to-pdf-no-header',('"--user-data-dir={0}"' -f $tmp),('"--print-to-pdf={0}"' -f $script:PdfPath),$uri)
   $sp = @{FilePath=$exe;ArgumentList=$a;PassThru=$true}
   if([Environment]::OSVersion.Platform -eq 'Win32NT'){ $sp['WindowStyle'] = 'Hidden' }
   $pr = Start-Process @sp
   if(-not $pr.WaitForExit(240000)){ try{ $pr.Kill() }catch{}; LG WARN 'PDF: el navegador no termino en 4 minutos.' }
   for($i=0;$i -lt 20 -and -not (Test-Path -LiteralPath $script:PdfPath);$i++){ Start-Sleep -Milliseconds 500 }
  }catch{ LG WARN "PDF con navegador: $($_.Exception.Message)" }
  finally{
   for($i=0;$i -lt 10 -and (Test-Path -LiteralPath $tmp);$i++){ try{ Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction Stop }catch{ Start-Sleep -Milliseconds 700 } }
   if(Test-Path -LiteralPath $tmp){ LG WARN "No se pudo eliminar el perfil temporal del navegador: $tmp" }
  }
  if((Test-Path -LiteralPath $script:PdfPath) -and (Get-Item -LiteralPath $script:PdfPath).Length -gt 0){ $script:PdfMethod = "Navegador headless ($(Split-Path -Leaf $exe))"; LG INFO "PDF generado con $script:PdfMethod"; return }
  LG WARN 'El navegador no genero el PDF; se usa el generador interno.'
 }
 try{ WritePdfText (RenderText -Partial:$Partial) $script:PdfPath; $script:PdfMethod = 'Generador interno (texto)'; LG INFO 'PDF generado con el generador interno.' }catch{ LG WARN "PDF interno: $($_.Exception.Message)" }
}

# ---------------------------------------------------------------- JSON y CSV del informe
function JsonOf($o){ $x = ToObj $o; if($null -eq $x){ return 'null' }; ConvertTo-Json -InputObject $x -Depth 6 }
function WriteJsonReport([switch]$Partial){
 $w = New-Object System.IO.StreamWriter($script:JsonReportPath,$false,$script:Utf8NoBom)
 try{
  $caso = [ordered]@{Herramienta='EviDumpWin';Version=$script:Version;Parcial=[bool]$Partial;GeneradoUtc=(Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')}
  foreach($c in $script:CaseInfo){ $caso[$c.Campo] = $c.Valor }
  $w.Write('{'); $w.Write("`n""caso"": "); $w.Write((JsonOf $caso))
  foreach($part in @(@('resumen',$script:Summary.ToArray()),@('indicadores',$script:Findings.ToArray()),@('fases',$script:Results.ToArray()),@('estadisticas',$script:ArtifactStats),@('metricas',$script:Data['metrics']),@('indice_artefactos',$script:SetIndex.ToArray()),@('copias',$script:Copies.ToArray()))){
   $v = $part[1]
   if($v -is [array] -and $v.Count -eq 0){ $j = '[]' } else { $j = JsonOf $v }
   $w.Write(",`n""" + $part[0] + """: "); $w.Write($j)
  }
  $w.Write(",`n""artefactos"": {")
  $first = $true
  foreach($k in $script:SetPreview.Keys){
   $f = Join-Path $script:Dirs.Json "$k.json"
   if(-not (Test-Path -LiteralPath $f)){ continue }
   if(-not $first){ $w.Write(',') }; $first = $false
   $w.Write("`n" + (ConvertTo-Json -InputObject ([string]$k)) + ': ')
   $w.Write([IO.File]::ReadAllText($f))
  }
  $w.Write("`n}`n}`n")
 }finally{ $w.Dispose() }
}
function CsvOut($rows,[string]$name,[string[]]$cols){
 $p = Join-Path $script:CsvReportDir $name
 $r = @($rows | Where-Object { $null -ne $_ })
 if($r.Count -eq 0){ [IO.File]::WriteAllText($p,(($cols | ForEach-Object { '"' + $_ + '"' }) -join ',') + "`r`n",$script:Utf8Bom); return }
 $r | Select-Object $cols | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding $script:CsvEnc
}
function WriteCsvReports{
 New-Item -ItemType Directory -Path $script:CsvReportDir -Force | Out-Null
 CsvOut $script:CaseInfo 'caso.csv' @('Campo','Valor')
 CsvOut $script:Summary.ToArray() 'resumen.csv' @('Area','Estado','Detalle')
 CsvOut $script:Findings.ToArray() 'indicadores.csv' @('Severidad','Area','Detalle')
 CsvOut $script:Results.ToArray() 'fases.csv' @('Nombre','Estado','Avisos','Segundos','Detalle')
 $st = @(); foreach($k in $script:ArtifactStats.Keys){ $st += [pscustomobject]@{Tipo=$k;Cantidad=$script:ArtifactStats[$k]} }
 CsvOut $st 'estadisticas.csv' @('Tipo','Cantidad')
 CsvOut $script:SetIndex.ToArray() 'indice_artefactos.csv' @('Conjunto','Filas','CSV')
}
function SaveReport([switch]$Partial){
 $top = @(BuildTop -Partial:$Partial)
 WriteMeta
 $script:Blocks.InsertRange($script:HeaderEnd,[object[]]$top)
 try{ [IO.File]::WriteAllText($script:ReportPath,(RenderHtml -Partial:$Partial),$script:Utf8NoBom) }catch{ LG WARN "Informe HTML: $($_.Exception.Message)" }
 try{ WriteCsvReports }catch{ LG WARN "Informes CSV: $($_.Exception.Message)" }
 try{ WriteJsonReport -Partial:$Partial }catch{ LG WARN "Informe JSON: $($_.Exception.Message)" }
 MakePdf -Partial:$Partial
 $script:ReportSaved = $true
}
function SaveCopyLog{ try{ if($script:Copies.Count -gt 0){ $script:Copies | Export-Csv -LiteralPath $script:CopyLogPath -NoTypeInformation -Encoding $script:CsvEnc } }catch{ LG WARN "acquisition_log: $($_.Exception.Message)" } }
function Hashes{
 $side = $script:HashPath + '.sha256'
 $files = @(Get-ChildItem -LiteralPath $script:CaseRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $script:HashPath -and $_.FullName -ne $side })
 $rows = New-Object System.Collections.Generic.List[object]
 $i = 0
 foreach($f in $files){
  $i++; if(($i % 50) -eq 0){ ShowProg -status ("Hashes {0}/{1}" -f $i,$files.Count) -step ($script:ProgressTotal) -total $script:ProgressTotal -sub (($i/[math]::Max(1,$files.Count))*100) }
  $h = 'ERROR'
  try{ $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }catch{ AddStat 'HashFailures' }
  $rows.Add([pscustomobject]@{RelativePath=(Rel $f.FullName);Length=$f.Length;SHA256=$h;LastWriteTimeUtc=(UtcStr $f.LastWriteTime)})
 }
 $rows | Export-Csv -LiteralPath $script:HashPath -NoTypeInformation -Encoding $script:CsvEnc
 $mh = (Get-FileHash -LiteralPath $script:HashPath -Algorithm SHA256).Hash
 [IO.File]::WriteAllText($side,("{0}  {1}`r`n" -f $mh,(Split-Path -Leaf $script:HashPath)),$script:Utf8NoBom)
 $script:ManifestHash = $mh
 $script:ManifestCount = $rows.Count
}
function Done{
 Write-Host ''
 C '============================================================' Green
 C '                    ADQUISICION COMPLETADA                   ' Yellow
 C '============================================================' Green
 Write-Host " Caso      : $script:CaseRoot"
 Write-Host " HTML      : $script:ReportPath"
 Write-Host " PDF       : $script:PdfPath ($script:PdfMethod)"
 Write-Host " JSON      : $script:JsonReportPath"
 Write-Host " CSV       : $script:CsvReportDir"
 Write-Host " Log       : $script:LogPath"
 Write-Host " Hashes    : $script:HashPath ($($script:ManifestCount) ficheros)"
 C (" SHA256 del manifiesto: {0}" -f $script:ManifestHash) Yellow
 Write-Host (" Tiempo    : {0} min" -f [math]::Round($script:RunTimer.Elapsed.TotalMinutes,2))
 Write-Host ''
 foreach($r in $script:Summary){ Write-Host (" - {0} [{1}]: {2}" -f $r.Area,$r.Estado,$r.Detalle) }
 $hi = @($script:Findings | Where-Object { $_.Severidad -eq 'Alta' }).Count
 if($hi -gt 0){ Warn "$hi indicadores de severidad Alta: revisar la seccion 'Indicadores a revisar' del informe." }
 Write-Host ''
 Write-Host ' Artefactos:' -ForegroundColor Cyan
 foreach($k in $script:ArtifactStats.Keys){ Write-Host ("   {0}: {1}" -f $k,$script:ArtifactStats[$k]) }
 Write-Host ''
}

# ---------------------------------------------------------------- flujo principal
$script:HeaderEnd = 0
$script:ManifestHash = ''
$script:ManifestCount = 0
$script:Finished = $false
$script:ReportSaved = $false
$script:ExitCode = 0
try{
 Setup
 $script:RunTimer = [Diagnostics.Stopwatch]::StartNew()
 LoadProfiles
 InitRegLW
 InitReport
 $script:HeaderEnd = $script:Blocks.Count
 $phases = New-Object System.Collections.Generic.List[object]
 $phases.Add(@('Red',{ CollectNetwork }))
 $phases.Add(@('Procesos, servicios y drivers',{ CollectRuntime }))
 $phases.Add(@('Usuarios y sesiones',{ CollectUsers }))
 $phases.Add(@('Sistema',{ CollectSystem }))
 $phases.Add(@('Persistencia',{ CollectPersistence }))
 $phases.Add(@('Seguridad',{ CollectSecurity }))
 $phases.Add(@('Registro y dispositivos',{ CollectRegistryDevices }))
 $phases.Add(@('Actividad de usuario',{ CollectUserActivity }))
 if($script:Level -ge 2){
  $phases.Add(@('Eventos',{ CollectEvents }))
  $phases.Add(@('Hives del registro',{ CollectHives }))
  $phases.Add(@('Ficheros del sistema',{ CollectSystemFiles }))
  $phases.Add(@('Navegadores',{ CollectBrowsers }))
 }
 if($script:Level -ge 3){
  $phases.Add(@('EVTX completos',{ CollectAllEvents }))
  $phases.Add(@('Binarios: hash y firma',{ CollectBinaries }))
  $phases.Add(@('Extras Pro',{ CollectProExtras }))
 }
 $phases.Add(@('Timeline',{ CollectTimeline }))
 $phases.Add(@('Analisis de indicadores',{ CollectFindings }))
 $script:ProgressTotal = $phases.Count + 1
 $script:ProgressCurrent = 0
 if($script:Level -eq 1){ ST 'Perfil' 'INFO' 'Rapido: sin EVTX completos, hives, navegadores ni copias de ficheros de sistema.' }
 Info ("Perfil {0}: {1} fases. Orden de volatilidad: red y procesos primero." -f $script:AcqProfile,$phases.Count)
 foreach($ph in $phases){ RunCollect $ph[0] $ph[1] }
 ShowProg -status 'Generando informe y manifiesto de hashes' -step $script:ProgressTotal -total $script:ProgressTotal
 $script:RunTimer.Stop()
 SaveCopyLog
 SaveReport
 $err = @($script:Results | Where-Object { $_.Estado -eq 'ERROR' }).Count
 LG INFO $(if($err -gt 0){ "Adquisicion finalizada con $err fases en error. Se calcula el manifiesto de hashes; el log no se modifica despues." }else{ 'Adquisicion finalizada correctamente. Se calcula el manifiesto de hashes; el log no se modifica despues.' })
 Hashes
 $script:Finished = $true
 EndProg
 Done
}catch{
 $script:ExitCode = 1
 Fail "Error fatal: $($_.Exception.Message) (linea $($_.InvocationInfo.ScriptLineNumber))"
 LG ERROR ("Error fatal: {0} (linea {1})" -f $_.Exception.Message,$_.InvocationInfo.ScriptLineNumber)
}finally{
 if(-not $script:Finished -and $script:CaseRoot -and $script:ReportPath -and (Test-Path -LiteralPath $script:CaseRoot)){
  try{
   if($script:RunTimer){ $script:RunTimer.Stop() } else { $script:RunTimer = [Diagnostics.Stopwatch]::new() }
   SaveCopyLog
   if(-not $script:ReportSaved){ SaveReport -Partial }
   LG WARN 'Adquisicion interrumpida: informe parcial guardado.'
   Hashes
   Warn "Adquisicion interrumpida. Informe parcial: $script:ReportPath"
  }catch{}
 }
 EndProg
}
exit $script:ExitCode
