[CmdletBinding()]
param(
    [string]$ReportPath = (Join-Path -Path (Get-Location) -ChildPath "Auditoria-Scripts(Resultado).md"),
    [switch]$VerboseReport
)

# --- Globals ---
$script:Utf8Bom = New-Object System.Text.UTF8Encoding($true)
$script:ReportLines = New-Object System.Collections.Generic.List[string]
$script:Summary = [ordered]@{}
$script:Now = Get-Date
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ================================
# BANNER DE INICIO
# ================================
function Show-Banner {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "              EviDumpWin" -ForegroundColor Yellow
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " Equipo: $env:COMPUTERNAME" -ForegroundColor White
    Write-Host " Usuario: $env:USERNAME" -ForegroundColor White
    Write-Host " Fecha: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor White
    Write-Host " Reporte: $ReportPath" -ForegroundColor White
    Write-Host ""
    Write-Host " Analizando sistema..." -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ================================
# BARRA DE PROGRESO
# ================================
function Show-Progress {
    param(
        [string]$Activity = "Ejecutando Auditoria",
        [string]$Status = "Procesando",
        [int]$PercentComplete = 0
    )
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

# -----------------------------------------
# Utilities
# -----------------------------------------
function Add-Line([string]$Text = "") {
    $script:ReportLines.Add($Text)
}
function Add-Block([string[]]$Lines) {
    foreach ($l in $Lines) { Add-Line $l }
}
function Add-Title([string]$Text, [int]$Level = 2) {
    Add-Line ""
    Add-Line ("{0} {1}" -f ("#" * $Level), $Text)
    Add-Line ""
}
function Add-KeyValueTable([hashtable]$Pairs) {
    Add-Line "| Clave | Valor |"
    Add-Line "|------:|:------|"
    foreach ($k in $Pairs.Keys) {
        $v = if ($Pairs[$k]) { $Pairs[$k] } else { "-" }
        Add-Line ("| **{0}** | {1} |" -f $k, ($v.ToString()).Replace("`n","<br>"))
    }
    Add-Line ""
}
function Add-Table([string[]]$Headers, [object[]]$Rows) {
    if (-not $Headers -or $Headers.Count -eq 0) { return }
    Add-Line ("| {0} |" -f ($Headers -join " | "))
    Add-Line ("|{0}|" -f (($Headers | ForEach-Object { "---" }) -join "|"))
    foreach ($r in $Rows) {
        if ($r -is [string]) {
            Add-Line "| $r |"
        } else {
            $vals = @()
            foreach ($h in $Headers) { $vals += ($r.$h -as [string]) }
            Add-Line ("| {0} |" -f ($vals -join " | "))
        }
    }
    Add-Line ""
}

function Save-Report() {
    try {
        $dir = Split-Path -Path $ReportPath -Parent
        if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        [System.IO.File]::WriteAllLines($ReportPath, $script:ReportLines, $script:Utf8Bom)
        Write-Host "Informe generado en: $ReportPath" -ForegroundColor Green
    } catch {
        Write-Error "No se pudo guardar el informe: $($_.Exception.Message)"
    }
}
function Fmt-Date($dt, [string]$fmt = "dd/MM/yyyy HH:mm:ss") {
    if (-not $dt) { return "-" }
    try { return ([datetime]$dt).ToString($fmt) } catch { return "$dt" }
}
function Set-Summary([string]$Key, [string]$Value) {
    $script:Summary[$Key] = $Value
}

# -----------------------------------------
# 0. Informacion general del sistema
# -----------------------------------------
function Get-InfoGeneral {
    Add-Title "0. Informacion general del sistema" 2

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $memTotalGB = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { "-" }
    
    # Manejo seguro de LastBootUpTime
    $lastBoot = $null
    if ($os.LastBootUpTime) {
        try {
            $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
        } catch {
            try {
                $lastBoot = Get-Date $os.LastBootUpTime -ErrorAction SilentlyContinue
            } catch {
                $lastBoot = $null
            }
        }
    }
    
    $uptime = if ($lastBoot) { (New-TimeSpan -Start $lastBoot -End $script:Now) } else { $null }

    $info = [ordered]@{
        "Equipo"         = $env:COMPUTERNAME
        "Usuario"        = $env:USERNAME
        "Dominio/Grupo"  = if ($cs.Domain) { $cs.Domain } else { $cs.Workgroup }
        "SO"             = if ($os.Caption) { "$($os.Caption) (Build $($os.BuildNumber))" } else { "-" }
        "Instalacion SO" = Fmt-Date $os.InstallDate
        "Arranque"       = Fmt-Date $lastBoot
        "Uptime"         = if ($uptime) { "{0:dd}d {0:hh}h {0:mm}m" -f $uptime } else { "-" }
        "CPU"            = if ($cpu) { $cpu.Name } else { "-" }
        "RAM"            = if ($memTotalGB -ne "-") { "$memTotalGB GB" } else { "-" }
        "Administrador"  = if ($script:IsAdmin) { "Si" } else { "No" }
        "Fecha Informe"  = Fmt-Date $script:Now
    }
    Add-KeyValueTable $info

    # Firewall
    try {
        $fw = Get-NetFirewallProfile -ErrorAction Stop
        $d = ($fw | Where-Object Name -eq "Domain").Enabled
        $p = ($fw | Where-Object Name -eq "Private").Enabled
        $u = ($fw | Where-Object Name -eq "Public").Enabled
        $fwTxt = "Dominio: {0} / Privada: {1} / Publica: {2}" -f ($(if ($d) { 'On' }else { 'Off' }), $(if ($p) { 'On' }else { 'Off' }), $(if ($u) { 'On' }else { 'Off' }))
        $fwIcon = if ($d -and $p -and $u) { "OK" } else { "WARNING" }
        Add-Table @("Componente","Estado") @([pscustomobject]@{ Componente="Firewall de Windows"; Estado="$fwIcon $fwTxt" })
        Set-Summary "Firewall" ("{0} {1}" -f $fwIcon, $fwTxt)
    } catch {
        Add-Table @("Componente","Estado") @([pscustomobject]@{ Componente="Firewall de Windows"; Estado="WARNING No se pudo consultar" })
        Set-Summary "Firewall" "WARNING No se pudo consultar"
    }
}

# -----------------------------------------
# 1. Permisos administrador
# -----------------------------------------
function Get-Permisos-Administrador {
    Add-Title "1. Permisos - Administrador (Resultado)" 2
    if ($script:IsAdmin) {
        Add-Line "OK El usuario actual tiene permisos de administrador (sesion elevada)."
        Set-Summary "Administrador" "OK Si"
    } else {
        Add-Line "NO El usuario actual NO tiene permisos de administrador."
        Set-Summary "Administrador" "NO No"
    }
}

# -----------------------------------------
# 2. Actualizaciones y Antivirus
# -----------------------------------------
function Get-Actualizaciones {
    Add-Title "2. Buscar Actualizaciones (Resultado)" 2
    $updatesTxt = "WARNING No se pudo consultar las actualizaciones."

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $pending = $searcher.Search("IsInstalled=0 and Type='Software'").Updates.Count
        if ($pending -eq 0) { 
            $updatesTxt = "OK El sistema esta actualizado. Sin actualizaciones pendientes." 
        } else { 
            $updatesTxt = "WARNING Hay $pending actualizaciones pendientes." 
        }
    } catch {
        $updatesTxt = "WARNING No fue posible consultar Windows Update (posible restriccion/WSUS)."
    }

    # Ultima KB
    $kbLine = "NO No se hallaron KBs instaladas recientemente."
    try {
        $qfe = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Where-Object { $_.HotFixID }
        $kbs = foreach ($k in $qfe) {
            $dt = $null
            if ($k.InstalledOn) { try { $dt = [datetime]$k.InstalledOn } catch { } }
            [pscustomobject]@{ KB = $k.HotFixID; Date = $dt }
        }
        $last = $kbs | Sort-Object Date -Descending | Select-Object -First 1
        if ($last) { 
            $kbLine = "OK Ultima actualizacion instalada: $($last.KB) el $(Fmt-Date $last.Date 'dd/MM/yyyy')." 
        }
    } catch {
        # Catch vacio pero valido
    }

    Add-Block @(
        "Estado de actualizacion:",
        $updatesTxt,
        "",
        $kbLine
    )

    Set-Summary "Actualizaciones" ($updatesTxt -replace "\*\*", "")
}

# -----------------------------------------
# 3. Estado Windows Defender
# -----------------------------------------
function Get-EstadoWindowsDefender {
    Add-Title "3. Estado Windows Defender (Resultado)" 2

    # Método 1: SecurityCenter2
    Add-Line "Informacion desde SecurityCenter2:"
    $avTxt = "WARNING No se detecto Windows Defender a traves de SecurityCenter2."
    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($av) {
            foreach ($avProduct in $av) {
                if ($avProduct.displayName -like "*Windows Defender*" -or $avProduct.displayName -like "*Windows Security*") {
                    $state = try { [int]$avProduct.productState } catch { 0 }
                    $hex = ('{0:X6}' -f $state)
                    $sig = [int]("0x" + $hex.Substring(0,2))
                    $rtp = [int]("0x" + $hex.Substring(2,2))
                    $sts = [int]("0x" + $hex.Substring(4,2))
                    
                    $sigDesc = switch ($sig) { 
                        0x00 { "OK Firmas al dia" } 
                        0x10 { "WARNING Firmas desactualizadas" } 
                        default { "NO Firmas estado 0x{0:X2}" -f $sig } 
                    }
                    $rtpDesc = switch ($rtp) { 
                        0x00 { "NO Proteccion en tiempo real OFF" } 
                        0x01 { "NO Proteccion en tiempo real OFF" }
                        0x10 { "OK Proteccion en tiempo real ON" } 
                        0x11 { "WARNING Proteccion en tiempo real PARCIAL" }
                        default { "NO Tiempo real 0x{0:X2}" -f $rtp } 
                    }
                    $stsDesc = switch ($sts) { 
                        0x00 { "NO No instalado" } 
                        0x01 { "NO Deshabilitado" }
                        0x10 { "OK Instalado" } 
                        0x11 { "OK Instalado y ejecutandose" }
                        default { "NO Estado 0x{0:X2}" -f $sts } 
                    }
                    
                    $avTxt = "$($avProduct.displayName) - $rtpDesc / $sigDesc / $stsDesc"
                    Add-Line $avTxt
                    Add-Line "Codigo de estado: $state (hex: $hex)"
                }
            }
        } else {
            Add-Line $avTxt
        }
    } catch {
        Add-Line "ERROR Error consultando SecurityCenter2: $($_.Exception.Message)"
    }

    # Método 2: PowerShell Module
    Add-Line ""
    Add-Line "Informacion desde modulo PowerShell:"
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus) {
                $rows = @(
                    [pscustomobject]@{ Componente = "Proteccion en tiempo real"; Estado = if ($defenderStatus.RealTimeProtectionEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "Motor de antivirus"; Estado = if ($defenderStatus.AntivirusEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "Antispyware"; Estado = if ($defenderStatus.AntispywareEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "Comportamiento"; Estado = if ($defenderStatus.BehaviorMonitorEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "IOAV Protection"; Estado = if ($defenderStatus.IoavProtectionEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "Nube"; Estado = if ($defenderStatus.CloudEnabled) { "OK ACTIVADO" } else { "NO DESACTIVADO" } },
                    [pscustomobject]@{ Componente = "Firmas actualizadas"; Estado = if ($defenderStatus.AntivirusSignatureUpdated) { "OK SI" } else { "NO NO" } },
                    [pscustomobject]@{ Componente = "Ultima actualizacion"; Estado = if ($defenderStatus.AntivirusSignatureAge) { "$($defenderStatus.AntivirusSignatureAge) dias" } else { "Desconocido" } }
                )
                Add-Table @("Componente", "Estado") $rows
                
                # Resumen general
                $activeComponents = ($rows | Where-Object { $_.Estado -like "OK*" }).Count
                $totalComponents = $rows.Count
                Add-Line "Resumen: $activeComponents de $totalComponents componentes activos"
                
                if ($activeComponents -eq $totalComponents) {
                    Set-Summary "Windows Defender" "OK Totalmente operativo"
                } elseif ($activeComponents -ge 5) {
                    Set-Summary "Windows Defender" "WARNING Parcialmente operativo ($activeComponents/$totalComponents)"
                } else {
                    Set-Summary "Windows Defender" "NO Con problemas ($activeComponents/$totalComponents)"
                }
            } else {
                Add-Line "NO No se pudo obtener el estado de Windows Defender"
                Set-Summary "Windows Defender" "NO No disponible"
            }
        } else {
            Add-Line "INFO Modulo PowerShell de Defender no disponible"
            Set-Summary "Windows Defender" "INFO Modulo no disponible"
        }
    } catch {
        Add-Line "ERROR Error consultando modulo PowerShell: $($_.Exception.Message)"
        Set-Summary "Windows Defender" "ERROR Error al consultar"
    }
}

# -----------------------------------------
# 4. Protector Pantalla
# -----------------------------------------
function Get-ProtectorPantalla {
    Add-Title "4. Estado del Protector de Pantalla (Resultado)" 2
    $reg = "HKCU:\Control Panel\Desktop"
    try {
        $active = (Get-ItemPropertyValue -Path $reg -Name "ScreenSaveActive" -ErrorAction Stop)
        
        # Manejar timeout que puede no existir
        $timeout = $null
        try {
            $timeout = (Get-ItemPropertyValue -Path $reg -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue)
        } catch {
            $timeout = $null
        }
        
        # Manejar secure que puede no existir
        $secure = $null
        try {
            $secure = (Get-ItemPropertyValue -Path $reg -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue)
        } catch {
            $secure = $null
        }

        if ($active -eq "1") {
            $mins = if ($timeout) { [math]::Round(([int]$timeout)/60,1) } else { "No configurado" }
            Add-Line "OK Protector de pantalla ACTIVADO."
            Add-Line "Se activa tras $mins minutos de inactividad."
            if ($secure -eq "1") { 
                Add-Line "Configurado para bloquear la sesion al activarse." 
            } else { 
                Add-Line "WARNING NO bloquea la sesion al activarse." 
            }
            Set-Summary "Protector pantalla" "OK Activado"
        } else {
            Add-Line "NO Protector de pantalla DESACTIVADO."
            Set-Summary "Protector pantalla" "NO Desactivado"
        }
    } catch {
        Add-Line "WARNING Error al leer configuracion del protector de pantalla: $($_.Exception.Message)"
        Set-Summary "Protector pantalla" "WARNING Error al consultar"
    }
}

# -----------------------------------------
# 5. Redes Wi-Fi guardadas
# -----------------------------------------
function Get-WifiGuardadas {
    Add-Title "5. Redes Wi-Fi Guardadas (Resultado)" 2
    $profiles = @()
    try {
        $raw = netsh wlan show profiles 2>$null
        $profiles = $raw | Where-Object { $_ -match "All User Profile|Perfil de todos los usuarios" } |
            ForEach-Object { ($_ -split ":\s*",2)[1].Trim() } | Where-Object { $_ -and $_ -ne "" } | Select-Object -Unique
    } catch {
        # Catch vacio pero valido
    }

    if (-not $profiles -or $profiles.Count -eq 0) {
        Add-Line "No se encontraron perfiles Wi-Fi."
        Set-Summary "Wi-Fi" "INFO 0 perfiles"
        return
    }
    $rows = @()
    foreach ($p in $profiles) {
        $details = netsh wlan show profile name="$p" key=clear 2>$null
        $hasKey = $details | Select-String "Key Content|Contenido de la clave"
        $security = if ($hasKey) { "Con clave (no mostrada)" } else { "Sin clave" }
        $rows += [pscustomobject]@{ "Perfil" = $p; "Seguridad" = $security }
    }
    Add-Table @("Perfil","Seguridad") $rows
    Set-Summary "Wi-Fi" ("INFO {0} perfiles" -f $profiles.Count)
}

# -----------------------------------------
# 6. VPNs configuradas
# -----------------------------------------
function Get-VPNs {
    Add-Title "6. VPNs Configuradas (Resultado)" 2
    try {
        $vpns = Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue
        if (-not $vpns) { $vpns = Get-VpnConnection -ErrorAction SilentlyContinue }
        if ($vpns) {
            $rows = $vpns | Select-Object Name, ServerAddress, SplitTunneling, AllUserConnection
            Add-Table @("Name","ServerAddress","SplitTunneling","AllUserConnection") $rows
            Set-Summary "VPNs" ("INFO {0} VPN(s)" -f ($vpns | Measure-Object).Count)
        } else {
            Add-Line "No se encontraron conexiones VPN configuradas."
            Set-Summary "VPNs" "INFO 0"
        }
    } catch {
        Add-Line "WARNING Error al consultar VPNs: $($_.Exception.Message)"
        Set-Summary "VPNs" "WARNING Error al consultar"
    }
}

# -----------------------------------------
# Funciones auxiliares
# -----------------------------------------
function Write-HeaderAndTOC {
    Add-Title "Informe de Auditoria del Equipo" 1
    Add-Block @(
        "Generado: $(Fmt-Date $script:Now)",
        "Equipo: $env:COMPUTERNAME",
        "Usuario: $env:USERNAME",
        "",
        "---",
        "### Tabla de contenidos",
        "- 0. Informacion general del sistema",
        "- 1. Permisos - Administrador", 
        "- 2. Buscar Actualizaciones",
        "- 3. Estado Windows Defender",
        "- 4. Estado del Protector de Pantalla",
        "- 5. Redes Wi-Fi Guardadas",
        "- 6. VPNs Configuradas",
        "",
        "---"
    )
}

function Write-ResumenEjecutivo {
    Add-Title "Resumen Ejecutivo" 2
    $rows = @()
    foreach ($k in $script:Summary.Keys) { $rows += [pscustomobject]@{ "Componente" = $k; "Estado/Detalle" = $script:Summary[$k] } }
    if ($rows.Count -eq 0) { Add-Line "No hay elementos en el resumen" } else { Add-Table @("Componente","Estado/Detalle") $rows }
}

# ================================
# BANNER DE FINALIZACION
# ================================
function Show-CompletionBanner {
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "           AUDITORIA COMPLETADA" -ForegroundColor Yellow
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " Informe generado exitosamente" -ForegroundColor Green
    Write-Host " Ubicacion: $ReportPath" -ForegroundColor White
    Write-Host ""
    Write-Host " Resumen ejecutivo:" -ForegroundColor Cyan
    Write-Host " -----------------" -ForegroundColor Cyan
    foreach ($k in $script:Summary.Keys) { 
        Write-Host "  $k : $($script:Summary[$k])" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
}

# ================================
# EJECUCION PRINCIPAL
# ================================
Show-Banner

# Mostrar progreso inicial
Show-Progress -Activity "Iniciando auditoria de seguridad" -Status "Preparando sistema..." -PercentComplete 0

Write-HeaderAndTOC
Show-Progress -Activity "Generando informe" -Status "Informacion general del sistema..." -PercentComplete 10

Get-InfoGeneral
Show-Progress -Activity "Generando informe" -Status "Verificando permisos..." -PercentComplete 20

Get-Permisos-Administrador
Show-Progress -Activity "Generando informe" -Status "Comprobando actualizaciones..." -PercentComplete 30

Get-Actualizaciones
Show-Progress -Activity "Generando informe" -Status "Analizando Windows Defender..." -PercentComplete 40

Get-EstadoWindowsDefender
Show-Progress -Activity "Generando informe" -Status "Revisando protector de pantalla..." -PercentComplete 50

Get-ProtectorPantalla
Show-Progress -Activity "Generando informe" -Status "Escaneando redes Wi-Fi..." -PercentComplete 60

Get-WifiGuardadas
Show-Progress -Activity "Generando informe" -Status "Verificando VPNs..." -PercentComplete 70

Get-VPNs
Show-Progress -Activity "Generando informe" -Status "Generando resumen ejecutivo..." -PercentComplete 80

# Resumen al final
Write-ResumenEjecutivo
Show-Progress -Activity "Generando informe" -Status "Guardando reporte..." -PercentComplete 90

# Guardar informe
Save-Report

# Completar progreso
Show-Progress -Activity "Generando informe" -Status "Completado" -PercentComplete 100
Start-Sleep -Milliseconds 500
Write-Progress -Activity "Generando informe" -Completed

Show-CompletionBanner

if ($VerboseReport) {
    Write-Host "--- Resumen rapido ---" -ForegroundColor Cyan
    foreach ($k in $script:Summary.Keys) { Write-Host ("{0}: {1}" -f $k, $script:Summary[$k]) -ForegroundColor White }
}