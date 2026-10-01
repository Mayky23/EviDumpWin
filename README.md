# EviDumpWin

`EviDumpWin.ps1` es un recolector forense en vivo para Windows orientado a respuesta a incidentes y auditoria. Funciona con un asistente interactivo en terminal (sin parametros): pide la ruta del caso, el nombre, el investigador, el motivo y el perfil de adquisicion, y genera un caso completo con informes, artefactos, log, registro de custodia y manifiesto de hashes.

## Que hace

- Recoge primero la evidencia mas volatil (red y procesos) y despues el resto, siguiendo el orden de volatilidad.
- Exporta informes con toda la informacion de la adquisicion en `JSON`, `CSV`, `PDF` y `HTML` (con CSS integrado), mas salidas crudas de utilidades nativas.
- Copia evidencias del host conservando la estructura y las marcas de tiempo originales; los ficheros bloqueados (Amcache, SRUM, hives no cargadas, bases de datos de navegador) se copian via sombra de volumen temporal (`esentutl /vss`) cuando hay privilegios.
- Exporta hives del registro con `reg save`, incluidas las de los usuarios con sesion iniciada.
- Analiza artefactos de registro: BAM, UserAssist (ROT13 y contadores), RecentDocs, MRUs, ShellBags, USB, redes conocidas.
- Genera un timeline consolidado en UTC y una seccion de **indicadores a revisar** (persistencia WMI, logs borrados, Defender desactivado o con exclusiones, procesos y servicios en rutas escribibles, lineas de comando sospechosas, etc.).
- Registra cada copia en `Logs\acquisition_log.csv` (origen, metodo, estado y marcas de tiempo originales).
- Calcula un manifiesto `SHA256` de todo el caso **despues** de cerrar el informe y el log, y el SHA256 del propio manifiesto.
- Sigue trabajando aunque una fuente falle (permisos, bloqueos, componentes ausentes) y, si se interrumpe, guarda un informe parcial.

## Uso

Ejecuta en una consola **como administrador**, sin cambiar la politica de ejecucion del equipo investigado:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\EviDumpWin.ps1
```

Si el script se descargo de Internet y se lanza como `.\EviDumpWin.ps1`, desbloquealo antes (la politica `RemoteSigned` bloquea scripts descargados sin firma):

```powershell
Unblock-File .\EviDumpWin.ps1
```

El script no admite parametros. El asistente solicita:

1. Ruta base del caso (por defecto, junto al script; se avisa si esta en la unidad del sistema).
2. Nombre del caso (se sanea; si ya existe se crea una carpeta nueva).
3. Investigador / operador.
4. Motivo o referencia del caso.
5. Perfil de adquisicion.
6. Si se restringen los permisos de la carpeta del caso (contiene hives y credenciales de navegador).

Si no se ejecuta como administrador, ofrece relanzarse elevado (UAC). En sesiones no interactivas usa los valores por defecto (perfil Completo).

## Perfiles

| Perfil | Contenido |
|---|---|
| `Rapido` | Red, procesos, usuarios y sesiones, sistema, persistencia, seguridad, registro y dispositivos, actividad de usuario, timeline e indicadores. Sin copias pesadas. |
| `Completo` | Todo lo anterior + EVTX clave y eventos relevantes, hives del registro (HKLM y usuarios), ficheros de sistema (Prefetch, Amcache, SRUM, tareas, setupapi, repositorio WMI...), navegadores. Recomendado. |
| `Pro` | Todo lo anterior + exportacion de todos los EVTX con registros, hash y firma Authenticode de binarios (procesos, servicios, drivers, autoruns y tareas), WER, cache RDP, WebCache, `$I` de la papelera, reglas de firewall y timeline ampliado. Ventana de eventos de 90 dias. |

## Estructura de salida

```text
<ruta-del-caso>\
  Reports\
    Informe_Forense.html
    Informe_Forense.pdf
    Informe_Forense.json
    CSV\
    hash_manifest_sha256.csv
    hash_manifest_sha256.csv.sha256
  Logs\
    EviDumpWin.log
    acquisition_log.csv
  Artifacts\
    Json\
    Csv\
    Raw\
    Files\
    Registry\
    Events\
    Browser\
    Timeline\
```

## Artefactos que recolecta

### Red

- Configuracion IP, adaptadores, rutas, cache ARP y DNS.
- Conexiones TCP y endpoints UDP con nombre y ruta del proceso.
- Shares, sesiones y unidades SMB mapeadas.
- RDP (estado, puerto, NLA), perfiles Wi-Fi, proxy de maquina y de usuario, reglas `portproxy`, fichero `hosts`.
- Salidas crudas de `ipconfig`, `arp`, `route`, `netstat -anob`, `nbtstat`, `net use/session/share` y `netsh`.

### Procesos, servicios y drivers

- Procesos con linea de comandos, proceso padre, usuario y fecha de inicio.
- Servicios y drivers con ruta y cuenta, named pipes, listado de Prefetch.
- Salidas crudas de `tasklist` y `driverquery`.

### Usuarios y sesiones

- Usuarios y grupos locales, miembros de Administradores (por SID, valido en cualquier idioma).
- Perfiles de usuario, sesiones de logon con usuario asociado, `quser`, `qwinsta`, `klist`.

### Sistema

- SO, build, instalacion, arranque, zona horaria, hardware, Secure Boot, variables de entorno.
- Volumenes, discos, particiones, BitLocker, shadow copies, `systeminfo`, `w32tm`.

### Persistencia

- Claves `Run`/`RunOnce` (64 y 32 bits) de la maquina y de todos los usuarios con sesion.
- Winlogon, AppInit_DLLs, paquetes LSA, BootExecute, IFEO, SilentProcessExit, Active Setup, BHO, monitores de impresion.
- Tareas programadas con acciones, disparadores y ultima ejecucion; carpetas de inicio; `Win32_StartupCommand`.
- Persistencia WMI: filtros, todos los tipos de consumidores y bindings.

### Seguridad

- Firewall, estado y preferencias de Defender (incluidas exclusiones) y su historial de detecciones.
- Productos antivirus, hotfixes, software instalado (maquina 64/32 bits y usuarios).
- Configuracion de endurecimiento: UAC, WDigest, LSA, SMB, logging de PowerShell, politicas de Defender.
- Certificados raiz de la maquina, `auditpol`, `whoami /all`, `gpresult /r`, `net accounts`.

### Registro y dispositivos

- USBSTOR, USB, dispositivos portatiles, EMDMgmt y MountedDevices, con fecha de ultima escritura de cada clave.
- BAM con ultima ejecucion por usuario, redes conocidas con fechas de creacion y ultima conexion.
- Por usuario: UserAssist decodificado, RecentDocs en orden MRU, RunMRU, TypedPaths, WordWheelQuery, ComDlg32, MountPoints2, servidores RDP, Sysinternals y ShellBags.

### Actividad de usuario (todos los perfiles)

- Historiales PSReadLine de todos los hosts.
- Recent, Jump Lists, escritorio, `Downloads` con origen Mark-of-the-Web (`Zone.Identifier`), `%TEMP%` y `C:\Windows\Temp`.
- Papelera de reciclaje de todas las unidades: ruta original, fecha de borrado y tamano.

### Eventos (Completo y Pro)

- EVTX de Application, System, Security, PowerShell, RDP, TaskScheduler, Defender, WMI, BITS, SMB, Firewall y Sysmon (si existe).
- Ultimos eventos de cada log en CSV y eventos clave (logons, creacion de procesos y cuentas, servicios, borrado de logs, Defender...) con campos extraidos.

### Hives, ficheros de sistema y navegadores (Completo y Pro)

- `SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY`, `DEFAULT` y `NTUSER.DAT`/`UsrClass.dat` de cada usuario (con `.LOG1`/`.LOG2` cuando se copian como fichero).
- Prefetch, Amcache, SRUM, tareas XML, setupapi, repositorio WMI, logs del firewall, Recent/Jump Lists, ActivitiesCache.
- Chrome, Edge, Brave, Vivaldi, Chromium, Opera, Opera GX y Firefox de todos los usuarios, con `Local State` y los ficheros auxiliares `-wal`, `-shm` y `-journal`.

## Informes

Todos los informes se generan al final de la adquisicion en `Reports\` y contienen la misma informacion:

| Formato | Fichero | Contenido |
|---|---|---|
| `HTML` | `Informe_Forense.html` | Informe completo autocontenido con CSS integrado (sin dependencias externas): cabecera del caso, indicadores clave, indice, tablas por area con etiquetas de severidad y estado, y anexo con vista previa de cada conjunto de datos. |
| `PDF` | `Informe_Forense.pdf` | Version imprimible del informe HTML (A4 apaisado). Se genera con Microsoft Edge o Google Chrome en modo headless; si no hay navegador disponible, con un generador PDF interno en texto. |
| `JSON` | `Informe_Forense.json` | Datos del caso, resumen, indicadores, fases, estadisticas, registro de copias y **todos** los conjuntos de datos en un unico fichero. |
| `CSV` | `CSV\*.csv` | Tablas del informe: caso, resumen, indicadores, fases, estadisticas e indice de artefactos. |

Ademas, cada conjunto de datos se guarda por separado en `Artifacts\Json` y `Artifacts\Csv`, y las salidas crudas de las utilidades nativas en `Artifacts\Raw`.

El informe incluye:

- Datos del caso: investigador, motivo, perfil, zona horaria, inicio en local y UTC.
- Resumen ejecutivo por area e indicadores a revisar ordenados por severidad.
- Estado de cada fase con avisos y tiempos.
- Tablas resumen de cada area (conexiones, procesos, persistencia, USB, BAM, UserAssist, descargas, papelera, eventos clave, hives, navegadores, timeline).
- Indice de artefactos, estadisticas, huella de la adquisicion e informacion de integridad.

## Integridad y cadena de custodia

- `Logs\acquisition_log.csv`: cada fichero copiado con origen, destino, metodo (`Copy-Item`, `esentutl /vss`, `reg save`, `wevtutil epl`), estado y marcas de tiempo originales en UTC. Las copias conservan las fechas de creacion y modificacion del origen.
- `Reports\hash_manifest_sha256.csv`: se calcula al final, cuando los informes (HTML, PDF, JSON y CSV) y el log ya estan cerrados, por lo que cubre todos los ficheros del caso.
- `Reports\hash_manifest_sha256.csv.sha256`: SHA256 del manifiesto. Se muestra en pantalla al terminar; anotalo en la documentacion de custodia.

## Requisitos

- Windows 10/11 o Windows Server 2016 o superior.
- Windows PowerShell 5.1 o PowerShell 7 en Windows.
- Consola elevada para obtener hives, EVTX de Seguridad, Prefetch, sesiones SMB y ficheros bloqueados.
- Microsoft Edge o Google Chrome para el PDF con estilos (incluidos por defecto en Windows 10/11). Sin navegador se genera un PDF en texto.

## Notas operativas

- Es una adquisicion en vivo: no sustituye a una imagen forense ni a un volcado de memoria.
- Huella en el sistema: ejecucion de utilidades nativas, sombras de volumen temporales al copiar ficheros bloqueados, compilacion de un pequeno tipo .NET (`Add-Type`) para leer la fecha de ultima escritura de las claves del registro y ejecucion de Edge/Chrome en modo headless para el PDF (con un perfil temporal dentro de la carpeta del caso que se elimina al terminar). Todo queda reflejado en el informe.
- Los usuarios sin sesion iniciada se cubren mediante la copia de sus `NTUSER.DAT`/`UsrClass.dat`; el analisis directo del registro solo se hace sobre hives cargadas.
- La carpeta del caso contiene datos sensibles (hives SAM/SECURITY, cookies y credenciales cifradas de navegadores): el asistente ofrece restringir sus permisos a Administradores, SYSTEM y el operador (no aplica en FAT/exFAT).
- Los indicadores son automaticos y sirven para priorizar, no son conclusiones.

## Recomendaciones de uso forense

- Ejecutar desde una unidad externa y guardar el caso en ella, no en el disco investigado.
- Ejecutar desde una consola elevada y minimizar la interaccion con el equipo antes de la recogida.
- Si se necesita memoria RAM, capturarla antes de lanzar EviDumpWin.
- Conservar el SHA256 del manifiesto junto con la documentacion del caso (hora, operador, motivo y contexto).
