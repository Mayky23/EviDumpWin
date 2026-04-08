# EviDumpWin

`EviDumpWin.ps1` es un recolector forense de Windows orientado a auditorias y respuesta inicial en vivo. Funciona con una interfaz guiada en terminal: pide la ruta del caso, el nombre y el perfil de adquisicion, crea una estructura de salida completa y deja informe, artefactos crudos, log y manifiesto de hashes.

## Que hace

- Crea una carpeta de caso elegida por el usuario.
- Genera un informe Markdown ejecutivo y tecnico.
- Exporta artefactos en `JSON`, `CSV` y `TXT` cuando aplica.
- Guarda salidas crudas de utilidades del sistema.
- Intenta copiar evidencias relevantes del host.
- Calcula un manifiesto `SHA256` de lo recolectado.
- Muestra progreso por fase y subfase durante la adquisicion.
- Registra tiempos por modulo, tiempo total y conteo de artefactos generados.
- Sigue trabajando aunque una fuente falle por permisos, bloqueo o ausencia del componente.

## Flujo de uso

Ejecuta el script:

```powershell
.\EviDumpWin.ps1
```

El asistente en terminal solicita:

1. Ruta base donde guardar el caso.
2. Nombre del caso.
3. Perfil de adquisicion.

Perfiles disponibles:

- `Rapido`: foco en evidencia volatil, estado actual, red, procesos, persistencia y actividad de usuario.
- `Completo`: recomendado para auditoria forense general.
- `Pro`: intenta extraer todo lo posible, incluidos EVTX, hives de usuario, timeline y artefactos avanzados adicionales.


## Estructura de salida

Cada ejecucion crea una carpeta de caso con esta estructura:

```text
<ruta-del-caso>\
  Reports\
    Informe_Forense.md
    hash_manifest_sha256.csv
  Logs\
    EviDumpWin.log
  Artifacts\
    Json\
    Csv\
    Txt\
    Raw\
    Registry\
    Events\
    Browser\
    Timeline\
```

## Artefactos que intenta recolectar

### Sistema

- Sistema operativo, build, BIOS, CPU, RAM y zona horaria.
- Volumenes, discos y estado BitLocker.

### Identidad y sesiones

- Usuarios locales y grupos.
- Miembros de `Administrators`.
- Perfiles de usuario.
- Sesiones de logon.

### Red

- Configuracion IP.
- Adaptadores de red.
- Conexiones TCP y endpoints UDP.
- Cache DNS.
- Shares SMB y sesiones SMB.
- Configuracion RDP.
- Perfiles Wi-Fi.
- Salidas crudas de `ipconfig`, `arp`, `route`, `netstat` y `netsh`.

### Ejecucion y persistencia

- Procesos activos.
- Servicios.
- Drivers.
- Tareas programadas.
- Claves `Run` y `RunOnce`.
- Inventario de Prefetch y copia del directorio cuando es posible.
- Salidas crudas de `tasklist`, `schtasks` y `wmic startup`.

### Seguridad

- Perfiles de firewall.
- Estado de Microsoft Defender si el modulo existe.
- Productos antivirus registrados en `SecurityCenter2`.
- Hotfixes.
- Software instalado.
- Salidas crudas de `auditpol`, `whoami /all`, `gpresult /r` y `net accounts`.

### Registro, dispositivos y WMI

- `USBSTOR`, `USB`, `MountedDevices`, `BAM`, `UserAssist`, `RecentDocs`, `ShellBags`.
- Persistencia WMI con `__EventFilter`, `CommandLineEventConsumer` y bindings.
- Copia de `setupapi.dev.log`, `Amcache.hve` y `SRUDB.dat` cuando es posible.

### Actividad de usuario

- Historiales `PSReadLine` por perfil.
- `Recent Items` y Jump Lists.
- Listado de `Downloads` y `%TEMP%`.
- Copia de `Recent` cuando es posible.

### Avanzado

En perfiles de escaneo avanzado intenta ademas:

- Exportar EVTX de logs relevantes.
- Copiar `NTUSER.DAT` y `UsrClass.dat` por perfil.
- Exportar hives `HKLM\\SAM`, `HKLM\\SYSTEM`, `HKLM\\SOFTWARE` y `HKLM\\SECURITY` si se ejecuta elevado.
- Copiar artefactos de `Chrome`, `Edge`, `Brave`, `Opera` y `Firefox` desde rutas objetivo, reduciendo el coste del escaneo.
- Crear un `timeline_seed.csv` inicial con Prefetch, Recent Items y papelera.

## Contenido del informe final

El informe incluye:

- Resumen ejecutivo por areas.
- Estado de ejecucion por modulo.
- Tiempo por fase y tiempo total.
- Estadisticas de artefactos generados.
- Estructura de salida del caso.

## Requisitos

- Windows PowerShell 5.1 o PowerShell 7 en Windows.
- Recomendado ejecutar la consola como administrador para maximizar cobertura.
- Politica de ejecucion que permita scripts.

Ejemplo para el usuario actual:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Notas operativas

- Es una adquisicion live: no sustituye a una imagen forense offline.
- Algunos archivos pueden estar bloqueados por el sistema o por aplicaciones abiertas.
- Sin privilegios elevados ciertos artefactos quedaran incompletos o no se exportaran.
- El manifiesto de hashes ayuda a verificar integridad de lo recolectado dentro de la carpeta de caso.
- El log `Logs\EviDumpWin.log` deja trazabilidad de errores y fuentes no disponibles.

## Recomendaciones de uso forense

- Ejecutar desde una consola elevada cuando el escenario lo permita.
- Guardar el caso en una ruta distinta al perfil del usuario auditado o en un volumen externo.
- Minimizar la interaccion con el equipo antes de lanzar la recogida.
- Documentar hora, operador, motivo de la adquisicion y contexto del sistema.

