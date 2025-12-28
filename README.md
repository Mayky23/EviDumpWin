# EviDumpWin

Script de **auditoría automática para sistemas Windows** desarrollado en PowerShell.  
Genera un **informe en formato Markdown (.md)** con información detallada del sistema, ideal para revisiones técnicas, inventarios, diagnósticos o documentación.

---

## 📌 Características

- Detecta si el script se ejecuta con **permisos de administrador**
- Recolecta información del sistema y del usuario actual
- Muestra **barra de progreso** durante la ejecución
- Genera un **informe Markdown estructurado**, listo para visualizar en GitHub, VS Code o convertir a PDF/HTML
- Incluye un **resumen rápido opcional** al finalizar la ejecución

---

## 📂 Salida

Por defecto, el script genera el archivo:

```
Auditoria-Scripts(Resultado).md
```

en el directorio desde el que se ejecuta el script.

El archivo contiene secciones con encabezados, tablas y valores clave del sistema.

---

## ⚙️ Requisitos

- Windows PowerShell 5.1 o superior  
- Permisos de administrador (recomendado para información completa)
- Política de ejecución que permita scripts (`RemoteSigned` o similar)

Para habilitar ejecución de scripts (opcional):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🚀 Uso

### Ejecución básica

```powershell
.EviDumpWin.ps1
```

### Especificar ruta personalizada del informe

```powershell
.EviDumpWin.ps1 -ReportPath "C:\Reportes\AuditoriaSistema.md"
```

### Mostrar resumen rápido en consola

```powershell
.EviDumpWin.ps1 -VerboseReport
```

---

## 🧾 Parámetros

| Parámetro | Tipo | Descripción |
|---------|------|-------------|
| `ReportPath` | `string` | Ruta y nombre del archivo Markdown de salida |
| `VerboseReport` | `switch` | Muestra un resumen rápido al finalizar |

---

## 🛠️ ¿Qué hace el script?

- Inicializa variables globales y codificación UTF-8 con BOM
- Muestra un **banner de inicio** con información del equipo
- Ejecuta tareas de auditoría mostrando progreso
- Construye el informe mediante funciones reutilizables:
  - Encabezados
  - Tablas clave/valor
  - Tablas estructuradas
- Guarda el informe y muestra confirmación final

---

## 📄 Ejemplo de contenido del informe

- Información del equipo
- Usuario y fecha de ejecución
- Estado de permisos
- Resultados organizados en tablas Markdown

---

## 🔐 Notas

- Algunas comprobaciones pueden devolver información limitada si no se ejecuta como administrador.
- El informe está optimizado para Markdown estándar.

