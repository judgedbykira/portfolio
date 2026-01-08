<#
.SYNOPSIS
    Crea la estructura writeups\<MachineName>\ para cada máquina retirada de machines.json
.DESCRIPTION
    Ejecutar desde la raíz del sitio. Crea:
    - writeups\<MachineName>\index.html  (plantilla)
    - writeups\<MachineName>\index.md    (vacío)
    - writeups\<MachineName>\img\        (vacía)
#>

$ErrorActionPreference = "Stop"

# --------------------------------------------------
# 1. Leer machines.json
# --------------------------------------------------
$jsonFile = Resolve-Path "machines.json"
$machines = Get-Content $jsonFile -Raw | ConvertFrom-Json

# --------------------------------------------------
# 2. Plantilla universal writeup/index.html
# --------------------------------------------------
$htmlTemplate = @'
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title id="page-title">Writeup</title>
  <link rel="icon" type="image/png" href="../../assets/favicon-32x32.png">
  <link rel="stylesheet" href="../../css/main.css">
  <link rel="stylesheet" href="../../css/writeup-hacker.css">
</head>

<body>
  <main class="writeup-main">
    <article class="writeup-content">
      <a href="/machines.html" class="back-button">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
          <path d="M19 12H5M12 19l-7-7 7-7"/>
        </svg>
        Volver a máquinas
      </a>

      <div class="writeup-head">
        <!-- IMAGEN de la máquina -->
        <img id="machine-icon" class="machine-banner" src="" alt="Icono máquina">
        <h1 id="machine-name">Cargando...</h1>
        <div class="writeup-meta">
          <span class="tag difficulty">Medium</span>
          <span class="tag status">Retirada</span>
        </div>
      </div>

      <div id="markdown-content" class="markdown-body">
        <p style="text-align:center;color:#ff4f81;padding:2rem;">Cargando contenido...</p>
      </div>
    </article>
  </main>

  <script src="../../js/marked.min.js"></script>
  <script src="../../js/writeup-renderer.js"></script>
</body>
</html>
'@

# --------------------------------------------------
# 3. Crear carpetas
# --------------------------------------------------
foreach ($m in $machines) {
    if ($m.status -ne "Retired") { continue }

    # Sanitizar nombre de carpeta
    $folderName = $m.name -replace '[<>:"/\\|?*]', ''
    $basePath   = Join-Path "writeups" $folderName
    $imgPath    = Join-Path $basePath "img"

    # Crear directorios
    New-Item -ItemType Directory -Path $imgPath -Force | Out-Null

    # index.html
    $htmlPath = Join-Path $basePath "index.html"
    if (-not (Test-Path $htmlPath)) {
        $htmlTemplate | Out-File -FilePath $htmlPath -Encoding utf8
    }

    # index.md vacío
    $mdPath = Join-Path $basePath "index.md"
    if (-not (Test-Path $mdPath)) {
        "# Writeup: $($m.name)`n`n> Añade tu contenido aquí…" |
            Out-File -FilePath $mdPath -Encoding utf8
    }
}

Write-Host "✅ Estructura de writeups creada para máquinas retiradas." -ForegroundColor Green