# 1. NÍVEL: EXCLUSÃO TOTAL (O arquivo nem aparece na lista)
$excludeTotalDirs = @("FRONTEND/node_modules", "BACKEND/target", ".git/", "venv", ".emergent", "dist", ".next")
$excludeTotalFiles = @("backup.md", "log.txt", "mvnw", "mvnw.cmd", ".gitignore")
$excludeTotalExtensions = @(".png", ".jpg", ".jpeg", ".exe", ".dll", ".pyc", ".ico", ".bin", ".zip")
 
# 2. NÍVEL: METADATA ONLY (O nome do arquivo aparece, mas o conteúdo é ignorado)
$excludeContentDirs = @("FRONTEND/src/components/ui", "BACKEND/.mvn")
$excludeContentExtensions = @(".json", ".svg", ".lock", ".md")

$currentPath = Get-Location
$backupFile = Join-Path -Path $currentPath -ChildPath "backup.md"

# Inicializa o arquivo
"# Project Backup for Analysis`nGenerated on: $(Get-Date)`n" | Out-File -FilePath $backupFile -Encoding utf8

$items = Get-ChildItem -Path $currentPath -Recurse -File -ErrorAction SilentlyContinue
 
foreach ($file in $items) {
    $relativePath = $file.FullName.Replace($currentPath.Path, "").TrimStart("\").Replace("\", "/")
    
    # --- Lógica de Nível 1: Exclusão Total ---
    $skipTotal = $false
    foreach ($dir in $excludeTotalDirs) {
        if ($relativePath.StartsWith($dir)) { $skipTotal = $true; break }
    }
    if ($skipTotal -or ($excludeTotalFiles -contains $file.Name) -or ($excludeTotalExtensions -contains $file.Extension)) {
        continue
    }

    # --- Lógica de Nível 2: Metadata Only (Omitir Conteúdo) ---
    $omitContent = $false
    foreach ($dir in $excludeContentDirs) {
        if ($relativePath.StartsWith($dir)) { $omitContent = $true; break }
    }
    if ($excludeContentExtensions -contains $file.Extension) { $omitContent = $true }

    # Escrita no Markdown
    "`n## File: /$relativePath" | Out-File -FilePath $backupFile -Append -Encoding utf8
    
    if ($omitContent) {
        "// [Conteúdo omitido: listado apenas para contexto de estrutura]`n" | Out-File -FilePath $backupFile -Append -Encoding utf8
    } else {
        "``````$($file.Extension.Trim('.'))" | Out-File -FilePath $backupFile -Append -Encoding utf8
        try {
            Get-Content $file.FullName | Out-File -FilePath $backupFile -Append -Encoding utf8
        }
        catch {
            "// [Erro ao ler conteúdo do arquivo]" | Out-File -FilePath $backupFile -Append -Encoding utf8
        }
        "``````" | Out-File -FilePath $backupFile -Append -Encoding utf8
    }
}

Write-Host "Backup (3 Níveis) concluído: $backupFile" -ForegroundColor Cyan