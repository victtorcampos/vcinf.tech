Write-Host "=== Instalando e Iniciando VCINF TECH (Windows/Docker) ===" -ForegroundColor Cyan

# 1. Verifica se Docker está rodando
$dockerCheck = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $dockerCheck) {
    Write-Host "Erro: Docker não encontrado. Instale o Docker Desktop." -ForegroundColor Red
    exit 1
}

# 2. Cria arquivo .env se não existir
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" -Destination ".env"
    Write-Host "Arquivo .env criado com configurações padrão." -ForegroundColor Yellow
}

# 3. Sobe o ambiente (Build + Up em background)
Write-Host "Iniciando containers... (Isso pode demorar na primeira vez)" -ForegroundColor Cyan
docker compose up --build -d

if ($LASTEXITCODE -ne 0) {
    Write-Host "Falha ao iniciar o Docker Compose." -ForegroundColor Red
    exit 1
}

# 4. Feedback
Write-Host "`n=== Tudo rodando! ===" -ForegroundColor Green
Write-Host "Frontend: http://localhost:3000"
Write-Host "Backend:  http://localhost:8080"
Write-Host "Logs:     docker compose logs -f" -ForegroundColor Gray
