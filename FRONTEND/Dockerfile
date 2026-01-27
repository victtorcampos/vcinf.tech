#!/bin/bash
echo "=== Instalando e Iniciando VCINF TECH (Docker) ==="

# Verifica se Docker existe
if ! command -v docker &> /dev/null; then
    echo "Erro: Docker não instalado. Instale o Docker primeiro."
    exit 1
fi

# Cria arquivo .env se não existir
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Arquivo .env criado com padrões."
fi

# Sobe tudo (rebuilda se necessário)
docker compose up --build -d

echo "=== Tudo rodando! ==="
echo "Frontend: http://localhost:3000"
echo "Backend:  http://localhost:8080"
echo "Logs:     docker compose logs -f"
#echo "Parar:    docker compose down"