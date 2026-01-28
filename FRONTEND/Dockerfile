FROM node:20-alpine AS base

# Estágio 1: Instalação de dependências
FROM base AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Estágio 2: Build da aplicação
FROM base AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Estágio 3: Imagem final (só o necessário)
FROM base AS runner
WORKDIR /app
ENV NODE_ENV=development
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=deps /app/node_modules ./node_modules

EXPOSE 3000
CMD ["npm", "run", "dev"]
