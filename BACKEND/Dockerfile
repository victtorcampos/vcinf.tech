# Estágio de Build
FROM maven:3.9-eclipse-temurin-17-alpine AS build
WORKDIR /app

# Otimização de Cache: Copia apenas o pom.xml primeiro
COPY pom.xml .
# Baixa dependências em modo batch (-B) para logs mais limpos, mas falha se der erro
RUN mvn dependency:go-offline -B

# Copia o código fonte
COPY src ./src

# Compila o projeto.
# Se este passo falhar, o docker build vai parar aqui e mostrar o erro.
RUN mvn clean package -DskipTests -B

# Estágio Final (Leve)
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copia o artefato com nome específico baseado no pom.xml (artifactId-version)
# Isso evita erros de "no such file" com wildcards se o build falhar silenciosamente antes
COPY --from=build /app/target/eco-system-0.0.1.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
EXPOSE 8080