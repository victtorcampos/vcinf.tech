# Estágio de Build
FROM maven:3.9-eclipse-temurin-17-alpine AS build
WORKDIR /app

# 1. Copia dependências e baixa (Cache Layer)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# 2. Copia código fonte
COPY src ./src

# 3. Compila o projeto (Gera a pasta /target)
RUN mvn clean package -DskipTests -B

# Estágio Final
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# 4. Copia o JAR gerado. O wildcard *.jar é mais seguro se a versão mudar.
COPY --from=build /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
EXPOSE 8080