# Estágio de Build
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app

# Copia arquivos do wrapper Maven
COPY .mvn/ .mvn
COPY mvnw pom.xml ./

# Garante que o mvnw seja executável e tenha quebras de linha Unix
RUN sed -i 's/\r$//' mvnw
RUN chmod +x mvnw

# Baixa dependências
RUN ./mvnw dependency:go-offline -B

# Copia código fonte e compila
COPY src ./src
RUN ./mvnw clean package -DskipTests -B

# Estágio Final
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
EXPOSE 8080