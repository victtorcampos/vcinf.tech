# Project Backup for AI Analysis
Generated on: 01/28/2026 09:16:44


## File: /.env.example
```example
DB_USER=admin
DB_PASS=@Ecs1504
REDIS_PASS=@Ecs1504
JWT_SECRET=secrectkeyforjwt12345
```

## File: /docker-compose.yml
```yml
services:
  # --- Infraestrutura ---
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: ${DB_USER:-admin}
      POSTGRES_PASSWORD: ${DB_PASS:-@Ecs1504}
      POSTGRES_DB: vcinf_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - vcinf-net

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASS:-@Ecs1504}
    ports:
      - "6379:6379"
    networks:
      - vcinf-net

  # --- Aplicação Backend ---
  backend:
    build: 
      context: ./BACKEND
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/vcinf_db
      DB_USER: ${DB_USER:-admin}
      DB_PASS: ${DB_PASS:-@Ecs1504}
      SPRING_DATA_REDIS_HOST: redis
      SPRING_DATA_REDIS_PORT: 6379
      REDIS_PASS: ${REDIS_PASS:-@Ecs1504}
    depends_on:
      - postgres
      - redis
    networks:
      - vcinf-net

  # --- Aplicação Frontend ---
  frontend:
    build:
      context: ./FRONTEND
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: ${API_URL:-http://localhost:8080} # Para o servidor Next.js
    depends_on:
      - backend
    networks:
      - vcinf-net

volumes:
  postgres_data:

networks:
  vcinf-net:
    driver: bridge
    
```

## File: /generate_AI_Backup.ps1
```ps1
# 1. NÍVEL: EXCLUSÃO TOTAL (O arquivo nem aparece na lista)
$excludeTotalDirs = @("FRONTEND/node_modules", "BACKEND/target", ".git", ".github", "venv", ".emergent", "dist", ".next")
$excludeTotalFiles = @("backup.md", "log.txt", "mvnw", "mvnw.cmd", ".gitignore")
$excludeTotalExtensions = @(".png", ".jpg", ".jpeg", ".exe", ".dll", ".pyc", ".ico", ".bin", ".zip")

# 2. NÍVEL: METADATA ONLY (O nome do arquivo aparece, mas o conteúdo é ignorado)
$excludeContentDirs = @("FRONTEND/src/components/ui", "BACKEND/.mvn")
$excludeContentExtensions = @(".json", ".svg", ".lock", ".md")

$currentPath = Get-Location
$backupFile = Join-Path -Path $currentPath -ChildPath "backup.md"

# Inicializa o arquivo
"# Project Backup for AI Analysis`nGenerated on: $(Get-Date)`n" | Out-File -FilePath $backupFile -Encoding utf8

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
```

## File: /run.ps1
```ps1
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
```

## File: /run.sh
```sh
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
#echo "Logs:     docker compose logs -f"
#echo "Parar:    docker compose down"
```

## File: /BACKEND/Dockerfile
```
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
```

## File: /BACKEND/pom.xml
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>tech.vcinftech.ecosystem</groupId>
    <artifactId>eco-system</artifactId>
    <version>0.0.1</version>
    <name>ecosystem</name>
    <description>ecosystem.vcinf.tech</description>
    <properties>
        <java.version>17</java.version>
        <org.mapstruct.version>1.5.5.Final</org.mapstruct.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.mapstruct</groupId>
            <artifactId>mapstruct</artifactId>
            <version>${org.mapstruct.version}</version>
        </dependency>
        <!-- JWT Dependencies -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.11.5</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <source>17</source>
                    <target>17</target>
                    <annotationProcessorPaths>
                        <path>
                            <groupId>org.mapstruct</groupId>
                            <artifactId>mapstruct-processor</artifactId>
                            <version>${org.mapstruct.version}</version>
                        </path>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                             <version>1.18.30</version>
                        </path>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok-mapstruct-binding</artifactId>
                            <version>0.2.0</version>
                        </path>
                    </annotationProcessorPaths>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

## File: /BACKEND/README.md
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /BACKEND/.mvn/wrapper/maven-wrapper.properties
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/EcoSystemApplication.java
```java
package tech.vcinftech.ecosystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class EcoSystemApplication {

    public static void main(String[] args) {
        SpringApplication.run(EcoSystemApplication.class, args);
    }

}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/config/ApplicationConfig.java
```java
package tech.vcinftech.ecosystem.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.vcinftech.ecosystem.repository.UserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByUsername(username)
                .map(user -> org.springframework.security.core.userdetails.User.builder()
                        .username(user.getUsername())
                        .password(user.getPassword())
                        .roles("USER") // Simples role por enquanto
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/config/DataInitializer.java
```java
package tech.vcinftech.ecosystem.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.vcinftech.ecosystem.domain.User;
import tech.vcinftech.ecosystem.repository.UserRepository;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {

    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByUsername("admin").isEmpty()) {
                log.info("Creating default admin user...");
                User admin = User.builder()
                        .username("admin")
                        .email("admin@vcinf.tech")
                        .password(passwordEncoder.encode("admin123"))
                        .fullName("System Administrator")
                        .active(true)
                        .build();
                userRepository.save(admin);
                log.info("Admin user created successfully.");
            } else {
                log.info("Admin user already exists.");
            }
        };
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/config/security/JwtAuthenticationFilter.java
```java
package tech.vcinftech.ecosystem.config.security;

import tech.vcinftech.ecosystem.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(TokenService tokenService, UserDetailsService userDetailsService) {
        this.tokenService = tokenService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        // Ajustado para o novo método extractUsername
        username = tokenService.extractUsername(jwt);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            
            // Ajustado para isTokenValid que valida também o usuário e expiração
            if (tokenService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/config/security/SecurityConfig.java
```java
package tech.vcinftech.ecosystem.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter, 
                          AuthenticationProvider authenticationProvider) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider)
            .authorizeHttpRequests(auth -> auth
                // Rotas Públicas
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/users/**").permitAll() // TEMPORÁRIO: Liberado para testes de banco
                // Swagger / OpenAPI (se adicionar no futuro)
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**").permitAll()
                // Todas as outras exigem token
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:3000");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/controller/AuthController.java
```java
package tech.vcinftech.ecosystem.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.vcinftech.ecosystem.dto.LoginRequest;
import tech.vcinftech.ecosystem.service.TokenService;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Autentica usando o AuthenticationManager configurado
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // Se a autenticação passar, recupera o UserDetails e gera o token
        final UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
        final String token = tokenService.generateToken(userDetails);

        return ResponseEntity.ok(Collections.singletonMap("token", token));
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/controller/DashboardController.java
```java
package tech.vcinftech.ecosystem.controller;

import tech.vcinftech.ecosystem.dto.DashboardSummary;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @GetMapping("/summary")
    @Cacheable("dashboard")
    public DashboardSummary getSummary() {
        // In a real app, this would fetch data from a service that queries the database.
        // Here, we simulate a delay and return mock data.
        try {
            Thread.sleep(1000); // Simulate latency
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return new DashboardSummary(150, 42);
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/controller/UserController.java
```java
package tech.vcinftech.ecosystem.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.vcinftech.ecosystem.domain.User;
import tech.vcinftech.ecosystem.service.UserService;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {
    
    private final UserService userService;
    
    @GetMapping
    public ResponseEntity<List<User>> findAll() {
        return ResponseEntity.ok(userService.findAll());
    }
    
    @GetMapping("/{id}")
    public ResponseEntity<User> findById(@PathVariable Long id) {
        return userService.findById(id)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }
    
    @PostMapping
    public ResponseEntity<User> create(@RequestBody User user) {
        User created = userService.create(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
    
    @PutMapping("/{id}")
    public ResponseEntity<User> update(@PathVariable Long id, @RequestBody User user) {
        User updated = userService.update(id, user);
        return ResponseEntity.ok(updated);
    }
    
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/domain/User.java
```java
package tech.vcinftech.ecosystem.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 100)
    private String username;
    
    @Column(nullable = false, unique = true, length = 150)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Column(length = 200)
    private String fullName;
    
    @Column(nullable = false)
    private Boolean active = true;
    
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/dto/DashboardSummary.java
```java
package tech.vcinftech.ecosystem.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummary implements Serializable {

    private static final long serialVersionUID = 1L; 
    
    private long totalUsers;
    private long activeSessions;
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/dto/ErrorResponse.java
```java
package tech.vcinftech.ecosystem.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ErrorResponse {
    private Instant timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/dto/LoginRequest.java
```java
package tech.vcinftech.ecosystem.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/exception/GlobalExceptionHandler.java
```java
package tech.vcinftech.ecosystem.exception;

import tech.vcinftech.ecosystem.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, HttpServletRequest request) {
        ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                ex.getMessage(),
                request.getRequestURI()
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/repository/UserRepository.java
```java
package tech.vcinftech.ecosystem.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tech.vcinftech.ecosystem.domain.User;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/service/TokenService.java
```java
package tech.vcinftech.ecosystem.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class TokenService {

    @Value("${jwt.secret:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}")
    private String secretKey;

    @Value("${jwt.expiration:86400000}") // 24 hours
    private long jwtExpiration;

    private final StringRedisTemplate redisTemplate;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) && !isTokenBlacklisted(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // --- REDIS LOGIC FOR BLACKLIST (LOGOUT) ---

    public void invalidateToken(String token) {
        Date expirationDate = extractExpiration(token);
        long ttl = expirationDate.getTime() - System.currentTimeMillis();
        
        if (ttl > 0) {
            redisTemplate.opsForValue().set("BL_" + token, "invalid", ttl, TimeUnit.MILLISECONDS);
        }
    }

    private boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("BL_" + token));
    }
}
```

## File: /BACKEND/src/main/java/tech/vcinftech/ecosystem/service/UserService.java
```java
package tech.vcinftech.ecosystem.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.vcinftech.ecosystem.domain.User;
import tech.vcinftech.ecosystem.repository.UserRepository;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    
    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    @Transactional(readOnly = true)
    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
    
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    @Transactional
    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new IllegalArgumentException("Username já existe");
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new IllegalArgumentException("Email já existe");
        }
        return userRepository.save(user);
    }
    
    @Transactional
    public User update(Long id, User user) {
        User existing = userRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("User não encontrado"));
        
        existing.setFullName(user.getFullName());
        existing.setEmail(user.getEmail());
        existing.setActive(user.getActive());
        
        return userRepository.save(existing);
    }
    
    @Transactional
    public void delete(Long id) {
        userRepository.deleteById(id);
    }
}
```

## File: /BACKEND/src/main/resources/application.yml
```yml
spring:
  application:
    name: ecosystem
  datasource:
    url: ${SPRING_DATASOURCE_URL:jdbc:postgresql://localhost:5432/vcinf_db}
    username: ${DB_USER:admin}
    password: ${DB_PASS:@Ecs1504}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 10
      minimum-idle: 5
      connection-timeout: 30000
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true
    properties:
      hibernate:
        format_sql: true
        dialect: org.hibernate.dialect.PostgreSQLDialect
        jdbc:
          time_zone: America/Cuiaba
  data:
    redis:
      host: ${SPRING_DATA_REDIS_HOST:localhost}
      port: ${SPRING_DATA_REDIS_PORT:6379}
      password: ${REDIS_PASS:@Ecs1504}
      timeout: 2000ms

server:
  port: 8080
  error:
    include-message: always
    include-binding-errors: always

logging:
  level:
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    tech.vcinftech.ecosystem: DEBUG
```

## File: /FRONTEND/Dockerfile
```
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["npm", "run", "dev"]
#
EXPOSE 3000

```

## File: /FRONTEND/eslint.config.mjs
```mjs
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
```

## File: /FRONTEND/next.config.ts
```ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
};

export default nextConfig;
```

## File: /FRONTEND/package.json
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/postcss.config.mjs
```mjs
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
```

## File: /FRONTEND/README.md
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/tailwind.config.ts
```ts
import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        primary: {
          DEFAULT: "var(--primary)",
          foreground: "var(--primary-foreground)",
        },
        secondary: "var(--secondary)",
        accent: {
          DEFAULT: "var(--accent)",
          foreground: "var(--accent-foreground)",
        },
        link: "var(--link)",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "gradient-conic":
          "conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))",
      },
    },
  },
  plugins: [],
};
export default config;
```

## File: /FRONTEND/tsconfig.json
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/public/file.svg
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/public/globe.svg
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/public/next.svg
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/public/vercel.svg
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/public/window.svg
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/proxy.ts
```ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Rotas que são públicas e não requerem autenticação
const publicRoutes = ['/login', '/cadastro', '/'];

export function proxy(request: NextRequest) {
  // 1. Tenta ler o cookie de autenticação (HttpOnly)
  const token = request.cookies.get('vcinf_token')?.value;
  
  // 2. Verifica qual rota o usuário está tentando acessar
  const { pathname } = request.nextUrl;
  const isPublicRoute = publicRoutes.some(route => pathname === route || pathname.startsWith('/login'));

  // CASO 1: Usuário NÃO logado tentando acessar rota protegida (Dashboard, Perfil, etc)
  if (!token && !isPublicRoute) {
    // Redireciona para login e anexa a URL original para redirecionar de volta depois
    const loginUrl = new URL('/login', request.url);
    loginUrl.searchParams.set('callbackUrl', pathname);
    return NextResponse.redirect(loginUrl);
  }

  // CASO 2: Usuário JÁ logado tentando acessar página de login/cadastro
  // (Melhoria de UX: joga direto pro dashboard)
  if (token && isPublicRoute && pathname !== '/') {
     return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  // CASO 3: Tudo certo, permite a requisição passar
  return NextResponse.next();
}

// Configuração do Matcher: Onde o middleware vai rodar?
// Excluímos: api routes (geralmente tem auth própria), arquivos estáticos (_next, imagens, favicon)
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
```

## File: /FRONTEND/src/app/globals.css
```css
@import "tailwindcss";

:root {
  --background: #f5f2f0;
  --foreground: #0f1518;
  --primary: #26444f;
  --primary-foreground: #f5f2f0;
  --secondary: #355a6c;
  --accent: #26444f;
  --accent-foreground: #f5f2f0;
  --link: #355a6c;
}

[data-theme="dark"] {
  --background: #0a0e11;
  --foreground: #f5f2f0;
  --primary: #4a8094;
  --primary-foreground: #f5f2f0;
  --secondary: #6b8e9e;
  --accent: #355a6c;
  --accent-foreground: #ffffff;
  --link: #8bcbe3;
}
 
body {
  background-color: var(--background);
  color: var(--foreground);
}
```

## File: /FRONTEND/src/app/layout.tsx
```tsx
import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ThemeProvider } from "@/components/ThemeProvider";
import { HydrationFix } from "@/components/HydrationFix";
import { Navbar } from "@/components/Navbar";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "VCINF TECH",
  description: "Soluções Completas em Hardware e Inteligência Fiscal",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" suppressHydrationWarning>
      <body>
        <HydrationFix />
        <ThemeProvider>
          <Navbar />
          <main className={inter.className}>{children}</main>
        </ThemeProvider>
      </body>
    </html>
  );
}

```

## File: /FRONTEND/src/app/page.tsx
```tsx
import { Hero } from '@/components/Hero';
import { Services } from '@/components/Services';
import { InfoBar } from '@/components/InfoBar';
import { Footer } from '@/components/Footer';

export default function Home() {
  return (
    <>
      <Hero />
      <Services />
      <InfoBar />
      <Footer />
    </>
  );
}

```

## File: /FRONTEND/src/app/api/auth/login/route.ts
```ts
import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { username, password } = body;

    // A URL deve ser a do serviço Docker interno se estiver rodando no server-side, 
    // mas aqui estamos rodando no contexto do Next.js que pode estar no host ou container.
    // Usamos variável de ambiente ou fallback para localhost:8080 (backend)
    const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

    const res = await fetch(`${API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (!res.ok) {
        // Se backend retornar erro, repassamos
        const errorData = await res.json().catch(() => ({}));
        return NextResponse.json(
            { message: errorData.message || 'Login falhou' }, 
            { status: res.status }
        );
    }

    const data = await res.json();
    const token = data.token;

    // Criamos a resposta
    const response = NextResponse.json({ success: true });

    // Definimos o cookie HttpOnly
    response.cookies.set({
      name: 'vcinf_token',
      value: token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      maxAge: 60 * 60 * 24, // 1 dia em segundos (ajuste conforme seu JWT expiration)
      sameSite: 'strict',
    });

    return response;

  } catch (error) {
    console.error('Erro no login proxy:', error);
    return NextResponse.json(
      { message: 'Erro interno no servidor de autenticação' }, 
      { status: 500 }
    );
  }
}
```

## File: /FRONTEND/src/app/login/page.tsx
```tsx
import LoginForm from '@/components/LoginForm';

export default function LoginPage() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <div className="w-full max-w-md p-8 space-y-8 bg-card rounded-lg shadow-lg">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-foreground">Área do Cliente</h1>
          <p className="text-muted-foreground">
            Acesse sua conta para gerenciar seus serviços.
          </p>
        </div>
        <LoginForm />
      </div>
    </div>
  );
}
```

## File: /FRONTEND/src/components/Footer.tsx
```tsx
'use client';

import Link from 'next/link';
import { LogoIcon } from './LogoIcon';
import { Phone, Mail, MapPin, Facebook, Instagram, Linkedin } from 'lucide-react';

const footerLinks = {
  services: [
    { label: 'Manutenção de Hardware', href: '#servicos' },
    { label: 'Infraestrutura', href: '#servicos' },
    { label: 'Dev Support', href: '#servicos' },
    { label: 'Desenvolvimento', href: '#servicos' },
  ],
  company: [
    { label: 'Sobre Nós', href: '#' },
    { label: 'Nosso Time', href: '#' },
    { label: 'Carreiras', href: '#' },
    { label: 'Blog', href: '#noticias' },
  ],
};

const socialLinks = [
  { icon: Facebook, href: '#', label: 'Facebook' },
  { icon: Instagram, href: '#', label: 'Instagram' },
  { icon: Linkedin, href: '#', label: 'LinkedIn' },
];

export function Footer() {
  return (
    <footer 
      id="contato"
      style={{ 
        backgroundColor: 'color-mix(in srgb, var(--foreground) 95%, var(--background))',
      }}
      data-testid="footer"
    >
      {/* Main Footer */}
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12">
          {/* Brand Column */}
          <div className="lg:col-span-1">
            <Link href="/" className="flex items-center gap-3 mb-6">
              <LogoIcon className="h-10 w-auto" />
              <span 
                className="text-xl font-bold"
                style={{ color: 'var(--background)' }}
              >
                VCINF TECH
              </span>
            </Link>
            <p 
              className="text-sm mb-6 leading-relaxed opacity-70"
              style={{ color: 'var(--background)' }}
            >
              Soluções completas em hardware e inteligência fiscal para empresas que buscam excelência tecnológica.
            </p>
            {/* Social Links */}
            <div className="flex gap-3">
              {socialLinks.map((social, index) => {
                const Icon = social.icon;
                return (
                  <a
                    key={index}
                    href={social.href}
                    aria-label={social.label}
                    className="w-10 h-10 rounded-lg flex items-center justify-center transition-all duration-300 hover:scale-110"
                    style={{ 
                      backgroundColor: 'color-mix(in srgb, var(--background) 15%, transparent)',
                      color: 'var(--background)'
                    }}
                  >
                    <Icon size={20} />
                  </a>
                );
              })}
            </div>
          </div>

          {/* Services Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Serviços
            </h3>
            <ul className="space-y-3">
              {footerLinks.services.map((link, index) => (
                <li key={index}>
                  <Link
                    href={link.href}
                    className="text-sm transition-colors duration-200 hover:opacity-100 opacity-70"
                    style={{ color: 'var(--background)' }}
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Company Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Empresa
            </h3>
            <ul className="space-y-3">
              {footerLinks.company.map((link, index) => (
                <li key={index}>
                  <Link
                    href={link.href}
                    className="text-sm transition-colors duration-200 hover:opacity-100 opacity-70"
                    style={{ color: 'var(--background)' }}
                  >
                    {link.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>

          {/* Contact Column */}
          <div>
            <h3 
              className="font-semibold mb-6"
              style={{ color: 'var(--background)' }}
            >
              Contato
            </h3>
            <ul className="space-y-4">
              <li>
                <a 
                  href="tel:+556635441504"
                  className="flex items-center gap-3 text-sm opacity-70 hover:opacity-100 transition-opacity"
                  style={{ color: 'var(--background)' }}
                >
                  <Phone size={18} />
                  (66) 3544-1504
                </a>
              </li>
              <li>
                <a 
                  href="mailto:contato@vcinf.tech"
                  className="flex items-center gap-3 text-sm opacity-70 hover:opacity-100 transition-opacity"
                  style={{ color: 'var(--background)' }}
                >
                  <Mail size={18} />
                  contato@vcinf.tech
                </a>
              </li>
              <li>
                <div 
                  className="flex items-start gap-3 text-sm opacity-70"
                  style={{ color: 'var(--background)' }}
                >
                  <MapPin size={18} className="flex-shrink-0 mt-0.5" />
                  <span>
                    Av. Natalino João Brescansin, Nº 375<br />
                    Centro Sul - Sorriso/MT
                  </span>
                </div>
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Bottom Bar */}
      <div 
        className="border-t"
        style={{ borderColor: 'color-mix(in srgb, var(--background) 15%, transparent)' }}
      >
        <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <p 
              className="text-sm opacity-60"
              style={{ color: 'var(--background)' }}
            >
              © 2026 VCINF TECH. Todos os direitos reservados.
            </p>
            <div className="flex gap-6">
              <Link 
                href="#" 
                className="text-sm opacity-60 hover:opacity-100 transition-opacity"
                style={{ color: 'var(--background)' }}
              >
                Política de Privacidade
              </Link>
              <Link 
                href="#" 
                className="text-sm opacity-60 hover:opacity-100 transition-opacity"
                style={{ color: 'var(--background)' }}
              >
                Termos de Uso
              </Link>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
```

## File: /FRONTEND/src/components/Hero.tsx
```tsx
'use client';

import Link from 'next/link';

export function Hero() {
  return (
    <section 
      className="relative min-h-[90vh] flex items-center justify-center overflow-hidden"
      style={{ backgroundColor: 'var(--background)' }}
      data-testid="hero-section"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 overflow-hidden">
        <div 
          className="absolute top-1/4 -left-20 w-96 h-96 rounded-full blur-3xl opacity-20"
          style={{ backgroundColor: 'var(--primary)' }}
        />
        <div 
          className="absolute bottom-1/4 -right-20 w-80 h-80 rounded-full blur-3xl opacity-15"
          style={{ backgroundColor: 'var(--secondary)' }}
        />
        <div 
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full blur-3xl opacity-10"
          style={{ backgroundColor: 'var(--primary)' }}
        />
        {/* Grid Pattern */}
        <div 
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `linear-gradient(var(--foreground) 1px, transparent 1px), linear-gradient(90deg, var(--foreground) 1px, transparent 1px)`,
            backgroundSize: '60px 60px'
          }}
        />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Badge */}
        <div 
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium mb-8"
          style={{ 
            backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
            color: 'var(--primary)'
          }}
        >
          <span className="relative flex h-2 w-2">
            <span 
              className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
              style={{ backgroundColor: 'var(--primary)' }}
            />
            <span 
              className="relative inline-flex rounded-full h-2 w-2"
              style={{ backgroundColor: 'var(--primary)' }}
            />
          </span>
          Sorriso/MT e Região
        </div>

        {/* Headline */}
        <h1 
          className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-6 max-w-4xl mx-auto leading-tight"
          style={{ color: 'var(--foreground)' }}
        >
          Soluções Completas em{' '}
          <span style={{ color: 'var(--primary)' }}>Hardware</span> e{' '}
          <span style={{ color: 'var(--primary)' }}>Inteligência Fiscal</span>
        </h1>

        {/* Subheadline */}
        <p 
          className="text-lg sm:text-xl max-w-2xl mx-auto mb-10 leading-relaxed"
          style={{ color: 'var(--secondary)' }}
        >
          Manutenção especializada, infraestrutura de redes e assessoria contábil 
          exclusiva para desenvolvedores de software.
        </p>

        {/* CTA Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
          <Link
            href="#contato"
            className="inline-flex items-center justify-center px-8 py-4 text-base font-semibold rounded-lg transition-all duration-300 hover:scale-105 hover:shadow-lg"
            style={{ 
              backgroundColor: 'var(--primary)', 
              color: 'var(--primary-foreground)',
              boxShadow: '0 4px 14px color-mix(in srgb, var(--primary) 40%, transparent)'
            }}
            data-testid="hero-cta-primary"
          >
            Falar com Especialista
            <svg className="w-5 h-5 ml-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
            </svg>
          </Link>
          
          <Link
            href="#servicos"
            className="inline-flex items-center justify-center px-8 py-4 text-base font-semibold rounded-lg transition-all duration-300 border-2"
            style={{ 
              borderColor: 'var(--secondary)',
              color: 'var(--secondary)',
              backgroundColor: 'transparent'
            }}
            data-testid="hero-cta-secondary"
          >
            Conhecer Serviços
          </Link>
        </div>

        {/* Stats */}
        <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
          {[
            { value: '10+', label: 'Anos de Experiência' },
            { value: '500+', label: 'Clientes Atendidos' },
            { value: '24h', label: 'Suporte Técnico' },
            { value: '100%', label: 'Satisfação' },
          ].map((stat, index) => (
            <div key={index} className="text-center">
              <div 
                className="text-3xl sm:text-4xl font-bold mb-1"
                style={{ color: 'var(--primary)' }}
              >
                {stat.value}
              </div>
              <div 
                className="text-sm"
                style={{ color: 'var(--secondary)' }}
              >
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Scroll Indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
        <svg 
          className="w-6 h-6" 
          fill="none" 
          stroke="currentColor" 
          viewBox="0 0 24 24"
          style={{ color: 'var(--secondary)' }}
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      </div>
    </section>
  );
}
```

## File: /FRONTEND/src/components/HydrationFix.tsx
```tsx
'use client';

import { useEffect } from 'react';

export function HydrationFix() {
  useEffect(() => {
    // Este código roda APENAS no cliente, depois da hidratação
    const theme = localStorage.getItem('theme') || 
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
  }, []);

  return null;
}
```

## File: /FRONTEND/src/components/InfoBar.tsx
```tsx
'use client';

import { MapPin, Clock, Phone } from 'lucide-react';

export function InfoBar() {
  return (
    <section 
      className="py-16"
      style={{ 
        backgroundColor: 'var(--primary)',
      }}
      data-testid="info-bar-section"
    >
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid md:grid-cols-3 gap-8 text-center md:text-left">
          {/* Location */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <MapPin size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Atendendo Sorriso/MT e região
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Av. Natalino João Brescansin, Nº 375, Centro Sul
              </p>
            </div>
          </div>

          {/* Hours */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <Clock size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Horário de Atendimento
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Segunda a Sexta: 8h às 18h
              </p>
            </div>
          </div>

          {/* Contact */}
          <div className="flex flex-col md:flex-row items-center md:items-start gap-4">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: 'color-mix(in srgb, var(--primary-foreground) 20%, transparent)' }}
            >
              <Phone size={24} style={{ color: 'var(--primary-foreground)' }} />
            </div>
            <div>
              <h3 
                className="font-semibold text-lg mb-1"
                style={{ color: 'var(--primary-foreground)' }}
              >
                Fale Conosco
              </h3>
              <p 
                className="text-sm opacity-80"
                style={{ color: 'var(--primary-foreground)' }}
              >
                (66) 3544-1504 • contato@vcinf.tech
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
```

## File: /FRONTEND/src/components/LoginForm.tsx
```tsx
"use client";

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { User, Lock, Loader2 } from 'lucide-react';

export default function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      // Chamamos nossa própria rota interna do Next.js (Proxy)
      // Ela vai cuidar de pegar o token e setar o cookie HttpOnly
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        // Não precisamos salvar nada no localStorage
        // O cookie vcinf_token já foi definido pelo servidor
        router.push('/dashboard');
        router.refresh(); // Força atualização para o middleware reconhecer o cookie
      } else {
        const errorData = await response.json();
        setError(errorData.message || 'Credenciais inválidas. Tente novamente.');
      }
    } catch (error) {
      setError('Não foi possível conectar ao servidor. Verifique sua conexão.');
    }

    setIsLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="relative">
        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          type="text"
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Usuário"
          required
          className="w-full pl-10 pr-4 py-2 border rounded-md bg-transparent focus:ring-primary focus:border-primary"
        />
      </div>
      <div className="relative">
        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Senha"
          required
          className="w-full pl-10 pr-4 py-2 border rounded-md bg-transparent focus:ring-primary focus:border-primary"
        />
      </div>

      {error && (
        <p className="text-sm text-red-500 text-center">{error}</p>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="w-full flex justify-center items-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-[var(--primary)] hover:bg-[var(--secondary)] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:opacity-50"
      >
        {isLoading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            <span>Entrando...</span>
          </>
        ) : (
          'Entrar'
        )}
      </button>
    </form>
  );
}
```

## File: /FRONTEND/src/components/LogoIcon.tsx
```tsx
import React from 'react';

interface LogoIconProps {
  className?: string;
}

export function LogoIcon({ className }: LogoIconProps) {
  return (
    <svg viewBox="0 0 200 220" xmlns="http://www.w3.org/2000/svg" className={className || "h-8 w-auto"}>
      {/* poligono */}
      <path fill="#26444f" fillRule="evenodd" d="M 40 20 L 160 20 L 160 125 L 120 160 L 40 94 Z M 75 60 L 120 60 L 120 100 Z"/>
      {/* hexágono */}
      <path fill="#f4f3ef" fillRule="evenodd" d="M 40 94 L 120 160 L 160 125 L 160 185 L 120 185 L 40 120 Z"/>
      {/* triângulo  */}
      <path fill="#355a6c" fillRule="evenodd" d="M 40 120 L 40 185 L 120 185 Z"/>
    </svg>
  );
}
```

## File: /FRONTEND/src/components/Navbar.tsx
```tsx
'use client';

import Link from 'next/link';
import { useState } from 'react';
import { ThemeToggle } from './ThemeToggle';
import { LogoIcon } from './LogoIcon';

export function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  const navLinks = [
    { href: '#home', label: 'Home' },
    { href: '#servicos', label: 'Serviços' },
    { href: '#loja', label: 'Loja Online' },
    { href: '#noticias', label: 'Notícias' },
    { href: '#contato', label: 'Contato' },
  ];

  return (
    <nav 
      className="fixed w-full z-20 top-0 start-0 border-b"
      style={{ 
        backgroundColor: 'var(--background)', 
        borderColor: 'color-mix(in srgb, var(--secondary) 30%, transparent)' 
      }}
      data-testid="main-navbar"
    >
      <div className="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">
        {/* Logo */}
        <Link 
          href="/" 
          className="flex items-center space-x-3"
          onClick={() => setIsMenuOpen(false)}
          data-testid="logo-link"
        >
          <LogoIcon className="h-8 w-auto" />
          <span 
            className="self-center text-xl font-semibold whitespace-nowrap"
            style={{ color: 'var(--primary)' }}
          >
            VCINF TECH
          </span>
        </Link>

        {/* CTA Button + Theme Toggle + Mobile Menu Button */}
        <div className="flex md:order-2 items-center gap-2">
          <ThemeToggle />
          
          <Link
            href="/login"
            className="hidden md:inline-flex items-center justify-center px-4 py-2 text-sm font-medium rounded-lg transition-colors focus:ring-4 focus:outline-none"
            style={{ 
              backgroundColor: 'var(--primary)', 
              color: 'var(--primary-foreground)',
            }}
            data-testid="cta-button"
            onMouseEnter={(e) => e.currentTarget.style.opacity = '0.9'}
            onMouseLeave={(e) => e.currentTarget.style.opacity = '1'}
          >
            Área do Cliente
          </Link>

          {/* Mobile menu button */}
          <button
            type="button"
            className="inline-flex items-center p-2 w-10 h-10 justify-center text-sm rounded-lg md:hidden focus:outline-none focus:ring-2 transition-colors"
            style={{ 
              color: 'var(--secondary)',
            }}
            onClick={() => setIsMenuOpen(!isMenuOpen)}
            aria-controls="navbar-sticky"
            aria-expanded={isMenuOpen}
            data-testid="mobile-menu-toggle"
          >
            <span className="sr-only">{isMenuOpen ? 'Fechar menu' : 'Abrir menu'}</span>
            {isMenuOpen ? (
              <svg className="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            ) : (
              <svg className="w-5 h-5" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" strokeLinecap="round" strokeWidth="2" d="M5 7h14M5 12h14M5 17h14"/>
              </svg>
            )}
          </button>
        </div>

        {/* Navigation Links */}
        <div 
          className={`items-center justify-between w-full md:flex md:w-auto md:order-1 ${isMenuOpen ? 'block' : 'hidden'}`}
          id="navbar-sticky"
        >
          <ul 
            className="flex flex-col p-4 md:p-0 mt-4 font-medium border rounded-lg md:space-x-8 md:flex-row md:mt-0 md:border-0"
            style={{ 
              borderColor: 'color-mix(in srgb, var(--secondary) 30%, transparent)',
              backgroundColor: isMenuOpen ? 'color-mix(in srgb, var(--secondary) 10%, var(--background))' : 'transparent'
            }}
          >
            {navLinks.map((link, index) => (
              <li key={link.label}>
                <Link
                  href={link.href}
                  className="block py-2 px-3 rounded md:p-0 transition-colors"
                  style={{ 
                    color: index === 0 ? 'var(--primary)' : 'var(--foreground)',
                  }}
                  onClick={() => setIsMenuOpen(false)}
                  data-testid={`nav-link-${index}`}
                  onMouseEnter={(e) => e.currentTarget.style.color = 'var(--primary)'}
                  onMouseLeave={(e) => e.currentTarget.style.color = index === 0 ? 'var(--primary)' : 'var(--foreground)'}
                >
                  {link.label}
                </Link>
              </li>
            ))}
            
            {/* Mobile CTA */}
            <li className="md:hidden mt-4">
              <Link
                href="/login"
                className="block w-full text-center px-4 py-2 text-sm font-medium rounded-lg transition-colors"
                style={{ 
                  backgroundColor: 'var(--primary)', 
                  color: 'var(--primary-foreground)',
                }}
                onClick={() => setIsMenuOpen(false)}
                data-testid="mobile-cta-button"
              >
                Área do Cliente
              </Link>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  );
}
```

## File: /FRONTEND/src/components/ProtectedRoute.jsx
```jsx
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ProtectedRoute = ({ children, allowedRoles = [] }) => {
  const { user, profile, loading } = useAuth();

  // Mostrar loading enquanto verifica autenticação
  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f1518] flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#00FFD1]"></div>
          <p className="mt-4 text-[rgba(255,255,255,0.85)] text-lg">Carregando...</p>
        </div>
      </div>
    );
  }

  // Redirecionar para login se não autenticado
  if (!user || !profile) {
    return <Navigate to="/login" replace />;
  }

  // Verificar se o role do usuário está permitido
  if (allowedRoles.length > 0 && !allowedRoles.includes(profile.role)) {
    // Redirecionar para o dashboard correto baseado no role
    const roleRedirects = {
      admin: '/admin/dashboard',
      accountant: '/accountant/dashboard',
      client_company: '/client/dashboard',
    };
    return <Navigate to={roleRedirects[profile.role] || '/login'} replace />;
  }

  return children;
};

export default ProtectedRoute;
```

## File: /FRONTEND/src/components/Services.tsx
```tsx
'use client';

import { Monitor, Network, FileCode, Code2 } from 'lucide-react';

const services = [
  {
    icon: Monitor,
    title: 'Manutenção de Hardware',
    description: 'Peças, equipamentos e manutenção especializada para manter sua infraestrutura funcionando perfeitamente.',
    features: ['Diagnóstico técnico', 'Troca de componentes', 'Upgrade de equipamentos']
  },
  {
    icon: Network,
    title: 'Infraestrutura',
    description: 'Redes, Servidores (Proxy, Firewall, BD) configurados com máxima segurança e performance.',
    features: ['Redes corporativas', 'Servidores dedicados', 'Firewall e segurança']
  },
  {
    icon: FileCode,
    title: 'Dev Support',
    description: 'Assessoria fiscal especializada para desenvolvedores e software houses.',
    features: ['Consultoria fiscal', 'Emissão de NF-e', 'Compliance tributário']
  },
  {
    icon: Code2,
    title: 'Desenvolvimento',
    description: 'Apps e softwares sob medida para automatizar e otimizar seu negócio.',
    features: ['Sistemas web', 'Aplicativos mobile', 'Integrações API']
  }
];

export function Services() {
  return (
    <section 
      id="servicos"
      className="py-24"
      style={{ backgroundColor: 'var(--background)' }}
      data-testid="services-section"
    >
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <span 
            className="inline-block px-4 py-1.5 rounded-full text-sm font-medium mb-4"
            style={{ 
              backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
              color: 'var(--primary)'
            }}
          >
            O que fazemos
          </span>
          <h2 
            className="text-3xl sm:text-4xl font-bold mb-4"
            style={{ color: 'var(--foreground)' }}
          >
            Nossas Especialidades
          </h2>
          <p 
            className="text-lg max-w-2xl mx-auto"
            style={{ color: 'var(--secondary)' }}
          >
            Soluções completas para empresas que precisam de tecnologia confiável e suporte especializado.
          </p>
        </div>

        {/* Services Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {services.map((service, index) => {
            const Icon = service.icon;
            return (
              <div
                key={index}
                className="group relative p-6 rounded-2xl border transition-all duration-300 hover:-translate-y-1"
                style={{ 
                  backgroundColor: 'var(--background)',
                  borderColor: 'color-mix(in srgb, var(--secondary) 20%, transparent)',
                  boxShadow: '0 4px 6px -1px color-mix(in srgb, var(--foreground) 5%, transparent)'
                }}
                data-testid={`service-card-${index}`}
              >
                {/* Icon */}
                <div 
                  className="w-14 h-14 rounded-xl flex items-center justify-center mb-5 transition-transform duration-300 group-hover:scale-110"
                  style={{ 
                    backgroundColor: 'color-mix(in srgb, var(--primary) 15%, transparent)',
                  }}
                >
                  <Icon 
                    size={28} 
                    style={{ color: 'var(--primary)' }}
                  />
                </div>

                {/* Content */}
                <h3 
                  className="text-xl font-semibold mb-3"
                  style={{ color: 'var(--foreground)' }}
                >
                  {service.title}
                </h3>
                <p 
                  className="text-sm mb-4 leading-relaxed"
                  style={{ color: 'var(--secondary)' }}
                >
                  {service.description}
                </p>

                {/* Features */}
                <ul className="space-y-2">
                  {service.features.map((feature, idx) => (
                    <li 
                      key={idx}
                      className="flex items-center text-sm"
                      style={{ color: 'var(--secondary)' }}
                    >
                      <svg 
                        className="w-4 h-4 mr-2 flex-shrink-0" 
                        fill="none" 
                        stroke="currentColor" 
                        viewBox="0 0 24 24"
                        style={{ color: 'var(--primary)' }}
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      {feature}
                    </li>
                  ))}
                </ul>

                {/* Hover Effect Border */}
                <div 
                  className="absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                  style={{ 
                    border: '2px solid var(--primary)',
                  }}
                />
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
```

## File: /FRONTEND/src/components/ThemeProvider.tsx
```tsx
'use client';

import React, { createContext, useState, useEffect, useContext } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>('light'); // O script inline define o valor inicial correto

  useEffect(() => {
    // A lógica inicial já foi tratada pelo script inline para evitar o flicker.
    // Este useEffect sincroniza o estado do React com o atributo `data-theme`
    // e lida com as mudanças no sistema operacional.
    const storedTheme = localStorage.getItem('theme') as Theme | null;
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const systemTheme = mediaQuery.matches ? 'dark' : 'light';

    setTheme(storedTheme || systemTheme);

    const handleSystemThemeChange = (e: MediaQueryListEvent) => {
      if (!localStorage.getItem('theme')) {
        const newSystemTheme = e.matches ? 'dark' : 'light';
        setTheme(newSystemTheme);
        document.documentElement.setAttribute('data-theme', newSystemTheme);
      }
    };

    mediaQuery.addEventListener('change', handleSystemThemeChange);

    return () => {
      mediaQuery.removeEventListener('change', handleSystemThemeChange);
    };
  }, []);

  const toggleTheme = () => {
    setTheme(prevTheme => {
      const newTheme = prevTheme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      return newTheme;
    });
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};
```

## File: /FRONTEND/src/components/ThemeToggle.css
```css
.theme-toggle {
  --icon-fill: var(--foreground);
  --icon-fill-hover: var(--primary);
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  color: var(--icon-fill);
  transition: color 0.3s ease;
}

.theme-toggle:hover {
  color: var(--icon-fill-hover);
}

.sun-and-moon {
  transform-origin: center center;
}

.sun-and-moon > .sun {
  transform-origin: center center;
  transition: transform 0.5s cubic-bezier(0.5, -0.5, 0.5, 1.5);
}

.sun-and-moon > .sun-beams {
  transform-origin: center center;
  transition: transform 0.5s cubic-bezier(0.5, -0.5, 0.5, 1.5), opacity 0.3s ease;
}

[data-theme="dark"] .sun-and-moon > .sun {
  transform: scale(1.75);
}

[data-theme="dark"] .sun-and-moon > .sun-beams {
  transform: rotateZ(-90deg);
  opacity: 0;
}

.sun-and-moon > .moon > circle {
  transform-origin: center center;
  transition: transform 0.5s cubic-bezier(0.5, -0.5, 0.5, 1.5);
}

[data-theme="dark"] .sun-and-moon > .moon > circle {
  transform: translateX(-7px);
}
```

## File: /FRONTEND/src/components/ThemeToggle.tsx
```tsx
'use client';

import React from 'react';
import { useTheme } from './ThemeProvider';
import './ThemeToggle.css';

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      className="theme-toggle"
      onClick={toggleTheme}
      aria-label={theme === 'light' ? 'Mudar para o modo escuro' : 'Mudar para o modo claro'}
    >
      <svg className="sun-and-moon" aria-hidden="true" width="24" height="24" viewBox="0 0 24 24">
        <mask className="moon" id="moon-mask">
          <rect x="0" y="0" width="100%" height="100%" fill="white" />
          <circle cx="24" cy="10" r="6" fill="black" />
        </mask>
        <circle className="sun" cx="12" cy="12" r="6" mask="url(#moon-mask)" fill="currentColor" />
        <g className="sun-beams" stroke="currentColor">
          <line x1="12" y1="1" x2="12" y2="3" />
          <line x1="12" y1="21" x2="12" y2="23" />
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
          <line x1="1" y1="12" x2="3" y2="12" />
          <line x1="21" y1="12" x2="23" y2="12" />
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
        </g>
      </svg>
    </button>
  );
}
```

## File: /FRONTEND/src/components/ui/accordion.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/alert-dialog.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/alert.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/aspect-ratio.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/avatar.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/badge.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/breadcrumb.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/button.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/calendar.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/card.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/carousel.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/checkbox.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/collapsible.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/command.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/context-menu.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/dialog.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/drawer.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/dropdown-menu.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/form.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/hover-card.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/input-otp.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/input.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/label.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/menubar.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/navigation-menu.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/pagination.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/popover.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/progress.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/radio-group.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/resizable.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/scroll-area.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/select.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/separator.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/sheet.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/skeleton.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/slider.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/sonner.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/switch.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/table.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/tabs.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/textarea.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/toast.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/toaster.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/toggle-group.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/toggle.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/components/ui/tooltip.jsx
// [Conteúdo omitido: listado apenas para contexto de estrutura]


## File: /FRONTEND/src/lib/utils.ts
```ts
import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```
