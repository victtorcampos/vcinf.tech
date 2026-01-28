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
