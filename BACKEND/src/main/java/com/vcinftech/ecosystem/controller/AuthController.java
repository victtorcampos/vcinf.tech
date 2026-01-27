package com.vcinftech.ecosystem.controller;

import com.vcinftech.ecosystem.dto.LoginRequest;
import com.vcinftech.ecosystem.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        // Mock authentication: in a real app, you'd authenticate against a database
        if ("user".equals(loginRequest.getUsername()) && "password".equals(loginRequest.getPassword())) {
            String token = tokenService.generateToken(loginRequest.getUsername());
            return ResponseEntity.ok().body(java.util.Collections.singletonMap("token", token));
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }
}
