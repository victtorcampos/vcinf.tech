package com.vcinftech.ecosystem.service;

import org.springframework.stereotype.Service;

@Service
public class TokenService {

    public String generateToken(String username) {
        // Mock token generation
        return "mock-jwt-token-for-" + username;
    }

    public boolean validateToken(String token) {
        // Mock token validation
        return token != null && token.startsWith("mock-jwt-token-for-");
    }

    public String getUsernameFromToken(String token) {
        // Mock username extraction
        if (validateToken(token)) {
            return token.substring("mock-jwt-token-for-".length());
        }
        return null;
    }
}
