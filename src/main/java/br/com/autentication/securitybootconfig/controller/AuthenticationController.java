package br.com.autentication.securitybootconfig.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    // Public route accessible to everyone
    @GetMapping("/public")
    public String publicRoute() {
        return "<h1>Public route, feel free to look around! 🔓</h1>";
    }

    // Private route, requires authorized users
    @GetMapping("/private")
    public String privateRoute(@AuthenticationPrincipal OidcUser principal) {
        return String.format(
                "<h1>Private route, only authorized personnel! 🔐</h1>" +
                        "<h3>Welcome, %s</h3>",
                principal.getFullName());
    }

    // Route showing OAuth2 data with user info and JWT token
    @GetMapping("/cookie")
    public String cookie(@AuthenticationPrincipal OidcUser principal) {
        return String.format(
                "<h1>Oauth2 🔐</h1>" +
                        "<h3>Principal: %s</h3>" +
                        "<h3>Email attribute: %s</h3>" +
                        "<h3>Authorities: %s</h3>" +
                        "<h3>JWT: %s</h3>",
                principal.getFullName(),
                principal.getAttribute("email"),
                principal.getAuthorities(),
                principal.getIdToken().getTokenValue());
    }

    // JWT route, extracting claims and showing the JWT token
    @GetMapping("/jwt")
    public Map<String, Object> jwt(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> jwtDetails = new HashMap<>();
        // Populate the map with JWT claims
        jwtDetails.put("Principal Claims", jwt.getClaims());
        jwtDetails.put("Email attribute", jwt.getClaim("email"));
        jwtDetails.put("JWT Token", jwt.getTokenValue());
        return jwtDetails; // Returning as JSON map
    }

    // Method to handle JWT expiration and token validation (optional)
    @SuppressWarnings("null")
    public boolean isTokenValid(Jwt jwt) {
        // Check if the token has expired
        return !jwt.getExpiresAt().isBefore(Instant.now());
    }

    // Method to extract custom claims from the JWT token
    public String getCustomClaim(Jwt jwt, String claim) {
        return jwt.getClaim(claim);
    }

    @Override
    public String toString() {
        return "AuthenticationController []";
    }
}
