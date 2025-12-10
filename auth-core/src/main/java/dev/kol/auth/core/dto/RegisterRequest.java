package dev.kol.auth.core.dto;

public record RegisterRequest(
        String username,
        String email,
        String password
) {
}
