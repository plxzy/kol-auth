package dev.kol.auth.core.dto;

public record LoginRequest(
        String username,
        String password
) {
}
