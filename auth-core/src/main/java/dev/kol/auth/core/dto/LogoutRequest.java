package dev.kol.auth.core.dto;

public record LogoutRequest(
        String refreshToken,
        String token
) {
}
