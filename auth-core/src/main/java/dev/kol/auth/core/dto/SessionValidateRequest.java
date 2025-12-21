package dev.kol.auth.core.dto;

public record SessionValidateRequest(
        String refreshToken,
        String deviceId
) {
}

