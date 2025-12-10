package dev.kol.auth.core.dto;

public record ErrorResponse(
        String error,
        String message
) {
}
