package dev.kol.auth.core.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Server-side session/refresh token record.
 */
public record Session(
        UUID id,
        UUID userId,
        String username,
        String email,
        String refreshToken,
        Instant expiresAt,
        boolean revoked,
        Instant createdAt,
        Instant updatedAt,
        String rotatedFrom
) {
    public boolean isExpired(Instant now) {
        return expiresAt != null && expiresAt.isBefore(now);
    }
}
