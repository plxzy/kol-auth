package dev.kol.auth.core.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal user record with hashed password. Do not expose passwordHash to clients.
 */
public record User(
        UUID id,
        String username,
        String email,
        String passwordHash,
        Instant createdAt,
        Instant updatedAt
) {
}
