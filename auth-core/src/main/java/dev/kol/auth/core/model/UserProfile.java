package dev.kol.auth.core.model;

import java.util.UUID;

/**
 * Public view of a user returned to clients.
 */
public record UserProfile(
        UUID id,
        String username,
        String email
) {
    public static UserProfile from(User user) {
        return new UserProfile(user.id(), user.username(), user.email());
    }
}
