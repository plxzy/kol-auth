package dev.kol.auth.core.dto;

import dev.kol.auth.core.model.UserProfile;
import dev.kol.auth.core.tokens.TokenPair;

public record AuthResponse(
        UserProfile user,
        TokenPair tokens
) {
}
