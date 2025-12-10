package dev.kol.auth.core.tokens;

/**
 * Access/refresh token bundle returned to clients.
 */
public record TokenPair(
        String accessToken,
        String refreshToken
) {
}
