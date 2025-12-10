package dev.kol.auth.core.tokens;

import java.util.Objects;

public record TokenConfig(
        String issuer,
        String audience,
        long accessTtlSeconds,
        long refreshTtlSeconds,
        String secret
) {
    public TokenConfig {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(audience, "audience");
        Objects.requireNonNull(secret, "secret");
    }
}
