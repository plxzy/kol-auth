package dev.kol.auth.server;

import dev.kol.auth.core.service.HashingConfig;
import dev.kol.auth.core.tokens.TokenConfig;

/**
 * Simple env-driven config for the auth server.
 * Defaults mirror kol-platform/config/auth.defaults.yml.
 */
public record AuthServerConfig(
        int port,
        TokenConfig tokenConfig,
        HashingConfig hashingConfig
) {
    public static AuthServerConfig fromEnv() {
        int port = intEnv("AUTH_SERVER_PORT", 8080);
        String issuer = env("AUTH_JWT_ISSUER", "https://auth.local.dev");
        String audience = env("AUTH_JWT_AUDIENCE", "kol-clients");
        String secret = env("AUTH_JWT_SECRET", "CHANGE_ME_SUPER_SECRET");
        long accessTtl = longEnv("AUTH_ACCESS_TTL_SECONDS", 900);
        long refreshTtl = longEnv("AUTH_REFRESH_TTL_SECONDS", 1_209_600);

        int argonTime = intEnv("ARGON2_TIME", 3);
        int argonMemory = intEnv("ARGON2_MEMORY_KIB", 65_536);
        int argonParallelism = intEnv("ARGON2_PARALLELISM", 1);

        TokenConfig tokenConfig = new TokenConfig(issuer, audience, accessTtl, refreshTtl, secret);
        HashingConfig hashingConfig = new HashingConfig(argonTime, argonMemory, argonParallelism);

        return new AuthServerConfig(port, tokenConfig, hashingConfig);
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int intEnv(String key, int defaultValue) {
        try {
            return Integer.parseInt(env(key, String.valueOf(defaultValue)));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static long longEnv(String key, long defaultValue) {
        try {
            return Long.parseLong(env(key, String.valueOf(defaultValue)));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}
