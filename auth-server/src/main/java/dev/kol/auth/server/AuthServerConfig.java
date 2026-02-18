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
        HashingConfig hashingConfig,
        String dbUrl,
        String dbUser,
        String dbPassword,
        String matrixHomeserverUrl,
        String matrixRegistrationToken
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

        String dbUrl = env("AUTH_DB_URL", "jdbc:postgresql://localhost:5432/kol_auth");
        String dbUser = env("AUTH_DB_USER", "kol_auth");
        String dbPassword = env("AUTH_DB_PASSWORD", "kol_dev_password");

        String matrixHomeserverUrl = optionalEnv("MATRIX_HOMESERVER_URL");
        String matrixRegistrationToken = optionalEnv("MATRIX_REGISTRATION_TOKEN");

        TokenConfig tokenConfig = new TokenConfig(issuer, audience, accessTtl, refreshTtl, secret);
        HashingConfig hashingConfig = new HashingConfig(argonTime, argonMemory, argonParallelism);

        return new AuthServerConfig(port, tokenConfig, hashingConfig, dbUrl, dbUser, dbPassword, matrixHomeserverUrl, matrixRegistrationToken);
    }

    private static String env(String key, String defaultValue) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static String optionalEnv(String key) {
        String value = System.getenv(key);
        return value == null || value.isBlank() ? null : value;
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
