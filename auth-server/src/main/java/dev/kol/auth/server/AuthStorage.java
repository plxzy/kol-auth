package dev.kol.auth.server;

public enum AuthStorage {
    POSTGRES,
    IN_MEMORY;

    public static AuthStorage fromEnv(String value) {
        if (value == null) {
            return POSTGRES;
        }
        return switch (value.trim().toLowerCase()) {
            case "inmemory", "in_memory", "memory", "mem" -> IN_MEMORY;
            case "postgres", "pg", "jdbc", "db" -> POSTGRES;
            default -> POSTGRES;
        };
    }
}
