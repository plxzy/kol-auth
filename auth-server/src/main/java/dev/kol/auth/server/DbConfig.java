package dev.kol.auth.server;

public record DbConfig(
        String url,
        String user,
        String password,
        String schema
) {
}
