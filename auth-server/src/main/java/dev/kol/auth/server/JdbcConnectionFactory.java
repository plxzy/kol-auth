package dev.kol.auth.server;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;

public class JdbcConnectionFactory {
    private final DbConfig config;

    public JdbcConnectionFactory(DbConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    public Connection open() throws SQLException {
        return DriverManager.getConnection(config.url(), config.user(), config.password());
    }
}
