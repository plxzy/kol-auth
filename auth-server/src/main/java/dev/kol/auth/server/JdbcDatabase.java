package dev.kol.auth.server;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;

final class JdbcDatabase {
    private final String url;
    private final String user;
    private final String password;

    JdbcDatabase(String url, String user, String password) {
        this.url = Objects.requireNonNull(url, "url");
        this.user = Objects.requireNonNull(user, "user");
        this.password = Objects.requireNonNull(password, "password");
    }

    Connection connect() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }
}

