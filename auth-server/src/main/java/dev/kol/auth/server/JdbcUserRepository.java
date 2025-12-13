package dev.kol.auth.server;

import dev.kol.auth.core.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;

public class JdbcUserRepository {
    private final JdbcConnectionFactory connectionFactory;
    private final String schema;

    public JdbcUserRepository(JdbcConnectionFactory connectionFactory, String schema) {
        this.connectionFactory = Objects.requireNonNull(connectionFactory, "connectionFactory");
        this.schema = Objects.requireNonNull(schema, "schema");
    }

    public User insert(UUID id, String username, String email, String passwordHash) throws SQLException {
        String sql = "INSERT INTO " + schema + ".users (id, username, email, password_hash, created_at, updated_at) " +
                "VALUES (?, ?, ?, ?, NOW(), NOW())";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, id);
            ps.setString(2, username);
            ps.setString(3, email);
            ps.setString(4, passwordHash);
            ps.executeUpdate();
        }
        return findById(id);
    }

    public User findById(UUID id) throws SQLException {
        String sql = "SELECT id, username, email, password_hash, created_at, updated_at FROM " + schema + ".users WHERE id = ?";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return mapUser(rs);
            }
        }
    }

    public User findByUsernameOrEmail(String usernameOrEmail) throws SQLException {
        String sql = "SELECT id, username, email, password_hash, created_at, updated_at " +
                "FROM " + schema + ".users " +
                "WHERE lower(username) = lower(?) OR lower(email) = lower(?) " +
                "LIMIT 1";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, usernameOrEmail);
            ps.setString(2, usernameOrEmail);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return mapUser(rs);
            }
        }
    }

    public boolean existsByUsernameOrEmailCaseInsensitive(String username, String email) throws SQLException {
        String sql = "SELECT 1 FROM " + schema + ".users WHERE lower(username) = lower(?) OR lower(email) = lower(?) LIMIT 1";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, email);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private static User mapUser(ResultSet rs) throws SQLException {
        UUID id = (UUID) rs.getObject("id");
        String username = rs.getString("username");
        String email = rs.getString("email");
        String passwordHash = rs.getString("password_hash");
        Instant createdAt = rs.getObject("created_at", OffsetDateTime.class).toInstant();
        Instant updatedAt = rs.getObject("updated_at", OffsetDateTime.class).toInstant();
        return new User(id, username, email, passwordHash, createdAt, updatedAt);
    }
}
