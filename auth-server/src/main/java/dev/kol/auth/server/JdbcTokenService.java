package dev.kol.auth.server;

import dev.kol.auth.core.model.User;
import dev.kol.auth.core.service.AuthException;
import dev.kol.auth.core.service.TokenService;
import dev.kol.auth.core.tokens.TokenConfig;
import dev.kol.auth.core.tokens.TokenPair;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

public class JdbcTokenService implements TokenService {
    private final JdbcConnectionFactory connectionFactory;
    private final TokenConfig config;
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();
    private final String schema;

    public JdbcTokenService(JdbcConnectionFactory connectionFactory, TokenConfig config, String schema) {
        this.connectionFactory = Objects.requireNonNull(connectionFactory, "connectionFactory");
        this.config = Objects.requireNonNull(config, "config");
        this.schema = Objects.requireNonNull(schema, "schema");
        this.key = Keys.hmacShaKeyFor(normalizeSecret(config.secret()));
    }

    @Override
    public RefreshResult issueTokens(User user) {
        Instant now = Instant.now();
        String access = buildAccessToken(user.id(), user.username(), user.email(), now);
        String refresh = generateRefreshToken();
        Instant expiresAt = now.plusSeconds(config.refreshTtlSeconds());

        String sql = "INSERT INTO " + schema + ".refresh_tokens " +
                "(id, user_id, token, issued_at, expires_at, revoked, rotated_from) " +
                "VALUES (?, ?, ?, NOW(), ?, FALSE, NULL)";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, user.id());
            ps.setString(3, refresh);
            ps.setObject(4, OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new AuthException(500, "Failed to persist refresh token");
        }

        return new RefreshResult(user.id(), new TokenPair(access, refresh));
    }

    @Override
    public RefreshResult refreshTokens(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(400, "Refresh token required");
        }

        Instant now = Instant.now();
        try (Connection c = connectionFactory.open()) {
            c.setAutoCommit(false);
            try {
                SessionRow session = selectForUpdate(c, refreshToken);
                if (session == null || session.revoked || session.expiresAt.isBefore(now)) {
                    c.rollback();
                    throw new AuthException(401, "Refresh token invalid or expired");
                }

                String newRefresh = generateRefreshToken();
                Instant newExpiresAt = now.plusSeconds(config.refreshTtlSeconds());

                revokeById(c, session.id);
                insertRotated(c, session.userId, newRefresh, newExpiresAt, refreshToken);
                c.commit();

                String access = buildAccessToken(session.userId, session.username, session.email, now);
                return new RefreshResult(session.userId, new TokenPair(access, newRefresh));
            } catch (AuthException e) {
                throw e;
            } catch (Exception e) {
                c.rollback();
                throw e;
            } finally {
                c.setAutoCommit(true);
            }
        } catch (AuthException e) {
            throw e;
        } catch (SQLException e) {
            throw new AuthException(500, "Failed to refresh session");
        }
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }
        String sql = "UPDATE " + schema + ".refresh_tokens SET revoked = TRUE, last_used_at = NOW() WHERE token = ?";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, refreshToken);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new AuthException(500, "Failed to revoke refresh token");
        }
    }

    private SessionRow selectForUpdate(Connection c, String token) throws SQLException {
        String sql = "SELECT rt.id, rt.user_id, u.username, u.email, rt.expires_at, rt.revoked " +
                "FROM " + schema + ".refresh_tokens rt " +
                "JOIN " + schema + ".users u ON u.id = rt.user_id " +
                "WHERE rt.token = ? " +
                "FOR UPDATE";
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, token);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                UUID id = (UUID) rs.getObject("id");
                UUID userId = (UUID) rs.getObject("user_id");
                String username = rs.getString("username");
                String email = rs.getString("email");
                Instant expiresAt = rs.getObject("expires_at", OffsetDateTime.class).toInstant();
                boolean revoked = rs.getBoolean("revoked");
                return new SessionRow(id, userId, username, email, expiresAt, revoked);
            }
        }
    }

    private void revokeById(Connection c, UUID id) throws SQLException {
        String sql = "UPDATE " + schema + ".refresh_tokens SET revoked = TRUE, last_used_at = NOW() WHERE id = ?";
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, id);
            ps.executeUpdate();
        }
    }

    private void insertRotated(Connection c, UUID userId, String token, Instant expiresAt, String rotatedFrom) throws SQLException {
        String sql = "INSERT INTO " + schema + ".refresh_tokens " +
                "(id, user_id, token, issued_at, expires_at, revoked, rotated_from) " +
                "VALUES (?, ?, ?, NOW(), ?, FALSE, ?)";
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, userId);
            ps.setString(3, token);
            ps.setObject(4, OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
            ps.setString(5, rotatedFrom);
            ps.executeUpdate();
        }
    }

    private String buildAccessToken(UUID userId, String username, String email, Instant issuedAt) {
        Instant expiry = issuedAt.plusSeconds(config.accessTtlSeconds());
        return Jwts.builder()
                .subject(userId.toString())
                .issuer(config.issuer())
                .audience().add(config.audience()).and()
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiry))
                .claim("username", username)
                .claim("email", email)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    private String generateRefreshToken() {
        byte[] bytes = new byte[48];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] normalizeSecret(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length >= 32) {
            return bytes;
        }
        byte[] padded = new byte[32];
        for (int i = 0; i < padded.length; i++) {
            padded[i] = bytes[i % bytes.length];
        }
        return padded;
    }

    private record SessionRow(
            UUID id,
            UUID userId,
            String username,
            String email,
            Instant expiresAt,
            boolean revoked
    ) {
    }
}
