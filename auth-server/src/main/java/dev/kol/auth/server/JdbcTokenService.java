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
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

final class JdbcTokenService implements TokenService {
    private final JdbcDatabase db;
    private final TokenConfig config;
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    JdbcTokenService(JdbcDatabase db, TokenConfig config) {
        this.db = Objects.requireNonNull(db, "db");
        this.config = Objects.requireNonNull(config, "config");
        this.key = Keys.hmacShaKeyFor(normalizeSecret(config.secret()));
    }

    @Override
    public RefreshResult issueTokens(User user, String deviceId) {
        if (user == null) throw new AuthException(400, "User required");
        if (deviceId == null || deviceId.isBlank()) throw new AuthException(400, "deviceId required");

        Instant now = Instant.now();
        String access = buildAccessToken(user.id(), user.username(), user.email(), now);
        String refresh = generateRefreshToken();

        try (Connection conn = db.connect()) {
            conn.setAutoCommit(false);
            try {
                revokeAllActiveForUser(conn, user.id());
                insertRefreshToken(conn, user.id(), refresh, now.plusSeconds(config.refreshTtlSeconds()), deviceId, null, now);
                conn.commit();
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new AuthException(500, "Database error issuing tokens");
        }

        return new RefreshResult(user.id(), new TokenPair(access, refresh));
    }

    @Override
    public RefreshResult refreshTokens(String refreshToken, String deviceId) {
        if (refreshToken == null || refreshToken.isBlank()) throw new AuthException(400, "Refresh token required");
        if (deviceId == null || deviceId.isBlank()) throw new AuthException(400, "deviceId required");

        Instant now = Instant.now();

        try (Connection conn = db.connect()) {
            conn.setAutoCommit(false);
            try {
                SessionRow row = selectSessionForUpdate(conn, refreshToken);
                if (row == null || row.revoked || row.expiresAt.isBefore(now)) {
                    throw new AuthException(401, "Refresh token invalid or expired");
                }

                String storedDevice = row.deviceInfo;
                if (storedDevice == null) {
                    // Backfill and enforce single-device going forward.
                    storedDevice = deviceId;
                    backfillDeviceInfo(conn, refreshToken, deviceId, now);
                    revokeOtherDevices(conn, row.userId, deviceId);
                } else if (!Objects.equals(storedDevice, deviceId)) {
                    throw new AuthException(401, "Refresh token invalid for device");
                }

                revokeOtherTokens(conn, row.userId, refreshToken);
                revokeRefreshTokenTx(conn, refreshToken, now);

                String newRefresh = generateRefreshToken();
                insertRefreshToken(conn, row.userId, newRefresh, now.plusSeconds(config.refreshTtlSeconds()), storedDevice, refreshToken, now);

                conn.commit();

                String access = buildAccessToken(row.userId, row.username, row.email, now);
                return new RefreshResult(row.userId, new TokenPair(access, newRefresh));
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (AuthException e) {
            throw e;
        } catch (SQLException e) {
            throw new AuthException(500, "Database error refreshing token");
        }
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) return;
        Instant now = Instant.now();
        try (Connection conn = db.connect()) {
            revokeRefreshTokenTx(conn, refreshToken, now);
        } catch (SQLException e) {
            // Best-effort. Access tokens are JWTs; refresh token revocation failing should not crash the server.
        }
    }

    private void revokeOtherDevices(Connection conn, UUID userId, String deviceId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE auth.refresh_tokens
                SET revoked = TRUE, last_used_at = NOW()
                WHERE user_id = ? AND revoked = FALSE AND device_info IS DISTINCT FROM ?
                """)) {
            ps.setObject(1, userId);
            ps.setString(2, deviceId);
            ps.executeUpdate();
        }
    }

    private void revokeAllActiveForUser(Connection conn, UUID userId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE auth.refresh_tokens
                SET revoked = TRUE, last_used_at = NOW()
                WHERE user_id = ? AND revoked = FALSE
                """)) {
            ps.setObject(1, userId);
            ps.executeUpdate();
        }
    }

    private void revokeOtherTokens(Connection conn, UUID userId, String keepToken) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE auth.refresh_tokens
                SET revoked = TRUE, last_used_at = NOW()
                WHERE user_id = ? AND revoked = FALSE AND token <> ?
                """)) {
            ps.setObject(1, userId);
            ps.setString(2, keepToken);
            ps.executeUpdate();
        }
    }

    private void backfillDeviceInfo(Connection conn, String refreshToken, String deviceId, Instant now) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE auth.refresh_tokens
                SET device_info = ?, last_used_at = ?
                WHERE token = ?
                """)) {
            ps.setString(1, deviceId);
            ps.setObject(2, OffsetDateTime.ofInstant(now, java.time.ZoneOffset.UTC));
            ps.setString(3, refreshToken);
            ps.executeUpdate();
        }
    }

    private void revokeRefreshTokenTx(Connection conn, String refreshToken, Instant now) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                UPDATE auth.refresh_tokens
                SET revoked = TRUE, last_used_at = ?
                WHERE token = ? AND revoked = FALSE
                """)) {
            ps.setObject(1, OffsetDateTime.ofInstant(now, java.time.ZoneOffset.UTC));
            ps.setString(2, refreshToken);
            ps.executeUpdate();
        }
    }

    private void insertRefreshToken(Connection conn, UUID userId, String token, Instant expiresAt, String deviceInfo, String rotatedFrom, Instant lastUsedAt) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                INSERT INTO auth.refresh_tokens (id, user_id, token, expires_at, revoked, rotated_from, device_info, last_used_at)
                VALUES (?, ?, ?, ?, FALSE, ?, ?, ?)
                """)) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, userId);
            ps.setString(3, token);
            ps.setObject(4, OffsetDateTime.ofInstant(expiresAt, java.time.ZoneOffset.UTC));
            ps.setString(5, rotatedFrom);
            ps.setString(6, deviceInfo);
            ps.setObject(7, OffsetDateTime.ofInstant(lastUsedAt, java.time.ZoneOffset.UTC));
            ps.executeUpdate();
        }
    }

    private SessionRow selectSessionForUpdate(Connection conn, String refreshToken) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("""
                SELECT rt.user_id, rt.expires_at, rt.revoked, rt.device_info, u.username, u.email
                FROM auth.refresh_tokens rt
                JOIN auth.users u ON u.id = rt.user_id
                WHERE rt.token = ?
                FOR UPDATE
                """)) {
            ps.setString(1, refreshToken);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                UUID userId = rs.getObject("user_id", UUID.class);
                OffsetDateTime expires = rs.getObject("expires_at", OffsetDateTime.class);
                boolean revoked = rs.getBoolean("revoked");
                String deviceInfo = rs.getString("device_info");
                String username = rs.getString("username");
                String email = rs.getString("email");
                return new SessionRow(userId, expires.toInstant(), revoked, deviceInfo, username, email);
            }
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

    private byte[] normalizeSecret(String secret) {
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

    private record SessionRow(UUID userId, Instant expiresAt, boolean revoked, String deviceInfo, String username, String email) {
    }
}
