package dev.kol.auth.server;

import dev.kol.auth.core.dto.AuthResponse;
import dev.kol.auth.core.dto.LoginRequest;
import dev.kol.auth.core.dto.LogoutRequest;
import dev.kol.auth.core.dto.RefreshRequest;
import dev.kol.auth.core.dto.RegisterRequest;
import dev.kol.auth.core.dto.WalletStatus;
import dev.kol.auth.core.model.User;
import dev.kol.auth.core.model.UserProfile;
import dev.kol.auth.core.service.AuthException;
import dev.kol.auth.core.service.AuthService;
import dev.kol.auth.core.service.PasswordHasher;
import dev.kol.auth.core.service.TokenService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;

final class JdbcAuthService implements AuthService {
    private final JdbcDatabase db;
    private final TokenService tokenService;
    private final PasswordHasher passwordHasher;

    JdbcAuthService(JdbcDatabase db, TokenService tokenService, PasswordHasher passwordHasher) {
        this.db = Objects.requireNonNull(db, "db");
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher");
    }

    @Override
    public AuthResponse register(RegisterRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        validateUsername(request.username());
        validatePassword(request.password());
        if (request.email() == null || request.email().isBlank()) throw new AuthException(400, "Email required");
        if (request.deviceId() == null || request.deviceId().isBlank()) throw new AuthException(400, "deviceId required");

        Instant now = Instant.now();
        UUID id = UUID.randomUUID();
        String hash = passwordHasher.hash(request.password().toCharArray());

        try (Connection conn = db.connect()) {
            if (userExists(conn, "username", request.username())) throw new AuthException(409, "User already exists");
            if (userExists(conn, "email", request.email())) throw new AuthException(409, "Email already registered");

            try (PreparedStatement ps = conn.prepareStatement("""
                    INSERT INTO auth.users (id, username, email, password_hash, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """)) {
                ps.setObject(1, id);
                ps.setString(2, request.username());
                ps.setString(3, request.email());
                ps.setString(4, hash);
                ps.setObject(5, OffsetDateTime.ofInstant(now, java.time.ZoneOffset.UTC));
                ps.setObject(6, OffsetDateTime.ofInstant(now, java.time.ZoneOffset.UTC));
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            throw new AuthException(500, "Database error registering user");
        }

        User user = new User(id, request.username(), request.email(), hash, now, now);
        TokenService.RefreshResult issued = tokenService.issueTokens(user, request.deviceId());
        return new AuthResponse(UserProfile.from(user), issued.tokens());
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        if (request.username() == null || request.username().isBlank()) throw new AuthException(400, "Username or email required");
        validatePassword(request.password());
        if (request.deviceId() == null || request.deviceId().isBlank()) throw new AuthException(400, "deviceId required");

        User user = findUser(request.username());
        if (user == null || !passwordHasher.verify(request.password().toCharArray(), user.passwordHash())) {
            throw new AuthException(401, "Invalid credentials");
        }
        TokenService.RefreshResult issued = tokenService.issueTokens(user, request.deviceId());
        return new AuthResponse(UserProfile.from(user), issued.tokens());
    }

    @Override
    public AuthResponse refresh(RefreshRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        TokenService.RefreshResult refreshed = tokenService.refreshTokens(request.refreshToken(), request.deviceId());
        User user = requireUser(refreshed.userId());
        return new AuthResponse(UserProfile.from(user), refreshed.tokens());
    }

    @Override
    public void logout(LogoutRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        String refreshToken = request.refreshToken() != null ? request.refreshToken() : request.token();
        tokenService.revokeRefreshToken(refreshToken);
    }

    @Override
    public WalletStatus walletStatus() {
        return new WalletStatus(false, "Wallet verification stub; implement challenge/verify flow.");
    }

    private boolean userExists(Connection conn, String column, String value) throws SQLException {
        String sql = "SELECT 1 FROM auth.users WHERE lower(" + column + ") = lower(?) LIMIT 1";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, value);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    private User findUser(String usernameOrEmail) {
        String key = usernameOrEmail.toLowerCase();
        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement("""
                     SELECT id, username, email, password_hash, created_at, updated_at
                     FROM auth.users
                     WHERE lower(username) = ? OR lower(email) = ?
                     LIMIT 1
                     """)) {
            ps.setString(1, key);
            ps.setString(2, key);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return mapUser(rs);
            }
        } catch (SQLException e) {
            throw new AuthException(500, "Database error");
        }
    }

    private User requireUser(UUID id) {
        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement("""
                     SELECT id, username, email, password_hash, created_at, updated_at
                     FROM auth.users
                     WHERE id = ?
                     """)) {
            ps.setObject(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new AuthException(404, "User not found for refresh token");
                return mapUser(rs);
            }
        } catch (SQLException e) {
            throw new AuthException(500, "Database error");
        }
    }

    private User mapUser(ResultSet rs) throws SQLException {
        UUID id = rs.getObject("id", UUID.class);
        String username = rs.getString("username");
        String email = rs.getString("email");
        String hash = rs.getString("password_hash");
        OffsetDateTime created = rs.getObject("created_at", OffsetDateTime.class);
        OffsetDateTime updated = rs.getObject("updated_at", OffsetDateTime.class);
        return new User(id, username, email, hash, created.toInstant(), updated.toInstant());
    }

    private void validateUsername(String username) {
        if (username == null || username.isBlank()) throw new AuthException(400, "Username required");
        if (username.length() < 3) throw new AuthException(400, "Username must be at least 3 characters");
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) throw new AuthException(400, "Password required");
        if (password.length() < 8) throw new AuthException(400, "Password must be at least 8 characters (12+ recommended)");
    }
}

