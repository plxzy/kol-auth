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

import java.sql.SQLException;
import java.util.Objects;
import java.util.UUID;

public class JdbcAuthService implements AuthService {
    private final JdbcUserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordHasher passwordHasher;

    public JdbcAuthService(JdbcUserRepository userRepository, TokenService tokenService, PasswordHasher passwordHasher) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository");
        this.tokenService = Objects.requireNonNull(tokenService, "tokenService");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher");
    }

    @Override
    public AuthResponse register(RegisterRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        validateUsername(request.username());
        validatePassword(request.password());
        if (request.email() == null || request.email().isBlank()) {
            throw new AuthException(400, "Email required");
        }

        try {
            if (userRepository.existsByUsernameOrEmailCaseInsensitive(request.username(), request.email())) {
                throw new AuthException(409, "User already exists");
            }

            String hash = passwordHasher.hash(request.password().toCharArray());
            UUID id = UUID.randomUUID();
            User user = userRepository.insert(id, request.username(), request.email(), hash);

            TokenService.RefreshResult issued = tokenService.issueTokens(user);
            return new AuthResponse(UserProfile.from(user), issued.tokens());
        } catch (AuthException e) {
            throw e;
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                throw new AuthException(409, "User already exists");
            }
            throw new AuthException(500, "Database error during register");
        }
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        if (request.username() == null || request.username().isBlank()) {
            throw new AuthException(400, "Username or email required");
        }
        validatePassword(request.password());

        try {
            User user = userRepository.findByUsernameOrEmail(request.username());
            if (user == null || !passwordHasher.verify(request.password().toCharArray(), user.passwordHash())) {
                throw new AuthException(401, "Invalid credentials");
            }
            TokenService.RefreshResult issued = tokenService.issueTokens(user);
            return new AuthResponse(UserProfile.from(user), issued.tokens());
        } catch (AuthException e) {
            throw e;
        } catch (SQLException e) {
            throw new AuthException(500, "Database error during login");
        }
    }

    @Override
    public AuthResponse refresh(RefreshRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        TokenService.RefreshResult refreshed = tokenService.refreshTokens(request.refreshToken());
        try {
            User user = userRepository.findById(refreshed.userId());
            if (user == null) {
                throw new AuthException(404, "User not found for refresh token");
            }
            return new AuthResponse(UserProfile.from(user), refreshed.tokens());
        } catch (AuthException e) {
            throw e;
        } catch (SQLException e) {
            throw new AuthException(500, "Database error during refresh");
        }
    }

    @Override
    public void logout(LogoutRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        tokenService.revokeRefreshToken(request.refreshToken());
    }

    @Override
    public WalletStatus walletStatus() {
        return new WalletStatus(false, "Wallet verification stub; implement challenge/verify flow.");
    }

    private void validateUsername(String username) {
        if (username == null || username.isBlank()) {
            throw new AuthException(400, "Username required");
        }
        if (username.length() < 3) {
            throw new AuthException(400, "Username must be at least 3 characters");
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new AuthException(400, "Password required");
        }
        if (password.length() < 8) {
            throw new AuthException(400, "Password must be at least 8 characters (12+ recommended)");
        }
    }

    private static boolean isUniqueViolation(SQLException e) {
        // Postgres unique_violation
        return "23505".equals(e.getSQLState());
    }
}
