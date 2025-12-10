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

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal in-memory auth flow. TODO: replace with proper DB persistence.
 */
public class InMemoryAuthService implements AuthService {
    private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();
    private final Map<String, User> usersByEmail = new ConcurrentHashMap<>();
    private final Map<UUID, User> usersById = new ConcurrentHashMap<>();
    private final TokenService tokenService;
    private final PasswordHasher passwordHasher;

    public InMemoryAuthService(TokenService tokenService, PasswordHasher passwordHasher) {
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

        String usernameKey = request.username().toLowerCase();
        if (usersByUsername.containsKey(usernameKey)) {
            throw new AuthException(409, "User already exists");
        }
        if (usersByEmail.containsKey(request.email().toLowerCase())) {
            throw new AuthException(409, "Email already registered");
        }

        Instant now = Instant.now();
        String hash = passwordHasher.hash(request.password().toCharArray());
        User user = new User(UUID.randomUUID(), request.username(), request.email(), hash, now, now);

        // TODO: persist to DB and reuse real user IDs.
        usersByUsername.put(usernameKey, user);
        usersByEmail.put(request.email().toLowerCase(), user);
        usersById.put(user.id(), user);

        TokenService.RefreshResult issued = tokenService.issueTokens(user);
        return new AuthResponse(UserProfile.from(user), issued.tokens());
    }

    @Override
    public AuthResponse login(LoginRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        if (request.username() == null || request.username().isBlank()) {
            throw new AuthException(400, "Username or email required");
        }
        validatePassword(request.password());

        User user = findUser(request.username());
        if (user == null || !passwordHasher.verify(request.password().toCharArray(), user.passwordHash())) {
            throw new AuthException(401, "Invalid credentials");
        }
        TokenService.RefreshResult issued = tokenService.issueTokens(user);
        return new AuthResponse(UserProfile.from(user), issued.tokens());
    }

    @Override
    public AuthResponse refresh(RefreshRequest request) {
        if (request == null) throw new AuthException(400, "Request body required");
        TokenService.RefreshResult refreshed = tokenService.refreshTokens(request.refreshToken());
        User user = requireUser(refreshed.userId());
        return new AuthResponse(UserProfile.from(user), refreshed.tokens());
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

    private User findUser(String usernameOrEmail) {
        String key = usernameOrEmail.toLowerCase();
        User fromUsername = usersByUsername.get(key);
        if (fromUsername != null) return fromUsername;
        return usersByEmail.get(key);
    }

    private User requireUser(UUID id) {
        User user = usersById.get(id);
        if (user == null) {
            throw new AuthException(404, "User not found for refresh token");
        }
        return user;
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
}
