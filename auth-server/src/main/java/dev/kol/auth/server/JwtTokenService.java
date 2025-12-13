package dev.kol.auth.server;

import dev.kol.auth.core.model.Session;
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
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory token service with JWT access tokens and opaque refresh tokens.
 * TODO: back sessions with a real datastore.
 */
public class JwtTokenService implements TokenService {
    private final TokenConfig config;
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, StoredSession> sessions = new ConcurrentHashMap<>();

    public JwtTokenService(TokenConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        this.key = Keys.hmacShaKeyFor(normalizeSecret(config.secret()));
    }

    @Override
    public RefreshResult issueTokens(User user, String deviceId) {
        Instant now = Instant.now();
        if (deviceId == null || deviceId.isBlank()) {
            throw new AuthException(400, "deviceId required");
        }

        // Revoke any existing sessions for this user (single active refresh token per account).
        sessions.replaceAll((token, existing) -> {
            Session session = existing.session();
            if (session.userId().equals(user.id()) && !session.revoked()) {
                return existing.withRevoked(now);
            }
            return existing;
        });

        String access = buildAccessToken(user.id(), user.username(), user.email(), now);
        String refresh = generateRefreshToken();
        Session session = new Session(
                UUID.randomUUID(),
                user.id(),
                user.username(),
                user.email(),
                refresh,
                now.plusSeconds(config.refreshTtlSeconds()),
                false,
                now,
                now,
                null
        );
        sessions.put(refresh, new StoredSession(session, deviceId));
        return new RefreshResult(user.id(), new TokenPair(access, refresh));
    }

    @Override
    public RefreshResult refreshTokens(String refreshToken, String deviceId) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(400, "Refresh token required");
        }
        if (deviceId == null || deviceId.isBlank()) {
            throw new AuthException(400, "deviceId required");
        }
        Instant now = Instant.now();
        StoredSession stored = sessions.get(refreshToken);
        if (stored == null || stored.session().revoked() || stored.session().isExpired(now)) {
            throw new AuthException(401, "Refresh token invalid or expired");
        }
        if (!Objects.equals(stored.deviceId(), deviceId)) {
            throw new AuthException(401, "Refresh token invalid for device");
        }

        sessions.remove(refreshToken);
        String newRefresh = generateRefreshToken();
        Session rotated = new Session(
                UUID.randomUUID(),
                stored.session().userId(),
                stored.session().username(),
                stored.session().email(),
                newRefresh,
                now.plusSeconds(config.refreshTtlSeconds()),
                false,
                now,
                now,
                refreshToken
        );
        sessions.put(newRefresh, new StoredSession(rotated, deviceId));

        String access = buildAccessToken(stored.session().userId(), stored.session().username(), stored.session().email(), now);
        return new RefreshResult(stored.session().userId(), new TokenPair(access, newRefresh));
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            return;
        }
        StoredSession existing = sessions.get(refreshToken);
        if (existing != null && !existing.session().revoked()) {
            sessions.put(refreshToken, existing.withRevoked(Instant.now()));
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

    private record StoredSession(Session session, String deviceId) {
        StoredSession withRevoked(Instant now) {
            Session s = session;
            return new StoredSession(new Session(
                    s.id(),
                    s.userId(),
                    s.username(),
                    s.email(),
                    s.refreshToken(),
                    s.expiresAt(),
                    true,
                    s.createdAt(),
                    now,
                    s.rotatedFrom()
            ), deviceId);
        }
    }
}
