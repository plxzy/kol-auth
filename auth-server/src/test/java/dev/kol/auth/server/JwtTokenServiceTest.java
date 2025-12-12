package dev.kol.auth.server;

import dev.kol.auth.core.model.User;
import dev.kol.auth.core.service.AuthException;
import dev.kol.auth.core.service.TokenService.RefreshResult;
import dev.kol.auth.core.tokens.TokenConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenServiceTest {

    private static final String SECRET = "very-secret-key-that-is-at-least-32-bytes-long";
    private static final String ISSUER = "test-issuer";
    private static final String AUDIENCE = "test-audience";
    private static final long ACCESS_TTL = 3600;
    private static final long REFRESH_TTL = 7200;

    private JwtTokenService tokenService;
    private SecretKey key;

    @BeforeEach
    void setUp() {
        TokenConfig tokenConfig = new TokenConfig(ISSUER, AUDIENCE, ACCESS_TTL, REFRESH_TTL, SECRET);
        tokenService = new JwtTokenService(tokenConfig);
        key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldIssueTokensForUser() {
        User user = new User(UUID.randomUUID(), "testUser", "test@example.com", "hash", Instant.now(), Instant.now());

        RefreshResult result = tokenService.issueTokens(user);

        assertThat(result).isNotNull();
        assertThat(result.userId()).isEqualTo(user.id());
        assertThat(result.tokens()).isNotNull();
        assertThat(result.tokens().accessToken()).isNotBlank();
        assertThat(result.tokens().refreshToken()).isNotBlank();

        // Verify access token claims
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(result.tokens().accessToken())
                .getPayload();

        assertThat(claims.getSubject()).isEqualTo(user.id().toString());
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
        assertThat(claims.getAudience()).contains(AUDIENCE);
        assertThat(claims.get("username")).isEqualTo(user.username());
        assertThat(claims.get("email")).isEqualTo(user.email());
    }

    @Test
    void shouldRefreshTokens() {
        User user = new User(UUID.randomUUID(), "testUser", "test@example.com", "hash", Instant.now(), Instant.now());
        RefreshResult initialResult = tokenService.issueTokens(user);
        String refreshToken = initialResult.tokens().refreshToken();

        RefreshResult refreshResult = tokenService.refreshTokens(refreshToken);

        assertThat(refreshResult).isNotNull();
        assertThat(refreshResult.userId()).isEqualTo(user.id());
        assertThat(refreshResult.tokens().accessToken()).isNotBlank();
        assertThat(refreshResult.tokens().refreshToken()).isNotBlank();
        assertThat(refreshResult.tokens().refreshToken()).isNotEqualTo(refreshToken);
    }

    @Test
    void shouldThrowExceptionWhenRefreshingWithInvalidToken() {
        assertThatThrownBy(() -> tokenService.refreshTokens("invalid-token"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Refresh token invalid or expired"); // Depending on exact error message logic
    }

    @Test
    void shouldThrowExceptionWhenRefreshingWithRevokedToken() {
        User user = new User(UUID.randomUUID(), "testUser", "test@example.com", "hash", Instant.now(), Instant.now());
        RefreshResult initialResult = tokenService.issueTokens(user);
        String refreshToken = initialResult.tokens().refreshToken();

        tokenService.revokeRefreshToken(refreshToken);

        assertThatThrownBy(() -> tokenService.refreshTokens(refreshToken))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Refresh token invalid or expired");
    }
    
    @Test
    void shouldNotThrowWhenRevokingNonExistentToken() {
        tokenService.revokeRefreshToken("non-existent-token");
    }
}
