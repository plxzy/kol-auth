package dev.kol.auth.core.service;

import dev.kol.auth.core.model.User;
import dev.kol.auth.core.tokens.TokenPair;

public interface TokenService {
    RefreshResult issueTokens(User user, String deviceId);

    RefreshResult refreshTokens(String refreshToken, String deviceId);

    void revokeRefreshToken(String refreshToken);

    record RefreshResult(java.util.UUID userId, TokenPair tokens) {
    }
}
