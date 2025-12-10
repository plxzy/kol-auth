package dev.kol.auth.core.service;

import dev.kol.auth.core.model.User;
import dev.kol.auth.core.tokens.TokenPair;

public interface TokenService {
    RefreshResult issueTokens(User user);

    RefreshResult refreshTokens(String refreshToken);

    void revokeRefreshToken(String refreshToken);

    record RefreshResult(java.util.UUID userId, TokenPair tokens) {
    }
}
