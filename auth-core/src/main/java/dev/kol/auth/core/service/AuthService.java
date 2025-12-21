package dev.kol.auth.core.service;

import dev.kol.auth.core.dto.AuthResponse;
import dev.kol.auth.core.dto.LogoutRequest;
import dev.kol.auth.core.dto.RefreshRequest;
import dev.kol.auth.core.dto.RegisterRequest;
import dev.kol.auth.core.dto.WalletStatus;
import dev.kol.auth.core.dto.LoginRequest;
import dev.kol.auth.core.dto.SessionValidateRequest;

public interface AuthService {
    AuthResponse register(RegisterRequest request);

    AuthResponse login(LoginRequest request);

    AuthResponse refresh(RefreshRequest request);

    void logout(LogoutRequest request);

    void validateSession(SessionValidateRequest request);

    WalletStatus walletStatus();
}
