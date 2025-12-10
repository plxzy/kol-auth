package dev.kol.auth.core.dto;

public record WalletStatus(
        boolean enabled,
        String message
) {
}
