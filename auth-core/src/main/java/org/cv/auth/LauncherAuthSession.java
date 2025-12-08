package org.cv.auth;

import java.util.Objects;
import java.util.UUID;

public final class LauncherAuthSession {
    private static final String USER_TYPE = "legacy";

    private final String username;
    private final String token;
    private final UUID uuid;

    private LauncherAuthSession(String username, String token, UUID uuid) {
        this.username = username;
        this.token = token;
        this.uuid = uuid;
    }

    public static LauncherAuthSession create(String username, String token) {
        String normalizedUser = Objects.requireNonNull(username, "username").trim();
        String normalizedToken = Objects.requireNonNull(token, "token").trim();
        if (normalizedUser.isEmpty()) {
            throw new IllegalArgumentException("Username cannot be blank");
        }
        if (normalizedToken.isEmpty()) {
            throw new IllegalArgumentException("Token cannot be blank");
        }
        UUID offlineUuid = IdentityIds.offlineUuidForUsername(normalizedUser);
        return new LauncherAuthSession(normalizedUser, normalizedToken, offlineUuid);
    }

    public String username() {
        return username;
    }

    public String token() {
        return token;
    }

    public String uuidString() {
        return uuid.toString();
    }

    public String userType() {
        return USER_TYPE;
    }
}

