package org.cv.auth;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class IdentityIds {
    private IdentityIds() {}

    public static UUID offlineUuidForUsername(String username) {
        return computeNamespacedUuid("OfflinePlayer:", username);
    }

    public static UUID kolUuidForUsername(String username) {
        return computeNamespacedUuid("Kol:", username);
    }

    private static UUID computeNamespacedUuid(String prefix, String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be null");
        }
        String trimmed = username.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        return UUID.nameUUIDFromBytes((prefix + trimmed).getBytes(StandardCharsets.UTF_8));
    }
}

