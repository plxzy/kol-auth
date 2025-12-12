package dev.kol.auth.server;

import dev.kol.auth.core.service.HashingConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class Argon2PasswordHasherTest {

    private final HashingConfig config = new HashingConfig(2, 16 * 1024, 1);
    private final Argon2PasswordHasher hasher = new Argon2PasswordHasher(config);

    @Test
    void shouldHashAndVerifyPassword() {
        char[] password = "mySecretPassword".toCharArray();

        String hash = hasher.hash(password);

        assertThat(hash).isNotNull();
        assertThat(hasher.verify(password, hash)).isTrue();
    }

    @Test
    void shouldFailVerificationForWrongPassword() {
        char[] password = "mySecretPassword".toCharArray();
        String hash = hasher.hash(password);

        char[] wrongPassword = "wrongPassword".toCharArray();

        assertThat(hasher.verify(wrongPassword, hash)).isFalse();
    }

    @Test
    void shouldGenerateDifferentHashesForSamePasswordWithDifferentSalt() {
        // Argon2 automatically generates a random salt for each hash call
        char[] password = "samePassword".toCharArray();

        String hash1 = hasher.hash(password);
        String hash2 = hasher.hash(password);

        assertThat(hash1).isNotEqualTo(hash2);
        assertThat(hasher.verify(password, hash1)).isTrue();
        assertThat(hasher.verify(password, hash2)).isTrue();
    }
}
