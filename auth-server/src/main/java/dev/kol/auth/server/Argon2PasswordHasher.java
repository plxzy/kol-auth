package dev.kol.auth.server;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import dev.kol.auth.core.service.HashingConfig;
import dev.kol.auth.core.service.PasswordHasher;

/**
 * Minimal Argon2id wrapper. TODO: wire pepper from secret manager.
 */
public class Argon2PasswordHasher implements PasswordHasher {
    private final Argon2 argon2;
    private final HashingConfig config;

    public Argon2PasswordHasher(HashingConfig config) {
        this.config = config;
        this.argon2 = Argon2Factory.create(
                Argon2Factory.Argon2Types.ARGON2id,
                16,
                32
        );
    }

    @Override
    public String hash(char[] password) {
        return argon2.hash(config.iterations(), config.memoryKb(), config.parallelism(), password);
    }

    @Override
    public boolean verify(char[] password, String hash) {
        return argon2.verify(hash, password);
    }
}
