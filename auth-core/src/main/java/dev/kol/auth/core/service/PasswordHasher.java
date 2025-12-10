package dev.kol.auth.core.service;

public interface PasswordHasher {
    String hash(char[] password);

    boolean verify(char[] password, String hash);
}
