package dev.kol.auth.core.service;

public class AuthException extends RuntimeException {
    private final int statusCode;

    public AuthException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public int statusCode() {
        return statusCode;
    }
}
