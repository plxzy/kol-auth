package dev.kol.auth.core.service;

public record HashingConfig(
        int iterations,
        int memoryKb,
        int parallelism
) {
}
