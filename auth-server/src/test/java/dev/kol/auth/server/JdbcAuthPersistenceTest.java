package dev.kol.auth.server;

import dev.kol.auth.core.dto.AuthResponse;
import dev.kol.auth.core.dto.LoginRequest;
import dev.kol.auth.core.dto.RegisterRequest;
import dev.kol.auth.core.service.HashingConfig;
import dev.kol.auth.core.service.PasswordHasher;
import dev.kol.auth.core.service.TokenService;
import dev.kol.auth.core.tokens.TokenConfig;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import static org.assertj.core.api.Assertions.assertThat;

class JdbcAuthPersistenceTest {
    private static PostgreSQLContainer<?> postgres;

    @BeforeAll
    static void start() {
        postgres = new PostgreSQLContainer<>("postgres:16-alpine")
                .withDatabaseName("kol_auth")
                .withUsername("kol_auth")
                .withPassword("kol_dev_password");
        postgres.start();
    }

    @AfterAll
    static void stop() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @Test
    @Tag("db")
    void persistsUsersAcrossServiceInstances() throws Exception {
        DbConfig db = new DbConfig(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword(), "auth");
        Flyway.configure()
                .dataSource(db.url(), db.user(), db.password())
                .schemas(db.schema())
                .createSchemas(true)
                .load()
                .migrate();

        JdbcConnectionFactory connectionFactory = new JdbcConnectionFactory(db);
        JdbcUserRepository userRepository = new JdbcUserRepository(connectionFactory, db.schema());

        TokenConfig tokenConfig = new TokenConfig(
                "https://auth.local.dev",
                "kol-clients",
                900,
                1_209_600,
                "CHANGE_ME_SUPER_SECRET_CHANGE_ME_SUPER_SECRET"
        );
        TokenService tokenService = new JdbcTokenService(connectionFactory, tokenConfig, db.schema());
        PasswordHasher passwordHasher = new Argon2PasswordHasher(new HashingConfig(2, 32_768, 1));

        JdbcAuthService first = new JdbcAuthService(userRepository, tokenService, passwordHasher);
        first.register(new RegisterRequest("persistuser", "persist@example.com", "password123"));

        assertThat(countUsers(connectionFactory, "auth", "persistuser")).isEqualTo(1);

        JdbcAuthService second = new JdbcAuthService(
                new JdbcUserRepository(connectionFactory, db.schema()),
                new JdbcTokenService(connectionFactory, tokenConfig, db.schema()),
                passwordHasher
        );

        AuthResponse loggedIn = second.login(new LoginRequest("persistuser", "password123"));
        assertThat(loggedIn.user().username()).isEqualTo("persistuser");
        assertThat(loggedIn.tokens().accessToken()).isNotBlank();
    }

    private static long countUsers(JdbcConnectionFactory connectionFactory, String schema, String username) throws Exception {
        String sql = "SELECT COUNT(*) FROM " + schema + ".users WHERE username = ?";
        try (Connection c = connectionFactory.open();
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getLong(1);
            }
        }
    }
}
