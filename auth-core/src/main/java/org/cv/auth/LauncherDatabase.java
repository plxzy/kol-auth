package org.cv.auth;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public final class LauncherDatabase {
    private static final String CONFIG_FILENAME = "database.properties";
    private static final String URL_KEY = "url";
    private static final String USER_KEY = "user";
    private static final String PASSWORD_KEY = "password";
    public static final String ALGO_SHA256 = "sha256";
    public static final String ALGO_ARGON2ID = "argon2id";

    private final String jdbcUrl;
    private final String username;
    private final String password;
    private final AtomicBoolean schemaReady = new AtomicBoolean(false);

    static {
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println("Kol auth-core: PostgreSQL JDBC driver not found on module path.");
        }
    }

    private LauncherDatabase(String jdbcUrl, String username, String password) {
        this.jdbcUrl = Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        this.username = username;
        this.password = password;
    }

    public static LauncherDatabase load(Path baseDir) {
        String url = firstNonBlank(
            System.getProperty("kol.dbUrl"),
            System.getenv("KOL_DB_URL"),
            readProperty(baseDir, URL_KEY)
        );
        if (url == null || url.isBlank()) {
            return null;
        }
        String jdbcUrl = normalizeJdbcUrl(url.trim());
        String user = firstNonBlank(
            System.getProperty("kol.dbUser"),
            System.getenv("KOL_DB_USER"),
            readProperty(baseDir, USER_KEY)
        );
        String password = firstNonBlank(
            System.getProperty("kol.dbPassword"),
            System.getenv("KOL_DB_PASSWORD"),
            readProperty(baseDir, PASSWORD_KEY)
        );
        return new LauncherDatabase(jdbcUrl, trimToNull(user), trimToNull(password));
    }

    void storeCredentials(String username, UUID uuid, String saltB64, String hashB64, String algorithm, boolean needsUpgrade) {
        if (!isConfigured()) {
            return;
        }
        if (isBlank(username) || isBlank(hashB64) || isBlank(algorithm)) {
            return;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 INSERT INTO launcher_users (username, uuid, salt, password_hash, password_algo, password_needs_upgrade, registered_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, now(), now())
                 ON CONFLICT (username) DO UPDATE
                   SET uuid = COALESCE(EXCLUDED.uuid, launcher_users.uuid),
                       salt = EXCLUDED.salt,
                       password_hash = EXCLUDED.password_hash,
                       password_algo = EXCLUDED.password_algo,
                       password_needs_upgrade = EXCLUDED.password_needs_upgrade,
                       updated_at = now()
                 """)) {
            ps.setString(1, username.trim());
            if (uuid != null) {
                ps.setString(2, uuid.toString());
            } else {
                ps.setNull(2, java.sql.Types.VARCHAR);
            }
            if (saltB64 == null || saltB64.isBlank()) {
                ps.setNull(3, java.sql.Types.VARCHAR);
            } else {
                ps.setString(3, saltB64.trim());
            }
            ps.setString(4, hashB64.trim());
            ps.setString(5, algorithm.trim().toLowerCase());
            ps.setBoolean(6, needsUpgrade);
            ps.executeUpdate();
            if (uuid != null) {
                ensureAccount(conn, uuid);
            }
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to persist registration in Postgres: " + e.getMessage());
        }
    }

    void updateWallet(String username, String wallet) {
        if (!isConfigured() || isBlank(username)) {
            return;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 UPDATE launcher_users
                    SET wallet = ?, updated_at = now()
                  WHERE username = ?
                 """)) {
            if (wallet == null || wallet.isBlank()) {
                ps.setNull(1, java.sql.Types.VARCHAR);
            } else {
                ps.setString(1, wallet.trim());
            }
            ps.setString(2, username.trim());
            int rows = ps.executeUpdate();
            if (rows == 0 && wallet != null && !wallet.isBlank()) {
                System.err.println("Kol auth-core: no Postgres record for '" + username
                    + "' when updating wallet; registration may have failed earlier.");
            }
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to update wallet in Postgres: " + e.getMessage());
        }
    }

    void ensureAccount(UUID uuid) {
        if (!isConfigured() || uuid == null) {
            return;
        }
        try (Connection conn = openConnection()) {
            ensureAccount(conn, uuid);
        } catch (SQLException e) {
            if (!isMissingTable(e)) {
                System.err.println("Kol auth-core: failed to ensure Postgres account row: " + e.getMessage());
            }
        }
    }

    void createSession(String token, UUID uuid, String username, java.time.Instant expiresAt) {
        if (!isConfigured() || token == null || token.isBlank() || uuid == null || username == null || username.isBlank()) {
            return;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 INSERT INTO launcher_sessions (token, uuid, username, issued_at, expires_at, revoked)
                 VALUES (?, ?, ?, now(), ?, false)
                 ON CONFLICT (token) DO UPDATE
                   SET uuid = EXCLUDED.uuid,
                       username = EXCLUDED.username,
                       issued_at = now(),
                       expires_at = EXCLUDED.expires_at,
                       revoked = false
                 """)) {
            ps.setString(1, token.trim());
            ps.setString(2, uuid.toString());
            ps.setString(3, username.trim());
            ps.setTimestamp(4, java.sql.Timestamp.from(expiresAt));
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to store session token: " + e.getMessage());
        }
    }

    SessionRecord fetchSession(String token) {
        if (!isConfigured() || token == null || token.isBlank()) {
            return null;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 SELECT uuid, username, issued_at, expires_at, revoked
                   FROM launcher_sessions
                  WHERE token = ?
                 """)) {
            ps.setString(1, token.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                UUID uuid = safeUuid(rs.getString(1));
                String username = trimToNull(rs.getString(2));
                java.time.Instant issued = toInstant(rs.getTimestamp(3));
                java.time.Instant expires = toInstant(rs.getTimestamp(4));
                boolean revoked = rs.getBoolean(5);
                return new SessionRecord(uuid, username, issued, expires, revoked);
            }
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to fetch session: " + e.getMessage());
            return null;
        }
    }

    void revokeSession(String token) {
        if (!isConfigured() || token == null || token.isBlank()) {
            return;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 UPDATE launcher_sessions
                    SET revoked = true
                  WHERE token = ?
                 """)) {
            ps.setString(1, token.trim());
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to revoke session: " + e.getMessage());
        }
    }

    Credentials fetchCredentials(String username) {
        if (!isConfigured() || isBlank(username)) {
            return null;
        }
        try (Connection conn = openConnection();
             PreparedStatement ps = conn.prepareStatement("""
                 SELECT uuid, salt, password_hash, password_algo, password_needs_upgrade, wallet
                   FROM launcher_users
                  WHERE username = ?
                 """)) {
            ps.setString(1, username.trim());
            try (var rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                String uuid = trimToNull(rs.getString(1));
                String salt = trimToNull(rs.getString(2));
                String hash = trimToNull(rs.getString(3));
                String algorithm = trimToNull(rs.getString(4));
                boolean needsUpgrade = rs.getBoolean(5);
                String wallet = trimToNull(rs.getString(6));
                if (salt == null || salt.isBlank() || hash == null || hash.isBlank()) {
                    return null;
                }
                return new Credentials(salt, hash, wallet, algorithm != null ? algorithm : ALGO_SHA256, needsUpgrade, uuid);
            }
        } catch (SQLException e) {
            System.err.println("Kol auth-core: failed to read credentials from Postgres: " + e.getMessage());
            return null;
        }
    }

    boolean hasUser(String username) {
        return fetchCredentials(username) != null;
    }

    public record SessionRecord(UUID uuid, String username, java.time.Instant issuedAt, java.time.Instant expiresAt, boolean revoked) {
        public boolean isExpired() {
            return expiresAt != null && java.time.Instant.now().isAfter(expiresAt);
        }
    }

    private Connection openConnection() throws SQLException {
        Connection connection = DriverManager.getConnection(jdbcUrl, username, password);
        ensureSchema(connection);
        return connection;
    }

    private void ensureSchema(Connection connection) throws SQLException {
        if (schemaReady.get()) {
            return;
        }
        synchronized (schemaReady) {
            if (schemaReady.get()) {
                return;
            }
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS launcher_users (
                        username TEXT PRIMARY KEY,
                        uuid TEXT,
                        salt TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        password_algo TEXT NOT NULL DEFAULT 'sha256',
                        password_needs_upgrade BOOLEAN NOT NULL DEFAULT FALSE,
                        wallet TEXT,
                        registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """);
                stmt.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS launcher_users_uuid_unique
                        ON launcher_users (uuid) WHERE uuid IS NOT NULL
                    """);
            }
            applyMigrations(connection);
            schemaReady.set(true);
        }
    }

    private boolean isConfigured() {
        return jdbcUrl != null && !jdbcUrl.isBlank();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (!isBlank(v)) {
                return v;
            }
        }
        return null;
    }

    private static String readProperty(Path baseDir, String key) {
        if (baseDir == null || key == null) {
            return null;
        }
        Path config = baseDir.resolve(CONFIG_FILENAME);
        if (!Files.exists(config)) {
            return null;
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(config)) {
            props.load(in);
        } catch (IOException e) {
            System.err.println("Kol auth-core: failed to read " + config + ": " + e.getMessage());
            return null;
        }
        String value = props.getProperty(key);
        if (value == null) {
            return null;
        }
        return value.trim().isEmpty() ? null : value.trim();
    }

    private static String normalizeJdbcUrl(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.startsWith("jdbc:")) {
            return trimmed;
        }
        if (trimmed.startsWith("postgresql://")) {
            return "jdbc:" + trimmed;
        }
        if (trimmed.startsWith("postgres://")) {
            return "jdbc:postgresql://" + trimmed.substring("postgres://".length());
        }
        return trimmed;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static UUID safeUuid(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private static java.time.Instant toInstant(java.sql.Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    public record Credentials(String salt, String passwordHash, String wallet, String algorithm, boolean needsUpgrade, String uuid) {}

    private void applyMigrations(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("""
                ALTER TABLE launcher_users
                ADD COLUMN IF NOT EXISTS uuid TEXT
                """);
            stmt.execute("""
                ALTER TABLE launcher_users
                ADD COLUMN IF NOT EXISTS password_algo TEXT NOT NULL DEFAULT 'sha256'
                """);
            stmt.execute("""
                ALTER TABLE launcher_users
                ADD COLUMN IF NOT EXISTS password_needs_upgrade BOOLEAN NOT NULL DEFAULT FALSE
                """);
            stmt.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS launcher_users_uuid_unique
                    ON launcher_users (uuid) WHERE uuid IS NOT NULL
                """);
        }
        markLegacyAlgorithms(connection);
        backfillMissingUuids(connection);
    }

    private void markLegacyAlgorithms(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("""
                UPDATE launcher_users
                   SET password_algo = 'sha256'
                 WHERE password_algo IS NULL
                """);
            stmt.executeUpdate("""
                UPDATE launcher_users
                   SET password_needs_upgrade = TRUE
                 WHERE password_algo = 'sha256'
                """);
        }
    }

    private void backfillMissingUuids(Connection connection) throws SQLException {
        List<String> usernames = new ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement("""
                SELECT username
                  FROM launcher_users
                 WHERE uuid IS NULL
                """)) {
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String user = rs.getString(1);
                    if (!isBlank(user)) {
                        usernames.add(user);
                    }
                }
            }
        }
        if (usernames.isEmpty()) {
            return;
        }
        for (String user : usernames) {
            UUID uuid = IdentityIds.offlineUuidForUsername(user);
            try (PreparedStatement upd = connection.prepareStatement("""
                    UPDATE launcher_users
                       SET uuid = ?, updated_at = now()
                     WHERE username = ?
                    """)) {
                upd.setString(1, uuid.toString());
                upd.setString(2, user);
                upd.executeUpdate();
            }
            ensureAccount(connection, uuid);
        }
    }

    private void ensureAccount(Connection connection, UUID uuid) throws SQLException {
        if (uuid == null) {
            return;
        }
        try (PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO accounts(uuid)
                VALUES (?)
                ON CONFLICT (uuid) DO NOTHING
                """)) {
            ps.setString(1, uuid.toString());
            ps.executeUpdate();
        } catch (SQLException e) {
            if (isMissingTable(e)) {
                return;
            }
            throw e;
        }
    }

    private static boolean isMissingTable(SQLException e) {
        return "42P01".equals(e.getSQLState());
    }
}
