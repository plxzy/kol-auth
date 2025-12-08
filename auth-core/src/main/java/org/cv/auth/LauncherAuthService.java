package org.cv.auth;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.interfaces.EdECPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.UUID;

public final class LauncherAuthService {
    private static final String SHARED_SECRET = "ChangeMeStrongSecret";
    private static final int ARGON2_ITERATIONS = 3;
    private static final int ARGON2_MEMORY_KB = 65536;
    private static final int ARGON2_PARALLELISM = 1;
    private static final String PROP_SALT = "salt";
    private static final String PROP_HASH = "hash";
    private static final String PROP_ALGO = "algo";
    private static final String PROP_UUID = "uuid";

    private final Path baseDir;
    private final Path usersDir;
    private final LauncherDatabase database;

    public LauncherAuthService() {
        this(Path.of(System.getProperty("user.home"), ".kol"));
    }

    public LauncherAuthService(Path baseDir) {
        this.baseDir = baseDir;
        this.usersDir = baseDir.resolve("users");
        this.database = LauncherDatabase.load(baseDir);
    }

    public Path getBaseDir() {
        return baseDir;
    }

    public Path getUsersDir() {
        return usersDir;
    }

    public boolean isRegistered(String username) {
        if (database != null) {
            return database.hasUser(username);
        }
        return Files.exists(userCredPath(username));
    }

    public boolean hasLegacyCredentials(String username) {
        return Files.exists(userCredPath(username));
    }

    public boolean isDatabaseEnabled() {
        return database != null;
    }

    public void registerUser(String username, String password) throws Exception {
        Files.createDirectories(usersDir);
        UUID uuid = IdentityIds.offlineUuidForUsername(username);
        if (database != null) {
            if (database.hasUser(username)) {
                throw new IOException("User already exists");
            }
        } else if (Files.exists(userCredPath(username))) {
            throw new IOException("User already exists");
        }
        PasswordHash hash = hashPasswordArgon2(password);
        if (database != null) {
            database.storeCredentials(username, uuid, hash.saltB64(), hash.hash(), hash.algorithm(), hash.needsUpgrade());
            database.ensureAccount(uuid);
        } else {
            Properties props = new Properties();
            populateCredentialProperties(props, uuid, hash);
            try (var out = Files.newOutputStream(userCredPath(username))) {
                props.store(out, "Kol user credentials");
            }
        }
    }

    public boolean verifyUser(String username, String password) throws Exception {
        if (database != null) {
            LauncherDatabase.Credentials creds = database.fetchCredentials(username);
            if (creds != null) {
                PasswordHash stored = toPasswordHash(creds);
                if (verifyStoredHash(stored, password)) {
                    UUID uuid = resolveOrCreateUuid(username, creds.uuid());
                    PasswordHash effective = stored.needsUpgrade() ? hashPasswordArgon2(password) : stored.withNeedsUpgrade(false);
                    database.storeCredentials(username, uuid, effective.saltB64(), effective.hash(), effective.algorithm(), effective.needsUpgrade());
                    database.ensureAccount(uuid);
                    updateLocalCredentialCache(username, uuid, effective);
                    return true;
                }
            }
        }
        Path cred = userCredPath(username);
        if (!Files.exists(cred)) {
            return false;
        }
        Properties props = new Properties();
        try (var in = Files.newInputStream(cred)) {
            props.load(in);
        }
        PasswordHash stored = toPasswordHash(props);
        if (stored == null) {
            return false;
        }
        if (!verifyStoredHash(stored, password)) {
            return false;
        }
        UUID uuid = ensureUuidProperty(props, username);
        PasswordHash effective = stored.needsUpgrade() ? hashPasswordArgon2(password) : stored.withNeedsUpgrade(false);
        populateCredentialProperties(props, uuid, effective);
        try (var out = Files.newOutputStream(cred)) {
            props.store(out, "Kol user credentials");
        }
        if (database != null) {
            database.storeCredentials(username, uuid, effective.saltB64(), effective.hash(), effective.algorithm(), effective.needsUpgrade());
            database.ensureAccount(uuid);
        }
        return true;
    }

    public void saveUsername(String username) throws IOException {
        Path userPath = baseDir.resolve("username.txt");
        Files.createDirectories(userPath.getParent());
        Files.writeString(userPath, username, StandardCharsets.UTF_8);
    }

    public String getSavedUsername() throws IOException {
        Path userPath = baseDir.resolve("username.txt");
        if (!Files.exists(userPath)) {
            return null;
        }
        String text = Files.readString(userPath, StandardCharsets.UTF_8).trim();
        return text.isEmpty() ? null : text;
    }

    public boolean logout() throws IOException {
        Path tokenPath = baseDir.resolve("token.txt");
        Path userPath = baseDir.resolve("username.txt");
        boolean removed = Files.deleteIfExists(tokenPath);
        removed |= Files.deleteIfExists(userPath);
        return removed;
    }

    public String getExistingToken() throws IOException {
        Path tokenPath = baseDir.resolve("token.txt");
        if (!Files.exists(tokenPath)) {
            return null;
        }
        String token = Files.readString(tokenPath, StandardCharsets.UTF_8).trim();
        return token.isEmpty() ? null : token;
    }

    public void ensureToken(String username) throws Exception {
        String existing = getExistingToken();
        if (existing != null) {
            System.out.println("Found existing token at " + baseDir.resolve("token.txt"));
            return;
        }
        saveToken(issueSessionToken(username));
    }

    public void saveToken(String token) throws IOException {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("token must not be blank");
        }
        Path tokenPath = baseDir.resolve("token.txt");
        Files.createDirectories(tokenPath.getParent());
        Files.writeString(tokenPath, token.trim(), StandardCharsets.UTF_8);
    }

    public String issueSessionToken(String username) throws Exception {
        UUID uuid = IdentityIds.offlineUuidForUsername(username);
        byte[] random = new byte[32];
        java.security.SecureRandom.getInstanceStrong().nextBytes(random);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        java.time.Instant expires = java.time.Instant.now().plus(java.time.Duration.ofDays(14));
        database.createSession(token, uuid, username, expires);
        return token;
    }

    public LauncherDatabase.SessionRecord findSession(String token) {
        return database != null ? database.fetchSession(token) : null;
    }

    public void revokeSession(String token) {
        if (database == null) {
            return;
        }
        database.revokeSession(token);
    }

    public String generateAndSaveWallet(String username) throws Exception {
        var kpg = java.security.KeyPairGenerator.getInstance("Ed25519");
        var kp = kpg.generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded();
        byte[] rawPub = extractRawEd25519PublicKey(spki);
        String address = base58Encode(rawPub);
        setUserWallet(username, address);

        byte[] seed32;
        if (kp.getPrivate() instanceof EdECPrivateKey edKey) {
            seed32 = edKey.getBytes().orElse(null);
            if (seed32 == null) {
                byte[] pkcs8 = kp.getPrivate().getEncoded();
                seed32 = extractEd25519PrivateSeed(pkcs8);
            }
        } else {
            byte[] pkcs8 = kp.getPrivate().getEncoded();
            seed32 = extractEd25519PrivateSeed(pkcs8);
        }
        savePrivateSeed(username, seed32);
        return address;
    }

    public String getUserWallet(String username) throws IOException {
        if (database != null) {
            LauncherDatabase.Credentials creds = database.fetchCredentials(username);
            if (creds != null) {
                String wallet = creds.wallet();
                if (wallet != null && !wallet.isBlank()) {
                    return wallet;
                }
            }
        }
        Path cred = userCredPath(username);
        if (!Files.exists(cred)) {
            return null;
        }
        Properties props = new Properties();
        try (var in = Files.newInputStream(cred)) {
            props.load(in);
        }
        String w = props.getProperty("wallet");
        if (w == null) {
            return null;
        }
        w = w.trim();
        return w.isEmpty() ? null : w;
    }

    public void setUserWallet(String username, String wallet) throws IOException {
        if (database != null) {
            database.updateWallet(username, wallet);
            return;
        }
        Path cred = userCredPath(username);
        Properties props = new Properties();
        if (Files.exists(cred)) {
            try (var in = Files.newInputStream(cred)) {
                props.load(in);
            }
        }
        if (wallet == null || wallet.isBlank()) {
            props.remove("wallet");
        } else {
            props.setProperty("wallet", wallet.trim());
        }
        Files.createDirectories(cred.getParent());
        try (var out = Files.newOutputStream(cred)) {
            props.store(out, "Kol user credentials");
        }
    }

    public String shortenWallet(String addr) {
        if (addr == null) {
            return null;
        }
        if (addr.length() <= 12) {
            return addr;
        }
        String start = addr.substring(0, 6);
        String end = addr.substring(addr.length() - 6);
        return start + "..." + end;
    }

    private PasswordHash hashPasswordArgon2(String password) {
        char[] chars = password.toCharArray();
        Argon2 argon2 = Argon2Factory.create();
        try {
            String hash = argon2.hash(ARGON2_ITERATIONS, ARGON2_MEMORY_KB, ARGON2_PARALLELISM, chars);
            String saltB64 = extractSaltFromPhc(hash);
            if (saltB64 == null) {
                throw new IllegalStateException("Argon2 hash missing salt component");
            }
            return new PasswordHash(LauncherDatabase.ALGO_ARGON2ID, saltB64, hash, false);
        } finally {
            argon2.wipeArray(chars);
            Arrays.fill(chars, '\0');
        }
    }

    private PasswordHash toPasswordHash(LauncherDatabase.Credentials creds) {
        if (creds == null) {
            return null;
        }
        String algorithm = normalizeAlgorithm(creds.algorithm());
        boolean needsUpgrade = creds.needsUpgrade() || LauncherDatabase.ALGO_SHA256.equals(algorithm);
        return new PasswordHash(algorithm, creds.salt(), creds.passwordHash(), needsUpgrade);
    }

    private PasswordHash toPasswordHash(Properties props) {
        if (props == null) {
            return null;
        }
        String hash = props.getProperty(PROP_HASH);
        if (hash == null || hash.isBlank()) {
            return null;
        }
        String algorithm = normalizeAlgorithm(props.getProperty(PROP_ALGO));
        String salt = props.getProperty(PROP_SALT);
        boolean needsUpgrade = LauncherDatabase.ALGO_SHA256.equals(algorithm);
        return new PasswordHash(algorithm, salt, hash.trim(), needsUpgrade);
    }

    private boolean verifyStoredHash(PasswordHash stored, String password) throws Exception {
        if (stored == null || stored.hash() == null) {
            return false;
        }
        String algorithm = normalizeAlgorithm(stored.algorithm());
        if (LauncherDatabase.ALGO_ARGON2ID.equals(algorithm)) {
            char[] chars = password.toCharArray();
            Argon2 argon2 = Argon2Factory.create();
            try {
                return argon2.verify(stored.hash(), chars);
            } finally {
                argon2.wipeArray(chars);
                Arrays.fill(chars, '\0');
            }
        }
        if (LauncherDatabase.ALGO_SHA256.equals(algorithm)) {
            String saltB64 = stored.saltB64();
            if (saltB64 == null || saltB64.isBlank()) {
                return false;
            }
            try {
                byte[] salt = Base64.getDecoder().decode(saltB64);
                String calc = hashLegacyPassword(salt, password);
                return stored.hash().equals(calc);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return false;
    }

    private UUID resolveOrCreateUuid(String username, String uuidText) {
        if (uuidText != null && !uuidText.isBlank()) {
            try {
                return UUID.fromString(uuidText.trim());
            } catch (IllegalArgumentException ignored) {
            }
        }
        return IdentityIds.offlineUuidForUsername(username);
    }

    private void updateLocalCredentialCache(String username, UUID uuid, PasswordHash hash) throws IOException {
        Path cred = userCredPath(username);
        if (!Files.exists(cred)) {
            return;
        }
        Properties props = new Properties();
        try (var in = Files.newInputStream(cred)) {
            props.load(in);
        }
        populateCredentialProperties(props, uuid, hash);
        try (var out = Files.newOutputStream(cred)) {
            props.store(out, "Kol user credentials");
        }
    }

    private void populateCredentialProperties(Properties props, UUID uuid, PasswordHash hash) {
        if (uuid != null) {
            props.setProperty(PROP_UUID, uuid.toString());
        }
        props.setProperty(PROP_ALGO, hash.algorithm());
        if (hash.saltB64() != null && !hash.saltB64().isBlank()) {
            props.setProperty(PROP_SALT, hash.saltB64());
        } else {
            props.remove(PROP_SALT);
        }
        props.setProperty(PROP_HASH, hash.hash());
    }

    private UUID ensureUuidProperty(Properties props, String username) {
        String text = props.getProperty(PROP_UUID);
        if (text != null && !text.isBlank()) {
            try {
                return UUID.fromString(text.trim());
            } catch (IllegalArgumentException ignored) {
            }
        }
        UUID uuid = IdentityIds.offlineUuidForUsername(username);
        props.setProperty(PROP_UUID, uuid.toString());
        return uuid;
    }

    private static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            return LauncherDatabase.ALGO_SHA256;
        }
        return algorithm.trim().toLowerCase();
    }

    private static String extractSaltFromPhc(String phc) {
        if (phc == null || !phc.startsWith("$argon2")) {
            return null;
        }
        String[] parts = phc.split("\\$");
        return parts.length >= 5 ? parts[4] : null;
    }

    private static String hashLegacyPassword(byte[] salt, String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        digest.update(":".getBytes(StandardCharsets.UTF_8));
        digest.update(password.getBytes(StandardCharsets.UTF_8));
        byte[] h = digest.digest();
        return Base64.getEncoder().encodeToString(h);
    }

    private record PasswordHash(String algorithm, String saltB64, String hash, boolean needsUpgrade) {
        PasswordHash withNeedsUpgrade(boolean value) {
            if (value == needsUpgrade) {
                return this;
            }
            return new PasswordHash(algorithm, saltB64, hash, value);
        }
    }

    private Path userCredPath(String username) {
        return usersDir.resolve(username + ".properties");
    }

    private void savePrivateSeed(String username, byte[] seed32) throws IOException {
        Files.createDirectories(usersDir);
        Path seedPath = usersDir.resolve(username + ".seed");
        String b64 = Base64.getEncoder().encodeToString(seed32);
        Files.writeString(seedPath, b64, StandardCharsets.UTF_8);
    }

    private static byte[] extractRawEd25519PublicKey(byte[] spki) throws IOException {
        for (int i = 0; i < spki.length - 34; i++) {
            if ((spki[i] & 0xFF) == 0x03 && (spki[i + 1] & 0xFF) == 0x21 && spki[i + 2] == 0x00) {
                byte[] out = new byte[32];
                System.arraycopy(spki, i + 3, out, 0, 32);
                return out;
            }
        }
        throw new IOException("Unsupported Ed25519 public key encoding");
    }

    private static byte[] extractEd25519PrivateSeed(byte[] pkcs8) throws IOException {
        for (int i = 0; i < pkcs8.length - 34; i++) {
            if ((pkcs8[i] & 0xFF) == 0x04 && (pkcs8[i + 1] & 0xFF) == 0x20) {
                byte[] seed = new byte[32];
                System.arraycopy(pkcs8, i + 2, seed, 0, 32);
                return seed;
            }
        }
        throw new IOException("Unsupported Ed25519 private key encoding");
    }

    private static String base58Encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        byte[] buf = input.clone();
        int size = (int) Math.ceil(input.length * 1.38) + 1;
        char[] out = new char[size];
        int outIdx = size;
        int start = zeros;
        while (start < buf.length) {
            int mod = divmod58(buf, start);
            if (buf[start] == 0) {
                start++;
            }
            out[--outIdx] = B58_ALPHABET[mod];
        }
        while (zeros-- > 0) {
            out[--outIdx] = '1';
        }
        return new String(out, outIdx, size - outIdx);
    }

    private static int divmod58(byte[] number, int start) {
        int remainder = 0;
        for (int i = start; i < number.length; i++) {
            int digit = number[i] & 0xFF;
            int tmp = remainder * 256 + digit;
            number[i] = (byte) (tmp / 58);
            remainder = tmp % 58;
        }
        return remainder;
    }

    private static final char[] B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
}

