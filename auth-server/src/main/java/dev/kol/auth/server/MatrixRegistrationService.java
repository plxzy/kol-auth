package dev.kol.auth.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

final class MatrixRegistrationService {
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._=-]+$");
    private static final Pattern SANITIZE_PATTERN = Pattern.compile("[^a-z0-9._=-]");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final String homeserverUrl;
    private final String registrationToken;
    private final ObjectMapper mapper;
    private final HttpClient httpClient;
    private final String domain;

    MatrixRegistrationService(String homeserverUrl, String registrationToken, ObjectMapper mapper) {
        this.homeserverUrl = Objects.requireNonNull(homeserverUrl, "homeserverUrl").replaceAll("/+$", "");
        this.registrationToken = Objects.requireNonNull(registrationToken, "registrationToken");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
        this.domain = extractDomain(homeserverUrl);
    }

    static MatrixRegistrationService fromConfig(AuthServerConfig config, ObjectMapper mapper) {
        String homeserverUrl = config.matrixHomeserverUrl();
        String registrationToken = config.matrixRegistrationToken();

        if (homeserverUrl == null || homeserverUrl.isBlank() || registrationToken == null || registrationToken.isBlank()) {
            System.out.println("[MatrixRegistrationService] Matrix integration not configured (MATRIX_HOMESERVER_URL and MATRIX_REGISTRATION_TOKEN not set)");
            return null;
        }

        String domain = extractDomain(homeserverUrl);
        System.out.println("[MatrixRegistrationService] Enabled for domain: " + domain);
        return new MatrixRegistrationService(homeserverUrl, registrationToken, mapper);
    }

    void registerUser(String username, String password) {
        if (username == null || username.isBlank()) {
            System.err.println("[MatrixRegistrationService] Skipping registration: username is null or blank");
            return;
        }
        if (password == null || password.isBlank()) {
            System.err.println("[MatrixRegistrationService] Skipping registration for '" + username + "': password is null or blank");
            return;
        }

        String sanitizedUsername = sanitizeUsername(username);
        if (sanitizedUsername.length() < 3) {
            System.err.println("[MatrixRegistrationService] Skipping registration for '" + username + "': sanitized username '" + sanitizedUsername + "' is too short (< 3 chars)");
            return;
        }

        try {
            performRegistration(sanitizedUsername, password);
        } catch (Exception e) {
            System.err.println("[MatrixRegistrationService] Registration failed for '" + sanitizedUsername + "' on " + domain + ": " + e.getMessage());
        }
    }

    private void performRegistration(String username, String password) throws Exception {
        String registrationUrl = homeserverUrl + "/_matrix/client/v3/register";

        Map<String, Object> authBody = Map.of(
                "type", "m.login.registration_token",
                "token", registrationToken
        );
        Map<String, Object> requestBody = Map.of(
                "username", username,
                "password", password,
                "auth", authBody
        );

        String jsonBody = mapper.writeValueAsString(requestBody);
        HttpResponse<String> response = sendPost(registrationUrl, jsonBody);

        if (response.statusCode() == 401) {
            String session = extractSession(response.body());
            if (session != null && !session.isBlank()) {
                jsonBody = buildRequestBodyWithSession(username, password, session);
                response = sendPost(registrationUrl, jsonBody);
            }
        }

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            System.out.println("[MatrixRegistrationService] Successfully registered user '" + username + "' on " + domain);
        } else if (response.statusCode() == 400 && response.body().contains("M_USER_IN_USE")) {
            System.out.println("[MatrixRegistrationService] User '" + username + "' already exists on " + domain + ", skipping");
        } else {
            System.err.println("[MatrixRegistrationService] Registration failed for '" + username + "' on " + domain + ": HTTP " + response.statusCode() + " - " + response.body());
        }
    }

    private HttpResponse<String> sendPost(String url, String body) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(REQUEST_TIMEOUT)
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String buildRequestBodyWithSession(String username, String password, String session) throws Exception {
        Map<String, Object> authBody = Map.of(
                "type", "m.login.registration_token",
                "token", registrationToken,
                "session", session
        );
        Map<String, Object> requestBody = Map.of(
                "username", username,
                "password", password,
                "auth", authBody
        );
        return mapper.writeValueAsString(requestBody);
    }

    private String extractSession(String responseBody) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = mapper.readValue(responseBody, Map.class);
            Object session = response.get("session");
            return session != null ? session.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String sanitizeUsername(String username) {
        String lower = username.toLowerCase();
        return SANITIZE_PATTERN.matcher(lower).replaceAll("");
    }

    private static String extractDomain(String url) {
        if (url == null || url.isBlank()) {
            return "unknown";
        }
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host != null && !host.isBlank()) {
                return host;
            }
            String withoutProtocol = url.replaceAll("^https?://", "");
            int colonIndex = withoutProtocol.indexOf(':');
            int slashIndex = withoutProtocol.indexOf('/');
            int endIndex = colonIndex > 0 ? colonIndex : (slashIndex > 0 ? slashIndex : withoutProtocol.length());
            return withoutProtocol.substring(0, endIndex);
        } catch (Exception e) {
            return url;
        }
    }
}
