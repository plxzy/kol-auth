package org.cv.auth.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.cv.auth.IdentityIds;
import org.cv.auth.LauncherAuthService;
import org.cv.auth.LauncherDatabase;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;

final class AuthValidationServer {
    private static final ObjectMapper JSON = new ObjectMapper();

    private final LauncherAuthService authService;
    private final HttpServer server;
    private final String host;
    private final int port;

    private AuthValidationServer(LauncherAuthService authService, String host, int port) throws IOException {
        this.authService = Objects.requireNonNull(authService, "authService");
        this.host = host;
        this.port = port;
        InetSocketAddress address = new InetSocketAddress(host, port);
        this.server = HttpServer.create(address, 0);
        this.server.createContext("/kol-auth/validate", new ValidationHandler());
        this.server.createContext("/launcher/register", new RegisterHandler());
        this.server.createContext("/launcher/login", new LoginHandler());
        this.server.createContext("/launcher/logout", new LogoutHandler());
        this.server.createContext("/ping", exchange -> {
            byte[] payload = "pong".getBytes();
            exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            } finally {
                exchange.close();
            }
        });
    }

    static void launch(LauncherAuthService authService, String host, int port) throws Exception {
        AuthValidationServer server = new AuthValidationServer(authService, host, port);
        server.startBlocking();
    }

    private void startBlocking() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.stop(0);
            latch.countDown();
        }, "kol-auth-server-shutdown"));
        server.start();
        System.out.println("Kol auth validation server listening on " + host + ":" + port);
        System.out.println("Send POST requests to http://" + host + ":" + port + "/kol-auth/validate");
        latch.await();
    }

    private abstract class JsonHandler implements HttpHandler {
        @Override
        public final void handle(HttpExchange exchange) throws IOException {
            try {
                handleJson(exchange);
            } catch (Exception ex) {
                ex.printStackTrace(System.err);
                try {
                    byte[] payload = JSON.writeValueAsBytes(ApiError.of("server_error"));
                    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                    exchange.sendResponseHeaders(500, payload.length);
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(payload);
                    }
                } catch (Exception ignored) {
                }
            } finally {
                exchange.close();
            }
        }

        protected abstract void handleJson(HttpExchange exchange) throws IOException;

        protected <T> T readBody(HttpExchange exchange, Class<T> clazz) throws IOException {
            try {
                return JSON.readValue(exchange.getRequestBody(), clazz);
            } catch (Exception ex) {
                throw new BadRequestException("invalid_json", ex);
            }
        }

        protected void writeJson(HttpExchange exchange, int status, Object body) throws IOException {
            byte[] payload = JSON.writeValueAsBytes(body);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(status, payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        }

        protected void ensureMethod(HttpExchange exchange, String method) {
            if (!method.equalsIgnoreCase(exchange.getRequestMethod())) {
                throw new MethodNotAllowedException();
            }
        }

        protected String trimToNull(String value) {
            if (value == null) {
                return null;
            }
            String trimmed = value.trim();
            return trimmed.isEmpty() ? null : trimmed;
        }
    }

    private final class ValidationHandler extends JsonHandler {
        @Override
        protected void handleJson(HttpExchange exchange) throws IOException {
            try {
                ensureMethod(exchange, "POST");
                ValidationRequest request = readBody(exchange, ValidationRequest.class);
                ValidationResponse response = processRequest(request);
                writeJson(exchange, 200, response);
            } catch (MethodNotAllowedException ex) {
                writeJson(exchange, 405, ValidationResponse.invalid("method_not_allowed"));
            } catch (BadRequestException ex) {
                writeJson(exchange, 400, ValidationResponse.invalid(ex.reason()));
            } catch (Exception ex) {
                ex.printStackTrace(System.err);
                writeJson(exchange, 500, ValidationResponse.invalid("server_error"));
            }
        }

        private ValidationResponse processRequest(ValidationRequest request) throws Exception {
            if (request == null) {
                throw new BadRequestException("invalid_request");
            }
            String token = trimToNull(request.token());
            String username = trimToNull(request.username());
            String uuidRaw = trimToNull(request.kolUuid());
            if (token == null || username == null || uuidRaw == null) {
                throw new BadRequestException("missing_fields");
            }
            UUID providedUuid;
            try {
                providedUuid = UUID.fromString(uuidRaw);
            } catch (IllegalArgumentException ex) {
                throw new BadRequestException("invalid_uuid");
            }
            if (!authService.isRegistered(username)) {
                return ValidationResponse.invalid("unknown_user");
            }
            UUID expectedUuid = IdentityIds.offlineUuidForUsername(username);
            if (!expectedUuid.equals(providedUuid)) {
                return ValidationResponse.invalid("uuid_mismatch");
            }
            LauncherDatabase.SessionRecord session = authService.findSession(token);
            if (session == null) {
                return ValidationResponse.invalid("unknown_token");
            }
            if (session.revoked() || session.isExpired()) {
                return ValidationResponse.invalid("expired_token");
            }
            if (session.uuid() == null || !session.uuid().equals(providedUuid)) {
                return ValidationResponse.invalid("uuid_mismatch");
            }
            return new ValidationResponse(true, session.uuid().toString(), null);
        }
    }

    private final class RegisterHandler extends JsonHandler {
        @Override
        protected void handleJson(HttpExchange exchange) throws IOException {
            try {
                ensureMethod(exchange, "POST");
                RegisterRequest request = readBody(exchange, RegisterRequest.class);
                RegisterResponse response = processRequest(request);
                writeJson(exchange, 200, response);
            } catch (MethodNotAllowedException ex) {
                writeJson(exchange, 405, ApiError.of("method_not_allowed"));
            } catch (BadRequestException ex) {
                writeJson(exchange, 400, ApiError.of(ex.reason()));
            } catch (Exception ex) {
                ex.printStackTrace(System.err);
                writeJson(exchange, 500, ApiError.of("server_error"));
            }
        }

        private RegisterResponse processRequest(RegisterRequest request) throws Exception {
            if (request == null) {
                throw new BadRequestException("invalid_request");
            }
            String username = trimToNull(request.username());
            String password = trimToNull(request.password());
            if (username == null || password == null) {
                throw new BadRequestException("missing_fields");
            }
            if (authService.isRegistered(username)) {
                throw new BadRequestException("user_exists");
            }
            authService.registerUser(username, password);
            String wallet;
            try {
                wallet = authService.generateAndSaveWallet(username);
            } catch (Exception ex) {
                throw new BadRequestException("wallet_generation_failed_contact_support", ex);
            }
            String uuid = IdentityIds.offlineUuidForUsername(username).toString();
            return new RegisterResponse(true, uuid, wallet);
        }
    }

    private final class LogoutHandler extends JsonHandler {
        @Override
        protected void handleJson(HttpExchange exchange) throws IOException {
            try {
                ensureMethod(exchange, "POST");
                LogoutRequest request = readBody(exchange, LogoutRequest.class);
                LogoutResponse response = processRequest(request);
                writeJson(exchange, response.ok() ? 200 : 400, response);
            } catch (MethodNotAllowedException ex) {
                writeJson(exchange, 405, ApiError.of("method_not_allowed"));
            } catch (BadRequestException ex) {
                writeJson(exchange, 400, ApiError.of(ex.reason()));
            } catch (Exception ex) {
                ex.printStackTrace(System.err);
                writeJson(exchange, 500, ApiError.of("server_error"));
            }
        }

        private LogoutResponse processRequest(LogoutRequest request) {
            if (request == null) {
                throw new BadRequestException("invalid_request");
            }
            String token = trimToNull(request.token());
            if (token == null) {
                throw new BadRequestException("missing_token");
            }
            authService.revokeSession(token);
            return LogoutResponse.success();
        }
    }

    private final class LoginHandler extends JsonHandler {
        @Override
        protected void handleJson(HttpExchange exchange) throws IOException {
            try {
                ensureMethod(exchange, "POST");
                LoginRequest request = readBody(exchange, LoginRequest.class);
                LoginResponse response = processRequest(request);
                writeJson(exchange, response.ok() ? 200 : 401, response);
            } catch (MethodNotAllowedException ex) {
                writeJson(exchange, 405, ApiError.of("method_not_allowed"));
            } catch (BadRequestException ex) {
                writeJson(exchange, 400, ApiError.of(ex.reason()));
            } catch (Exception ex) {
                ex.printStackTrace(System.err);
                writeJson(exchange, 500, ApiError.of("server_error"));
            }
        }

        private LoginResponse processRequest(LoginRequest request) throws Exception {
            if (request == null) {
                throw new BadRequestException("invalid_request");
            }
            String username = trimToNull(request.username());
            String password = trimToNull(request.password());
            if (username == null || password == null) {
                throw new BadRequestException("missing_fields");
            }
            boolean verified = authService.verifyUser(username, password);
            if (!verified) {
                return LoginResponse.fail("invalid_credentials");
            }
            String token = authService.issueSessionToken(username);
            String wallet = null;
            try {
                wallet = trimToNull(authService.getUserWallet(username));
            } catch (IOException ignored) {
            }
            String uuid = IdentityIds.kolUuidForUsername(username).toString();
            return LoginResponse.success(username, uuid, token, wallet);
        }
    }

    private static final class MethodNotAllowedException extends RuntimeException {}

    private static final class BadRequestException extends RuntimeException {
        private final String reason;

        BadRequestException(String reason) {
            this(reason, null);
        }

        BadRequestException(String reason, Throwable cause) {
            super(reason, cause);
            this.reason = reason;
        }

        String reason() {
            return reason;
        }
    }

    public static record ValidationRequest(String token, String kolUuid, String username) {}

    public static record RegisterRequest(String username, String password) {}

    public static record RegisterResponse(boolean ok, String kolUuid, String wallet) {}

    public static record LoginRequest(String username, String password) {}
    public static record LogoutRequest(String token) {}

    public static record LoginResponse(boolean ok, String username, String kolUuid, String token, String wallet, String error) {
        static LoginResponse success(String username, String kolUuid, String token, String wallet) {
            return new LoginResponse(true, username, kolUuid, token, wallet, null);
        }

        static LoginResponse fail(String error) {
            return new LoginResponse(false, null, null, null, null, error);
        }
    }

    public static record ApiError(boolean ok, String error) {
        static ApiError of(String message) {
            return new ApiError(false, message);
        }
    }

    public static record ValidationResponse(boolean valid, String kolUuid, String message) {
        static ValidationResponse invalid(String message) {
            return new ValidationResponse(false, null, message);
        }
    }

    public static record LogoutResponse(boolean ok, String error) {
        static LogoutResponse success() {
            return new LogoutResponse(true, null);
        }
    }
}
