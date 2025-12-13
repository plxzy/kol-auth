package dev.kol.auth.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kol.auth.core.dto.ErrorResponse;
import dev.kol.auth.core.dto.LoginRequest;
import dev.kol.auth.core.dto.LogoutRequest;
import dev.kol.auth.core.dto.RefreshRequest;
import dev.kol.auth.core.dto.RegisterRequest;
import dev.kol.auth.core.service.AuthException;
import dev.kol.auth.core.service.AuthService;
import dev.kol.auth.core.service.PasswordHasher;
import dev.kol.auth.core.service.TokenService;
import dev.kol.auth.core.tokens.TokenConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.flywaydb.core.Flyway;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.function.Function;

/**
 * Minimal HTTP server exposing /auth/* endpoints.
 */
public class AuthServerMain {
    public static void main(String[] args) throws IOException {
        AuthServerConfig config = AuthServerConfig.fromEnv();
        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

        TokenConfig tokenConfig = config.tokenConfig();
        PasswordHasher passwordHasher = new Argon2PasswordHasher(config.hashingConfig());
        AuthService authService = buildAuthService(config, tokenConfig, passwordHasher);

        HttpServer server = HttpServer.create(new InetSocketAddress(config.port()), 0);
        registerRoutes(server, mapper, authService);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.printf("auth-server listening on http://localhost:%d%n", config.port());
    }

    private static AuthService buildAuthService(AuthServerConfig config, TokenConfig tokenConfig, PasswordHasher passwordHasher) {
        String storage = System.getenv("AUTH_STORAGE");
        boolean useDb = storage == null || storage.isBlank() || !"inmemory".equalsIgnoreCase(storage);

        if (useDb) {
            JdbcDatabase db = new JdbcDatabase(config.dbUrl(), config.dbUser(), config.dbPassword());
            if (flywayMigrateOnStart()) {
                String migrationsPath = java.nio.file.Files.exists(java.nio.file.Path.of("migrations"))
                        ? "migrations"
                        : "auth-server/migrations";
                Flyway flyway = Flyway.configure()
                        .dataSource(config.dbUrl(), config.dbUser(), config.dbPassword())
                        .locations("filesystem:" + migrationsPath)
                        .schemas("auth")
                        .load()
                        ;
                if (flywayRepairOnStart()) {
                    flyway.repair();
                }
                flyway.migrate();
            }
            TokenService tokenService = new JdbcTokenService(db, tokenConfig);
            return new JdbcAuthService(db, tokenService, passwordHasher);
        }

        // Fallback for local development.
        TokenService tokenService = new JwtTokenService(tokenConfig);
        return new InMemoryAuthService(tokenService, passwordHasher);
    }

    private static boolean flywayMigrateOnStart() {
        String value = System.getenv("AUTH_FLYWAY_MIGRATE_ON_START");
        if (value == null || value.isBlank()) return true;
        return "true".equalsIgnoreCase(value) || "1".equals(value) || "yes".equalsIgnoreCase(value);
    }

    private static boolean flywayRepairOnStart() {
        String value = System.getenv("AUTH_FLYWAY_REPAIR_ON_START");
        if (value == null || value.isBlank()) return false;
        return "true".equalsIgnoreCase(value) || "1".equals(value) || "yes".equalsIgnoreCase(value);
    }

    private static void registerRoutes(HttpServer server, ObjectMapper mapper, AuthService authService) {
        server.createContext("/auth/login", jsonPost(mapper, body -> new Response(200, authService.login((LoginRequest) body)), LoginRequest.class));
        server.createContext("/auth/register", jsonPost(mapper, body -> new Response(201, authService.register((RegisterRequest) body)), RegisterRequest.class));
        server.createContext("/auth/refresh", jsonPost(mapper, body -> new Response(200, authService.refresh((RefreshRequest) body)), RefreshRequest.class));
        server.createContext("/auth/logout", jsonPost(mapper, body -> {
            authService.logout((LogoutRequest) body);
            return new Response(204, null);
        }, LogoutRequest.class));
        server.createContext("/auth/wallet", jsonGet(mapper, () -> new Response(200, authService.walletStatus())));

        // Deprecated launcher aliases
        server.createContext("/launcher/login", jsonPost(mapper, body -> new Response(200, authService.login((LoginRequest) body)), LoginRequest.class));
        server.createContext("/launcher/register", jsonPost(mapper, body -> new Response(201, authService.register((RegisterRequest) body)), RegisterRequest.class));
        server.createContext("/launcher/refresh", jsonPost(mapper, body -> new Response(200, authService.refresh((RefreshRequest) body)), RefreshRequest.class));
    }

    private static HttpHandler jsonPost(ObjectMapper mapper, Function<Object, Response> handler, Class<?> bodyType) {
        return exchange -> {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                respondWithError(exchange, mapper, 405, "method_not_allowed", "Use POST");
                return;
            }
            try (InputStream input = exchange.getRequestBody()) {
                Object body = mapper.readValue(input, bodyType);
                Response response = handler.apply(body);
                sendResponse(exchange, mapper, response);
            } catch (JsonProcessingException e) {
                respondWithError(exchange, mapper, 400, "invalid_json", e.getOriginalMessage());
            } catch (AuthException e) {
                respondWithError(exchange, mapper, e.statusCode(), "auth_error", e.getMessage());
            } catch (Exception e) {
                respondWithError(exchange, mapper, 500, "server_error", "Unexpected error");
            }
        };
    }

    private static HttpHandler jsonGet(ObjectMapper mapper, SupplierWithException<Response> supplier) {
        return exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                respondWithError(exchange, mapper, 405, "method_not_allowed", "Use GET");
                return;
            }
            try {
                Response response = supplier.get();
                sendResponse(exchange, mapper, response);
            } catch (AuthException e) {
                respondWithError(exchange, mapper, e.statusCode(), "auth_error", e.getMessage());
            } catch (Exception e) {
                respondWithError(exchange, mapper, 500, "server_error", "Unexpected error");
            }
        };
    }

    private static void sendResponse(HttpExchange exchange, ObjectMapper mapper, Response response) throws IOException {
        int status = response.statusCode();
        Object body = response.body();
        if (body == null || status == 204) {
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
            return;
        }
        byte[] bytes = mapper.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
        exchange.close();
    }

    private static void respondWithError(HttpExchange exchange, ObjectMapper mapper, int status, String error, String message) throws IOException {
        ErrorResponse errorResponse = new ErrorResponse(error, message);
        byte[] payload = mapper.writeValueAsBytes(errorResponse);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(payload);
        }
        exchange.close();
    }

    private record Response(int statusCode, Object body) {
    }

    @FunctionalInterface
    private interface SupplierWithException<T> {
        T get() throws Exception;
    }
}
