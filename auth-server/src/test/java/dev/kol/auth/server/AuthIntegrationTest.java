package dev.kol.auth.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kol.auth.core.dto.AuthResponse;
import dev.kol.auth.core.dto.LoginRequest;
import dev.kol.auth.core.dto.RefreshRequest;
import dev.kol.auth.core.dto.RegisterRequest;
import dev.kol.auth.core.service.AuthService;
import dev.kol.auth.core.service.PasswordHasher;
import dev.kol.auth.core.service.TokenService;
import dev.kol.auth.core.tokens.TokenConfig;
import com.sun.net.httpserver.HttpServer;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.Executors;
import java.lang.reflect.Method;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

class AuthIntegrationTest {

    private HttpServer server;

    @BeforeEach
    void setUp() throws Exception {
        int port = findRandomPort();
        RestAssured.port = port;
        RestAssured.baseURI = "http://localhost";

        // Manually assemble dependencies to avoid complex DI setup for this simple test
        AuthServerConfig envConfig = AuthServerConfig.fromEnv();
        AuthServerConfig config = new AuthServerConfig(
                envConfig.port(),
                envConfig.tokenConfig(),
                envConfig.hashingConfig(),
                envConfig.dbConfig(),
                AuthStorage.IN_MEMORY
        );
        TokenConfig tokenConfig = config.tokenConfig();
        TokenService tokenService = new JwtTokenService(tokenConfig);
        PasswordHasher passwordHasher = new Argon2PasswordHasher(config.hashingConfig());
        AuthService authService = new InMemoryAuthService(tokenService, passwordHasher);

        ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Use reflection to access the private registerRoutes method, or duplicate the routing logic.
        // Duplicating routing logic here is safer/easier than reflection on private static methods usually,
        // but let's try to invoke the main class's logic if possible or just manually register similar to main.
        // Ideally, AuthServerMain should expose a method to create the server/handler.
        // For now, let's copy the route registration logic from AuthServerMain (or use reflection).
        // Since AuthServerMain.registerRoutes is private static, let's use reflection to call it.
        Method registerRoutes = AuthServerMain.class.getDeclaredMethod("registerRoutes", HttpServer.class, ObjectMapper.class, AuthService.class);
        registerRoutes.setAccessible(true);
        registerRoutes.invoke(null, server, mapper, authService);

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private int findRandomPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    void shouldRegisterAndLoginUser() {
        RegisterRequest registerRequest = new RegisterRequest("testuser", "test@example.com", "password123");

        // Register
        given()
            .contentType(ContentType.JSON)
            .body(registerRequest)
        .when()
            .post("/auth/register")
        .then()
            .statusCode(201)
            .body("user.username", equalTo("testuser"))
            .body("user.email", equalTo("test@example.com"))
            .body("tokens.accessToken", notNullValue());

        // Login
        LoginRequest loginRequest = new LoginRequest("testuser", "password123");

        given()
            .contentType(ContentType.JSON)
            .body(loginRequest)
        .when()
            .post("/auth/login")
        .then()
            .statusCode(200)
            .body("user.username", equalTo("testuser"))
            .body("tokens.accessToken", notNullValue());
    }

    @Test
    void shouldFailLoginWithWrongPassword() {
        RegisterRequest registerRequest = new RegisterRequest("wrongpassuser", "wrong@example.com", "password123");
        given().contentType(ContentType.JSON).body(registerRequest).post("/auth/register").then().statusCode(201);

        LoginRequest loginRequest = new LoginRequest("wrongpassuser", "wrongpassword");

        given()
            .contentType(ContentType.JSON)
            .body(loginRequest)
        .when()
            .post("/auth/login")
        .then()
            .statusCode(401)
            .body("error", equalTo("auth_error"));
    }

    @Test
    void shouldRefreshToken() {
        RegisterRequest registerRequest = new RegisterRequest("refreshuser", "refresh@example.com", "password123");
        AuthResponse response = given()
            .contentType(ContentType.JSON)
            .body(registerRequest)
            .post("/auth/register")
            .then()
            .statusCode(201)
            .extract().as(AuthResponse.class);

        String refreshToken = response.tokens().refreshToken();

        RefreshRequest refreshRequest = new RefreshRequest(refreshToken);

        given()
            .contentType(ContentType.JSON)
            .body(refreshRequest)
        .when()
            .post("/auth/refresh")
        .then()
            .statusCode(200)
            .body("tokens.accessToken", notNullValue())
            .body("tokens.refreshToken", notNullValue()); // Should get a rotated refresh token
    }
}
