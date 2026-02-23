# Build stage
FROM gradle:9.2.1-jdk25 AS builder
WORKDIR /app
COPY . .
RUN gradle :auth-server:shadowJar --no-daemon -x test

# Runtime stage
FROM eclipse-temurin:25-jre
WORKDIR /app

# Copy the fat jar from builder
COPY --from=builder /app/auth-server/build/libs/*-all.jar app.jar

COPY --from=builder /app/auth-server/migrations auth-server/migrations

# Expose port
EXPOSE 8080

# Environment variables with defaults
ENV AUTH_DB_URL=jdbc:postgresql://postgres:5432/kol_auth \
    AUTH_DB_USER=kol_auth \
    AUTH_DB_PASSWORD=kol_dev_password \
    AUTH_JWT_SECRET=CHANGE_ME_SUPER_SECRET \
    AUTH_JWT_ISSUER=kol-auth \
    AUTH_JWT_AUDIENCE=kol-clients \
    AUTH_ACCESS_TTL_SECONDS=900 \
    AUTH_REFRESH_TTL_SECONDS=604800 \
    ARGON2_TIME=3 \
    ARGON2_MEMORY_KIB=65536 \
    ARGON2_PARALLELISM=4

ENTRYPOINT ["sh", "-c", "java -Xmx192m -XX:MaxMetaspaceSize=64m -XX:+UseContainerSupport -jar app.jar"]
