# kol-auth

Gradle multi-project containing shared auth library (`auth-core`) and HTTP service (`auth-server`).

## Modules
- `auth-core` — domain models (User, Session, TokenPair), DTOs, and service interfaces. Publish to Maven local for consumers (`dev.kol:auth-core`).
- `auth-server` — minimal HTTP server exposing `/auth/*` endpoints. Uses in-memory storage today; swap in a real DB implementation later.

## Prereqs
- JDK 21
- Docker (for Postgres) if you want to run migrations locally
- `./gradlew` (wrapper included)

## Quick Start
1) Start dev DB (from `kol-platform`): `docker compose -f ../kol-platform/docker-compose.dev.yml up -d`.
2) Run migrations: `./gradlew :auth-server:flywayMigrate`.
3) Start server: `./gradlew :auth-server:run`.
4) Try endpoints:
   - `POST http://localhost:8080/auth/register`
   - `POST http://localhost:8080/auth/login`
   - `POST http://localhost:8080/auth/refresh`
   - `POST http://localhost:8080/auth/logout`

## Publishing `auth-core` locally
```
./gradlew :auth-core:publishToMavenLocal
```
This publishes `dev.kol:auth-core:0.1.0-SNAPSHOT`, which `kol-fabric` and `kol-launcher` can consume during local dev.

## Build & Test
- Build all: `./gradlew build`
- Run service only: `./gradlew :auth-server:run`
- Flyway migrations: `./gradlew :auth-server:flywayMigrate`

## Environment Variables
- `AUTH_DB_URL` (default `jdbc:postgresql://localhost:5432/kol_auth`)
- `AUTH_DB_USER` (default `kol_auth`)
- `AUTH_DB_PASSWORD` (default `kol_dev_password`)
- `AUTH_JWT_SECRET` (default `CHANGE_ME_SUPER_SECRET`)
- `AUTH_JWT_ISSUER` / `AUTH_JWT_AUDIENCE`
- `AUTH_ACCESS_TTL_SECONDS` / `AUTH_REFRESH_TTL_SECONDS`
- `ARGON2_TIME`, `ARGON2_MEMORY_KIB`, `ARGON2_PARALLELISM`

Defaults live in `config/auth.defaults.yml` and mirror `kol-platform/config/auth.defaults.yml`.

## OpenAPI
- Spec lives in `openapi/openapi.yml` (keep in sync with `kol-platform/openapi/auth.yaml`).

## Migrations
- Files live in `auth-server/migrations`.
- Schema creates `auth.users` and `auth.refresh_tokens`.
- Flyway plugin is configured to read DB creds from env/system properties; clean is disabled by default.

## Docker
Build a dev image (no secrets baked in):
```
cd auth-server
docker build -t kol-auth-server:dev .
docker run --env-file ../config/.env.local -p 8080:8080 kol-auth-server:dev
```

## Notes for AI Assistants
- Domain/types: `auth-core/src/main/java/dev/kol/auth/core`.
- HTTP handlers: `auth-server/src/main/java/dev/kol/auth/server/AuthServerMain.java`.
- Token logic: `auth-server/src/main/java/dev/kol/auth/server/JwtTokenService.java`.
- Replace `InMemoryAuthService` with a DB-backed implementation; reuse DTOs and interfaces.
- Keep secrets out of git; use `.env` files (git-ignored) or env vars.
