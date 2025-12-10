# Kol — Security Checklist (Auth)

This file is the canonical security checklist and high-level guidance for auth-core, auth-server, and the launcher.

## Goals
- Strong password storage (Argon2id).
- Short-lived access tokens & server-controlled refresh tokens (rotating).
- Enforce TLS & safe secret handling.
- Protect local launcher secrets via OS keyring.
- Provide revocation, audit, rate-limiting, and wallet verification.

---

## Crypto & hashing
- Use **Argon2id** for password hashing.
    - Recommended defaults: time=3, memory=65536 KB (64 MB), parallelism=1.
    - Allow configurable parameters through env/config.
- Optionally use a server-side **pepper** from secret manager (not in repo).
- Never log password material.

## JWT & tokens
- Access tokens: **JWT RS256** (or ECDSA P-256) signed by server private key.
    - Access TTL default: **900s** (15 minutes).
    - Include `sub, username, kolUuid, iat, exp, iss, aud`.
- Refresh tokens: **opaque random tokens** stored server-side, long lived by default, **rotating** on `/auth/refresh`.
    - Refresh TTL default: **14 days**.
    - Implement rotation on use and detect reuse; on reuse revoke all sessions for the subject.

## Token revocation & sessions
- Store refresh tokens (sessions) with fields:
    - `token`, `uuid`, `username`, `issued_at`, `expires_at`, `revoked`, `last_used_at`, `device_info`, `rotated_from_token`.
- Support logout (revoke single token), and logout-all (revoke all tokens for uuid).
- Admin endpoint to list/revoke sessions recommended.

## Wallet ownership verification
- Use a challenge/nonce flow:
    - `GET /auth/wallet/challenge?addr=...` → server returns nonce (short TTL, e.g., 5 min).
    - Client signs nonce using private key and `POST /auth/wallet/verify` with signature.
    - Server verifies with ed25519 (Solana).
    - Persist `wallet` and `verified_at` only on successful verification.

## Launcher secret storage
- Use OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service).
- Store only refresh tokens in keyring; store non-sensitive session metadata (`username`, `kolUuid`, `wallet`) in `~/.kol/session.json`.
- Fallback: encrypted file with strict permissions (`0600`) if keyring unavailable.

## Transport / TLS
- Enforce HTTPS/TLS for every public auth endpoint (TLS1.2+ recommended - prefer 1.3).
- Do not allow credentials over plaintext HTTP.
- If cookies are used, set `Secure`, `HttpOnly`, `SameSite` appropriately.

## Rate limiting & brute force mitigation
- Rate-limit login/register endpoints per IP and per account. Example:
    - Per-IP: 200 requests/hour (adjust to infra).
    - Per-account: 5 failed login attempts per 15 minutes → temporary lockout or increasing backoff.
- Implement exponential backoff.

## Password policy & account safety
- Minimum password length: **12**.
- Reject known-bad/common passwords (common-password blacklist).
- Encourage/passively support 2FA/TOTP for sensitive accounts.

## Secrets & keys
- Private JWT signing keys stored outside VCS (env variable path or secrets manager).
- Rotate signing keys regularly (e.g., every 90 days) and provide JWKS for public key discovery.
- Do not commit private keys or peppers.

## Storage & data protection
- DB user uses least-privilege. Use DB-level encryption-at-rest when available.
- Do not store sensitive tokens in logs.
- Limit retention of login attempts & throttling logs (prune old data).

## Logging, monitoring & alerts
- Audit-log: login success/failure, logout, refresh usage/revocation, wallet verify attempts.
- Alert on suspicious patterns: reused refresh token, many failed logins, unusual geo/IP behavior.

## Testing & QA
- Unit tests for: Argon2 flows, JWT generation/verification, refresh rotation, revoke logic, wallet signature verification.
- Integration tests for: login → refresh → revoke flows, reuse-detection.
- CI should run security-sensitive unit/integration tests.

## Operational & deployment
- Config defaults in `config/auth.defaults.yml`. Use env vars to override in prod.
- Document key rotation steps and emergency key revocation.
- Require TLS on ingress; document cert management (Let's Encrypt, Vault, etc.).

## Migration & compatibility
- If renaming endpoints (e.g., `/launcher/*` → `/auth/*`) provide aliases and deprecation window.
- Provide migration scripts for sessions table renames and token format changes.

---

## Quick checklist for PRs
- Add tests for new token behavior before switching clients.
- Wire new code to defaults in `config/auth.defaults.yml`. Do not hardcode security parameters.
- Ensure code reads private keys/pepper from env/secret manager.
