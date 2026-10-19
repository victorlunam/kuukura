# OWASP ASVS 5.0 Level 2: self-review checklist

Status: **draft for the reviewer**. It is organized by ASVS 5.0 chapter. Each row is a theme with our control and where
to verify it; it is not yet mapped to individual requirement IDs (do that pass against the published ASVS 5.0 text and
record the ID next to each row). Status: **Met** (implemented and tested), **Partial**, **Open** (known gap), **N/A**.
Do this review before real secrets go in, together with [threat-model.md](threat-model.md).

| Chapter | Theme | Our control | Evidence | Status |
|---|---|---|---|---|
| V1 Encoding and sanitization | HTML output encoding | Pages use `html/template`; strict CSP (`default-src 'none'`, nonce for the one inline script/style) | `api/pages.go`, `TestPagesAreLockedDown` | Met |
| | SQL injection | Every query is parameterized; the few dynamic fragments are fixed column names | `storage/`, `secrets/`, gosec in CI | Met |
| | OS command injection | The server runs no commands; the CLI runs only the user's own command | | Met |
| V2 Validation and business logic | Input validation | Names `^[A-Z0-9_]{1,128}$`, tags `^[a-z0-9._-]{1,64}$` (max 10), value limits 64 KB / 1 MB, strict JSON (unknown fields rejected), 2 MB body limit | `secrets/`, `storage/tags.go`, `api/server.go`, `TestLimitsAndValidation` | Met |
| | Business rules enforced server-side | Last admin protected; clash check all-or-nothing; machines never admin/reveal | `identity/`, `secrets/update.go`, tests | Met |
| | Anti-automation | In-process token buckets: 10/min per IP (login/invite/unauthenticated), 300/min per token, 10/min per principal for reveal | `api/ratelimit.go`, `TestRateLimits` | Met |
| V3 Web frontend security | CSP, no external resources, no framing | CSP, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options`, HSTS | `api/pages.go`, `api/server.go` | Met |
| | CSRF | No cookies; every state-changing call needs a bearer token in `Authorization` | | N/A by design |
| V4 API and web service | Content types, errors | JSON only; RFC 9457 problem+json, no internals | `api/problem.go`, `TestProblemJSONAndTransport` | Met |
| | Authorization at every endpoint | Auth middleware on all but login/page/health routes; deny by default; each denial audited | `api/server.go`, `TestSecretsOverHTTP` | Met |
| | Values only in bodies | No value in URLs/query strings; `Cache-Control: no-store` everywhere | `docs/api.md` | Met |
| V5 File handling | Uploaded files | File secrets are opaque bytes (max 1 MB), stored encrypted, base name only, never executed or served as a page | `secrets/secrets.go` | Met |
| V6 Authentication | Strong, phishing-resistant second factor | WebAuthn passkey with user verification required; TOTP fallback; 10 single-use recovery codes stored hashed | `auth/`, `auth/login_test.go` | Met |
| | Credential recovery | Break-glass admin invite (server terminal only, 15 min, single use); recovery codes | `identity/`, `cmd/ku-server/admin.go` | Met |
| | Brute-force resistance | Per-IP limit on all login endpoints; mid-login tokens expire in 5 min; no per-account lockout | | Partial (consider per-account failure counter) |
| | TOTP replay | A valid code can be reused inside its window | | Open |
| | Recovery code storage | SHA-256 of an 80-bit random code | `auth/factors.go` | Met |
| V7 Session management | Token generation/storage | 256-bit random `ku_` tokens, only SHA-256 stored, constant-time compare | `auth/tokens.go`, `TestTokenLifecycle` | Met |
| | Timeouts, logout, revocation | 8 h absolute, 1 h idle (server-enforced), logout and disable revoke; machine keys ~90 d | `auth/tokens_test.go`, `TestWorkspaceAdminAndMachines` | Met |
| | Client storage | macOS Keychain, this-device-only, never config files (default login keychain; data protection keychain needs signed entitlements) | `cmd/ku/keychain_darwin.go` | Partial |
| V8 Authorization | Deny by default, least privilege | Grants (`read`/`write` on tag sets) only; admin role gives no secret access; machine = own grants AND owner's | `access/`, tests | Met |
| | Step-up for sensitive actions | Passkey with user verification; single-use, 60 s, bound to principal/purpose/selector; machines never | `auth/login_test.go`, `TestTouchIDGates` | Met |
| V9 Self-contained tokens | | Tokens are opaque, not JWTs | | N/A |
| V10 OAuth and OIDC | Code flow + PKCE, state, nonce, `email_verified`, ID token verification | `auth/provider.go`, `auth/login.go`; CLI uses its own localhost PKCE | tests (fake provider) | Met (Google path not exercised in CI) |
| | Redirect handling | The CLI callback binds `127.0.0.1`, checks `state`; the CLI never follows redirects with a token | `cmd/ku/cmd_profile.go`, `cmd/ku/main.go` | Met |
| V11 Cryptography | Standard primitives only | AES-256-GCM, 96-bit random nonces, per-version random DEK, AAD with domain separation, age (scrypt) for the offline copy, SHA-256 | `keys/`, `keys/keys_test.go` | Met |
| | Key management | Master key in memory only; rotation by rewrap; KMS option | `keys/`, `secrets/rotate.go`, runbook | Met |
| | Nonce uniqueness | Random 96-bit per encryption under a fresh DEK | | Met |
| | Fuzzing | `FuzzParseAAD`, `FuzzOpen` | `keys/keys_test.go` | Met |
| V12 Secure communication | TLS | HTTPS required (`https-required` otherwise); TLS terminates at your proxy | `TestProblemJSONAndTransport` | Met (depends on proxy config) |
| | Trust of forwarded headers | Only from private/loopback peers | `api/server.go` | Met (check your network layout) |
| V13 Configuration | Fail fast, no secrets in code/logs | Validated at startup; secrets via Docker secret files; values never in errors | `cmd/ku-server/config.go`, tests | Met |
| | Secure defaults | Distroless non-root image, read-only secrets, `/data` volume | `Dockerfile` | Met |
| | Dependency hygiene | `govulncheck`, `gosec`, `staticcheck`, `go vet` required in CI | `.github/workflows/ci.yml` | Met |
| V14 Data protection | Secrets at rest | Envelope encryption; no hash/plaintext columns; TOTP secrets encrypted under the master key | `secrets/`, `auth/factors.go` | Met |
| | Values never in logs/errors/audit | Tests assert a fake value never appears in logs, audit rows, list output, errors | `TestSecretsOverHTTP`, `TestMaskingEverywhere` | Met |
| | Cache control | `no-store` on all responses | | Met |
| V15 Secure coding and architecture | Minimal dependencies, no custom crypto | Stdlib crypto + go-webauthn, go-oidc, age, pquerna/otp, Echo, pgx, modernc sqlite | `go.mod` | Met |
| | Concurrency | Audit appends are serialized (advisory lock / single writer); unique `prev_hash` keeps the chain linear | `audit/audit.go` | Met |
| | In-memory login state | Login/step-up/CLI-code state lives in process memory; a restart drops in-flight logins | `auth/ttl.go` | Partial (fine for one instance) |
| V16 Logging and error handling | Audit trail | Append-only, hash-chained audit log (Postgres grants / SQLite triggers); denials audited; `Verify` detects edits and deletions | `audit/`, tests | Met |
| | Structured logs, no sensitive data | JSON access logs with route, status, timing; panics logged without values | `api/server.go` | Met |
| | Audit verification job | There is no scheduled `Verify`; run it from a script or console | | Open |
| V17 WebRTC | | Not used | | N/A |

## Open items to decide before real secrets

1. TOTP code replay inside the 30 s window.
2. Per-account lockout / failed-login counter (currently per-IP rate limits only).
3. Periodic audit-chain verification (and where to alert).
4. Restrict step-up/enrollment to platform authenticators (`authenticatorAttachment=platform`) if hardware keys should not count.
5. Move the macOS token to the data protection keychain once the CLI is signed with the needed entitlement.
6. Exercise the real Google flow once end to end on a staging domain.
