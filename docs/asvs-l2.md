# OWASP ASVS 5.0.0 Level 2: self-review checklist

Status: **draft for the reviewer**. It is organized by the chapters of OWASP ASVS 5.0.0. Each row is a theme with our
control and where to verify it; it is not yet mapped to individual requirement IDs (do that pass against the published
ASVS 5.0.0 text and record the ID next to each row). Status: **Met** (implemented and tested), **Partial**, **Open** (known gap), **N/A**.
Do this review before real secrets go in, together with [threat-model.md](threat-model.md).
Code paths in the Evidence column are under [`internal/`](../internal) unless they start with `apps/`.

| Chapter | Theme | Our control | Evidence | Status |
|---|---|---|---|---|
| V1 Encoding and sanitization | HTML output encoding | Pages use `html/template`; strict CSP (`default-src 'none'`, nonce for the one inline script/style) | `apps/ku-server/api/page.go`, `TestPagesAreLockedDown` | Met |
| | SQL injection | Every query is parameterized; the few dynamic fragments are fixed column names | `storage/`, `secrets/`, gosec in CI | Met |
| | OS command injection | The server runs no commands; the CLI runs only the user's own command | | Met |
| V2 Validation and business logic | Input validation | Names `^[A-Z0-9_]{1,128}$`, tags `^[a-z0-9._-]{1,64}$` (max 10), value limits 64 KB / 1 MB, strict JSON (unknown fields rejected), 2 MB body limit | `secrets/`, `storage/tags.go`, `apps/ku-server/api/request.go`, `apps/ku-server/api/server.go`, `TestLimitsAndValidation` | Met |
| | Business rules enforced server-side | Last admin protected; clash check all-or-nothing; machines never admin/reveal | `identity/`, `secrets/update.go`, tests | Met |
| | Anti-automation | In-process token buckets: 10/min per IP (login/invite/unauthenticated), 300/min per token, 10/min per principal for reveal | `apps/ku-server/api/ratelimit.go`, `TestRateLimits` | Met |
| V3 Web frontend security | CSP, no external resources, no framing | CSP, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options`, HSTS | `apps/ku-server/api/page.go`, `apps/ku-server/api/middleware.go` | Met |
| | CSRF | No cookies; every state-changing call needs a bearer token in `Authorization` | | N/A by design |
| V4 API and web service | Content types, errors | JSON only; RFC 9457 problem+json, no internals | `apps/ku-server/api/problem.go`, `TestProblemJSONAndTransport` | Met |
| | Authorization at every endpoint | Auth middleware on all but login/page/health routes; deny by default; each denial audited | `apps/ku-server/api/routes.go`, `apps/ku-server/api/middleware.go`, `TestSecretsOverHTTP` | Met |
| | Values only in bodies | No value in URLs/query strings; `Cache-Control: no-store` everywhere | `docs/api.md` | Met |
| V5 File handling | Uploaded files | File secrets are opaque bytes (max 1 MB), stored encrypted, base name only, never executed or served as a page | `secrets/set.go` | Met |
| V6 Authentication | Strong, phishing-resistant second factor | WebAuthn passkey with user verification required; TOTP fallback; 10 single-use recovery codes stored hashed | `auth/`, `auth/login_test.go` | Met |
| | Credential recovery | `ku-server user invite` / `user reset-factors` (server terminal only, 15 min, single use, audited under the host principal); recovery codes | `identity/host.go`, `apps/ku-server/user.go`, `TestResetFactorsByHost` | Met |
| | Brute-force resistance | Per-IP limit on all login endpoints; mid-login tokens expire in 5 min; no per-account lockout | | Partial (consider per-account failure counter) |
| | TOTP replay | A code's 30 s step is spent on use, at sign-in and for confirmations (`last_used_at` guard, atomic) | `auth/totp.go`, `TestInviteTOTPEnrollmentAndLogin` | Met |
| | Recovery code storage | SHA-256 of an 80-bit random code | `auth/recovery.go` | Met |
| V7 Session management | Token generation/storage | 256-bit random `ku_` tokens, only SHA-256 stored, constant-time compare | `auth/tokens.go`, `TestTokenLifecycle` | Met |
| | Timeouts, logout, revocation | 8 h absolute, 1 h idle (server-enforced), logout and disable revoke; machine keys ~90 d | `auth/tokens_test.go`, `TestWorkspaceAdminAndMachines` | Met |
| | Client storage | System keychain first (macOS Keychain, Windows Credential Manager, Linux Secret Service); only when there is none, a private file (0600, never config.toml, never both places). Sessions last 8 h, revocable on the server | `apps/ku/store.go`, `store_test.go`, `docs/install.md` | Partial (the file fallback is not encrypted; macOS uses the login keychain, not the data protection keychain, which needs a signed binary) |
| V8 Authorization | Deny by default, least privilege | Grants (`read`/`write` on tag sets) only; admin role gives no secret access; machine = own grants AND owner's | `access/`, tests | Met |
| | Step-up for sensitive actions | A confirmation with the account's passkey (user verification) or authenticator app; single-use, 60 s, bound to principal/purpose/selector; machines never | `auth/stepup_test.go`, `TestConfirmationGates`, `TestConfirmationPageSaysWhatItConfirms` | Met |
| V9 Self-contained tokens | | Tokens are opaque, not JWTs | | N/A |
| V10 OAuth and OIDC | Code flow + PKCE, state, nonce, `email_verified`, ID token verification | `auth/provider.go`, `auth/login.go`; CLI uses its own localhost PKCE | tests (fake provider); real Google invite + passkey enrollment run by hand on localhost (2026-10-19) | Met (the Google path is not exercised in CI) |
| | Redirect handling | The CLI callback binds `127.0.0.1`, checks `state`; the CLI never follows redirects with a token | `apps/ku/cmd_login.go`, `apps/ku/main.go` | Met |
| V11 Cryptography | Standard primitives only | AES-256-GCM, 96-bit random nonces, per-version random DEK, AAD with domain separation, SHA-256 | `keys/`, `keys/keys_test.go` | Met |
| | Key management | Master key in memory only (stored in a key file outside the database and data volume, an env var or KMS; `key show` prints it once per version for a backup); the server refuses to start with a key that cannot open the data; rotation by rewrap (to a new key version, or to a new KMS key: each row keeps the ARN it was wrapped under until rewrapped); KMS option; DEKs cleared after use. No migration between the manual and KMS providers | `keys/`, `masterkey/`, `secrets/rotate.go`, `secrets/keycheck.go`, runbook | Met (switching providers is unsupported) |
| | Nonce uniqueness | Random 96-bit per encryption under a fresh DEK | | Met |
| | Fuzzing | `FuzzOpen` (a forged payload must never open) | `keys/keys_test.go` | Met |
| V12 Secure communication | TLS | HTTPS required (`https-required` otherwise); TLS terminates at your proxy | `TestProblemJSONAndTransport` | Met (depends on proxy config) |
| | Trust of forwarded headers | Only from private/loopback peers | `apps/ku-server/api/server.go` | Met (check your network layout) |
| V13 Configuration | Fail fast, no secrets in code/logs | Validated at startup; secrets via Docker secret files; values never in errors | `apps/ku-server/config.go`, tests | Met |
| | Secure defaults | Distroless non-root image, read-only secrets, `/data` volume | `Dockerfile` | Met |
| | Dependency hygiene | `govulncheck`, `gosec`, `staticcheck` (pinned versions), `go vet` required in CI; actions pinned by commit; Dependabot for actions and Go modules | `.github/workflows/ci.yml`, `.github/dependabot.yml` | Met |
| | Release integrity | Build provenance for the CLI archives and the image, keyless cosign signature and SBOM for the image, OpenSSF Scorecard | `.github/workflows/release.yml`, `scorecard.yml`, [deploy.md](deploy.md#verifying-a-release) | Partial (only as good as the user verifying them; the macOS signature depends on the signing secrets) |
| V14 Data protection | Secrets at rest | Envelope encryption; no hash/plaintext columns; TOTP secrets encrypted under the master key | `secrets/`, `auth/factors.go` | Met |
| | Values never in logs/errors/audit | Tests assert a fake value never appears in logs, audit rows, list output, errors | `TestSecretsOverHTTP`, `TestMaskingEverywhere` | Met |
| | Cache control | `no-store` on all responses | | Met |
| V15 Secure coding and architecture | Minimal dependencies, no custom crypto | Stdlib crypto + go-webauthn, go-oidc, pquerna/otp, Echo, pgx, modernc sqlite | `go.mod` | Met |
| | Concurrency | Audit appends are serialized (advisory lock / single writer); unique `prev_hash` keeps the chain linear; writers of one secret take a row lock, and losing a race on a unique index is a retryable clash, not an error | `audit/audit.go`, `secrets/`, `TestConcurrent*` | Met |
| | In-memory login state | Login/step-up/CLI-code state lives in process memory; a restart drops in-flight logins | `auth/ttl.go` | Partial (fine for one instance) |
| V16 Logging and error handling | Audit trail | Append-only, hash-chained audit log (Postgres grants / SQLite triggers); denials audited; `Verify` detects edits and deletions | `audit/`, tests | Met |
| | Structured logs, no sensitive data | JSON access logs with route, status, timing; panics logged without values | `apps/ku-server/api/middleware.go` | Met |
| | Audit verification | `ku-server audit verify` recomputes the chain and prints rows and head hash; the server does not run it by itself, so the operator schedules it and stores the head elsewhere ([runbook](runbook-key-rotation-drill.md)) | `apps/ku-server/audit.go`, `TestAuditVerify` | Partial (no built-in schedule or alert) |
| V17 WebRTC | | Not used | | N/A |

## Open items to decide before real secrets

1. (closed) TOTP code replay: a code now works once.
2. Per-account lockout / failed-login counter (currently per-IP rate limits only).
3. Scheduling `audit verify` and deciding where its failure alerts and where the head hash is kept (the command exists; the schedule is the operator's).
4. Restrict step-up/enrollment to platform authenticators (`authenticatorAttachment=platform`) if hardware keys should not count.
5. Move the macOS token to the data protection keychain once the CLI is signed with the needed entitlement.
6. Repeat the real Google + Touch ID run on a staging domain over HTTPS (done once on localhost, see [local-testing.md](local-testing.md)).
