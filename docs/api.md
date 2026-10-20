# kuukura API

All values in this document are FAKE examples. HTTPS is required (the server trusts `X-Forwarded-Proto` and
`X-Forwarded-For` only from private network ranges, i.e. the reverse proxy). Authenticated calls send
`Authorization: Bearer ku_...`. JSON bodies are strict: unknown fields are rejected. Values only travel in
POST/PATCH bodies and responses, never in URLs. Responses that carry a value, and every other response, are
`Cache-Control: no-store`.

## Errors

RFC 9457 `application/problem+json`, with a stable `code` (kebab-case; the CLI maps every one to plain copy) and a
sentence-case `title`, and optional `items` (the secrets or identities involved, never values). The table below is the
whole list: the server builds every error from one table, and the CLI's tests walk it:

```json
{ "type": "/problems/blocked", "title": "Secret is blocked", "status": 409,
  "detail": "blocked until a new value is saved", "instance": "urn:uuid:5b0c...",
  "code": "blocked", "items": ["STRIPE_KEY app:shop env:prod"] }
```

| status | code | meaning |
|---|---|---|
| 400 | `invalid-request` | malformed body, bad name or tag, empty value, too large |
| 400 | `needs-one` | `--name` rename needs exactly one secret |
| 400 | `https-required` | request was not HTTPS |
| 401 | `unauthorized` | any authentication failure (always generic) |
| 403 | `forbidden` | not permitted (deny by default; every denial is audited) |
| 403 | `step-up-required` | a confirmation with the account's passkey or authenticator app is needed (see Step-up) |
| 403 | `factor-required` | `POST /auth/stepup` on an account with no passkey and no authenticator app |
| 404 | `not-found` | nothing matches, archived, or a secret the caller may not read (indistinguishable) |
| 404 | `confirmation-expired` | the confirmation request is unknown, expired, or was lost in a server restart; run the command again |
| 409 | `needs-confirmation` | `POST /secrets/versions` without `create` and no exact match |
| 409 | `ambiguous` | several secrets match; `items` lists them |
| 409 | `blocked` | current version is compromised; `items` names them |
| 409 | `clash` | name + tags would collide; `items` lists the clashes; nothing changed |
| 409 | `kind-mismatch`, `conflict`, `last-admin` | |
| 409 | `last-factor` | removing the account's only passkey or authenticator app |
| 405 | `method-not-allowed` | |
| 413 | `too-large` | body over 2 MB |
| 429 | `quota-exceeded` | rate limit; has `Retry-After` and `RateLimit: limit=10, remaining=0, reset=6` |
| 500 | `internal` | nothing else is exposed |

Rate limits (in-process token bucket): unauthenticated, login, token exchange and invite endpoints 10/min per IP;
the confirmation page and its calls (`GET /stepup`, `POST /stepup/{id}/...`) have their own bucket, 60/min per IP,
because one confirmation is several calls; authenticated 300/min per token; `POST /secrets/reveal` 10/min per
principal. The error body's `Content-Type` is `application/problem+json`.

## Selectors

`{ "name": "STRIPE_KEY", "tags": ["app:shop", "env:prod"] }`. Name optional (uppercased, `^[A-Z0-9_]{1,128}$`),
tags optional and ANDed (`key:value`, each part `^[a-z0-9._-]{1,64}$`, max 10, one value per key on a secret).

## Login (CLI: browser + localhost PKCE)

1. CLI generates a verifier, listens on `127.0.0.1:<port>`, opens
   `GET /auth/login?cli_port=53682&cli_challenge=<base64url sha256(verifier)>&cli_state=<random>&cli_profile=work`.
   `cli_profile` is optional, display-only (`^[a-z0-9._-]{1,32}$`, anything else is ignored): the pages show it in the header.
   The link works once: after a completed sign-in, reopening it shows "already used" (410).
2. The server redirects to Google (code flow + PKCE, `email_verified` required). `GET /auth/callback` shows a
   page for the passkey, authenticator app code or recovery code (enrollment on first login).
3. On success the browser goes to `http://127.0.0.1:<port>/callback?code=<one-time>&state=<cli_state>`.
4. `POST /auth/token` `{ "code": "...", "verifier": "..." }` ->
   `{ "token": "ku_...", "expires_at": "2026-10-19T22:00:00Z" }`. Sessions: 8 h absolute, 1 h idle.
5. `POST /auth/logout` -> 204.

Invite acceptance: `GET /invite?token=ku_...` -> page -> `GET /auth/login?invite=ku_...` (no CLI parameters) ->
Google -> enrollment -> `/auth/done`. The invitee then runs `ku login`.

Pages' JSON endpoints (bearer = the short mid-login token the page holds): `POST /auth/mfa/passkey/{begin,finish}`,
`/auth/mfa/totp {code}`, `/auth/mfa/recovery {code}`, `/auth/enroll/passkey/{begin,finish}`,
`/auth/enroll/totp/begin`, `/auth/enroll/totp/confirm {code}`. Finish/confirm return
`{ "redirect": "...", "recovery_codes": ["ABCD-...", ...] }` (codes only on first enrollment, shown once).

## Step-up (a confirmation with the account's passkey or authenticator app)

For reveal, `--out`, `--authorize off` and running `requires_authorize` secrets. Machines never get one.
The confirmation uses whatever the account has set up: a **passkey** (user verification required) or an
**authenticator app code**. An authenticator code works once (its 30-second step is spent), across sign-in and
confirmations alike, so a code that was just used to sign in has to be replaced by the next one.

1. `POST /auth/stepup` `{ "purpose": "reveal" | "run" | "authorize_off" | "factor_add" | "factor_remove", "subject": "STRIPE_KEY env:prod", "profile": "work" }`
   (`profile` optional, display-only, same rules as `cli_profile`) ->
   201 `{ "id": "...", "url": "https://vault.example.com/stepup?id=...", "methods": ["passkey", "totp"] }`.
   `methods` lists what the account can use (the CLI words its prompt from it). `subject` is required (400 `invalid-request`,
   "Subject is required." when empty) and is the selector as `NAME tag tag` (name uppercased, tags sorted); for
   `factor_add` it is the kind, for `factor_remove` the credential id. The server keeps `purpose` and `subject` with the request.
2. The CLI opens `url`; the page says what is being confirmed ("Reveal STRIPE_KEY env:prod", "Run with ...",
   "Turn off confirmation for ...", "Add a passkey", "Add an authenticator app", "Remove a passkey or authenticator app"; the subject is
   shown as escaped plain text) and offers only the account's methods: a WebAuthn assertion
   (`POST /stepup/{id}/begin`, `/finish`) or an authenticator code (`POST /stepup/{id}/totp` `{ "code": "123456" }` -> 204).
3. The CLI polls `GET /auth/stepup/{id}` -> `{ "done": true }`.
4. The CLI repeats the original call with header `X-Step-Up: <id>`. The grant is single use, valid 60 s after
   the assertion, and bound to the principal, purpose and subject.

A wrong code or a failed assertion is audited like a failed sign-in: action `login_failed`, result `denied`, for the
request's principal, with metadata `{ "step": "confirmation", "purpose": "reveal" }`. A passkey whose sign count did
not advance (it may have been copied) still works, and is audited as `update` on the principal with metadata
`{ "factor": "passkey", "change": "clone_warning" }`.

## Account: factors (passkeys and authenticator apps)

Humans only (machines get 403). Adding or removing needs a confirmation (Step-up above) with purpose
`factor_add` (subject `passkey` or `totp`) or `factor_remove` (subject: the credential id), sent as `X-Step-Up`.

- `GET /account/factors` -> `{ "factors": [ { "id": "...", "kind": "passkey" | "totp", "added": "2026-10-19", "default": true } ] }`.
  Exactly one factor is the default: the first one enrolled, until the person moves the mark. The sign-in and
  confirmation pages offer its method first (every factor keeps working), and `methods` in the step-up response
  lists it first.
- `PATCH /account/factors/{id}` `{ "default": true }` -> 204. No confirmation is needed (it only changes the order).
  An id that is not the caller's is 404 `not-found`. Removing the default hands the mark to an earlier remaining factor.
- `POST /account/factors` `{ "kind": "passkey" | "totp", "profile": "work" }` -> 201 `{ "url": "https://.../account/add?id=..." }`.
  The link works once and lasts 10 minutes. `GET` on it shows a card with a "Continue" button and spends nothing,
  so a link preview or prefetch cannot burn it; the button (`go=1`) spends the link. The page then registers the
  new factor with a short enroll session that only accepts that kind; it is not a login and issues no recovery
  codes. Then the browser goes to `/account/added`. Removals of different factors are serialized per account, so
  two at once cannot leave it with none.
- `DELETE /account/factors/{id}` -> 204. The last remaining factor is refused with 409 `last-factor`; an id that is
  not the caller's is 404 `not-found`.

Each change is audited as `update` on the principal with metadata `{ "factor": "passkey", "change": "added" | "removed" | "default" }`.

## Secrets

`GET /secrets?name=&tags=app:shop,env:prod` (read) ->
```json
{ "secrets": [ { "name": "STRIPE_KEY", "version": 4, "tags": ["app:shop","env:prod"], "kind": "text",
                 "requires_authorize": false, "blocked": false } ] }
```
Never a value, not even masked.

`POST /secrets/versions` (write) - create a secret or add a version when name + tags match exactly:
```json
{ "name": "STRIPE_KEY", "tags": ["app:shop","env:prod"], "kind": "text",
  "value": "sk_test_FAKE_EXAMPLE", "create": true }
```
`kind` `text` (default, `value`, max 64 KB) or `file` (`value_base64` + `filename`, max 1 MB);
`"generate": true` replaces the value with a server-generated one that is never returned; `description` optional.
Without `create` and no exact match: 409 `needs-confirmation`. -> 201 (new) / 200
`{ "name": "STRIPE_KEY", "version": 5, "created": false }`.

`POST /secrets/reveal` (read + step-up `reveal`) - body is a selector selecting exactly one secret ->
`{ "name": "...", "version": 4, "kind": "text", "value": "sk_test_FAKE_EXAMPLE" }` (files:
`"filename"`, `"value_base64"`). Machines: 403.

`POST /run` (read; step-up `run` only if a selected secret has `requires_authorize`) - selector ->
`{ "secrets": [ { "name": "...", "version": 4, "kind": "text", "value": "..." } ] }`.
Fails closed: any blocked secret (409 `blocked`), or a name matching
several secrets (409 `ambiguous`). A secret the caller may not read is treated as if it did not exist (404
`not-found`, no tags or other details), so a person with a narrow grant cannot learn which other secrets exist; the
attempt is still audited as `denied`. One `read` audit row per secret. An empty selector is rejected.

`PATCH /secrets` (write) - metadata only, never a version, all or nothing:
```json
{ "selector": { "name": "BASE_ULR" }, "rename": "BASE_URL",
  "add_tags": ["env:qa"], "remove_tags": ["team:old"], "requires_authorize": true }
```
Adding `k:v` replaces an existing value for key `k`. `rename` needs exactly one selected secret.
`requires_authorize: false` needs step-up `authorize_off`. `{ "selector": {...}, "archived": true }` archives
(soft delete; name + tags become reusable). -> `{ "updated": ["STRIPE_KEY app:shop env:qa team:pay"] }`.

`POST /secrets/revoke` (write) - selector; marks each current version compromised ->
`{ "revoked": ["STRIPE_KEY app:shop env:prod"] }`. The secret is blocked until the next `POST /secrets/versions`.

## Workspace (admin only)

Being admin does not grant secret access.

- `POST /workspace/invites` `{ "email": "dev@example.com", "profile": "work" }` -> 201 `{ "link": "https://.../invite?token=ku_...&profile=work", "expires_at": "..." }`
  (`profile` is optional and display-only: the inviter's CLI profile name, offered to the invitee as the suggested name in
  `ku profile add <name> --url ...` on the final page. The invitee can name theirs anything; the URL is what matters.)
  (24 h, single use, bound to the email); `{ "name": "ci-deploy", "machine": true }` -> 201
  `{ "token": "ku_...", "expires_at": "..." }` (shown once; ~90 days).
- `PATCH /workspace/groups/{g}` `{ "add": ["dev@example.com"], "remove": [] }` -> 204 (creates the group on first use).
- `POST /workspace/grants` `{ "subject": "dev@example.com" | "group-name", "permission": "read" | "write", "tags": ["app:shop"] }` -> 201.
  A grant covers secrets whose tags contain all grant tags. `write` implies `read`. A machine can do only what
  both its own grants and its owner's grants allow.
- `DELETE /workspace/grants` `{ "subject": "...", "tags": ["app:shop"] }` -> 204.
- `PATCH /workspace/identities/{id}` `{ "status": "disabled" }` -> 204. `{id}` is the identity name (email or
  machine name). Ends its sessions and tokens (and its machines'). The last admin cannot be disabled.
  `{ "status": "active" }` -> 200 `{ "status": "active" | "invited" }` lifts a disable, with the rules of
  `ku-server user enable`: only a disabled identity can be enabled (409 `conflict` otherwise); a person who never
  enrolled a passkey or authenticator app goes back to `invited`; a machine whose owner is disabled stays disabled
  (409 `conflict`); tokens revoked by the disable stay revoked. Any other status is 400 `invalid-request`.
  Audited as `disable`, and as `update` with metadata `{ "change": "enabled", "status": "..." }`.
- `GET /workspace/audit?name=&tags=&limit=100` (`limit` 1 to 1000, default 100) ->
  `{ "rows": [ { "id": "...", "at": "2026-10-19T14:00:00Z", "principal": "dev@example.com", "action": "read",
  "secret": "STRIPE_KEY", "secret_id": "...", "version": 4, "result": "ok", "ip": "203.0.113.7",
  "target_type": "...", "target_id": "...", "metadata": {} } ] }`.

## Health

`GET /healthz` -> `200 ok` or `503 unavailable`. No auth, no details.
