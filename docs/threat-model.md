# Threat model walkthrough

Walk through this before real secrets go in. Decryption happens only on the server; the CLI is a secure channel.

## Assets

Secret values; the master key (KEK); session and machine tokens; passkeys/TOTP secrets; the audit log; the offline key copy.

## Actors

Members (read/write only what grants allow), admins (manage people, groups, grants; **no** secret access by role), machines (CI),
coding agents (run under a person's session), an outside attacker, a stolen laptop, a leaked CI token, a leaving employee.

## Trust boundaries

CLI <-> reverse proxy (TLS) <-> server <-> database. Google (login only). Browser pages for login/step-up.

## Threats and controls

| # | Threat | Control | Residual |
|---|---|---|---|
| 1 | Database theft (file, backup, SQL injection) | Only ciphertext + wrapped DEKs; AAD binds each blob to secret id, version and key id; master key not in DB | Attacker with DB **and** the master key reads everything |
| 2 | Swapping ciphertexts between rows | AAD includes secret id and version; wrap AAD has its own purpose byte | |
| 3 | Stolen session token | 8 h / 1 h idle; stored only as hash server-side; Keychain this-device-only; revoke by `ku workspace remove` | A live token can read what its user can read until it expires |
| 4 | Stolen laptop with a live session | Reveal, `--out`, `--authorize off` and `requires_authorize` need a confirmation with the account's second step: a passkey (user verification, e.g. Touch ID) or an authenticator code | `ku run` of plain secrets needs no confirmation |
| 5 | Phishing of login | Passkeys (origin-bound); Google login; invite-only | TOTP/recovery codes are phishable |
| 6 | Account takeover via Google account | Second factor required on every login | Compromised Google account + second factor |
| 7 | Leaked CI machine token | Scoped by grants, never reveal, never admin, never exceeds its owner; ~90 d; revoke by removing the machine | Token works until revoked/expired |
| 8 | Malicious or leaving member | Offboarding drill: disable, rotate what they could read | Anything they already saw |
| 9 | Coding agent leaks values | `SKILL.md`; low-value dev secrets; `requires_authorize`; rotate on leak | Accepted: an agent can print what `ku run` injects ([agents.md](agents.md)) |
| 10 | Audit tampering | Insert-only (grants/triggers; on Postgres the server refuses a role that owns the tables or can become their owner), hash chain, `ku-server admin verify-audit` (prints rows and head hash); denials audited | A DB owner can rewrite the whole chain or cut off its newest rows; the server does not verify by itself, so verification must be run on a schedule and its head stored elsewhere |
| 11 | Brute force / abuse | Rate limits per IP/token/principal; generic auth errors | No per-account lockout (see ASVS open items) |
| 12 | Misconfigured proxy (plain HTTP, spoofed forwarding) | Server rejects non-HTTPS; trusts forwarded headers only from private ranges | Wrong network layout weakens IP-based limits |
| 13 | Lost master key | Offline age copy; KMS option | Lose both the key and the copy: data is gone |
| 14 | Lost second factor | Recovery codes; break-glass invite from the server terminal | Whoever has a server shell can mint an admin invite |
| 15 | Supply chain | Few audited dependencies; `govulncheck`, `gosec`, `staticcheck` in CI at pinned versions, actions pinned by commit, Dependabot; distroless image; releases carry build provenance, a keyless cosign signature on the image and an SBOM ([verify them](deploy.md#verifying-a-release)) | Provenance proves where a build came from, not that the source is free of bugs; users who do not verify get no benefit |
| 16 | A secret named like a loader or interpreter hook turns `ku run` into code execution | `ku run` refuses to inject variable names that make a program load code or change how it starts (loader and interpreter hook names such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`); the run fails and names the secret | The refusal is a list of names: a hook it does not know is still injected. Creating such a secret needs a write grant |
| 17 | A confirmation approved without knowing what it authorizes | The step-up page shows what is being confirmed (the action and the secrets it covers) before it asks for the passkey or code; a confirmation is single use, 60 s, and bound to the principal, purpose and selector | A person can still approve without reading it |

## Not defended

- **Reading server RAM** (root on the host, a debugger, a cold-boot dump, a compromised hypervisor): the master key, data
  keys and plaintext values exist in memory while serving.
- **A malicious admin with host or database access**: they can mint an admin invite, read process memory, replace the
  binary or rewrite the audit chain. Admin by role cannot read secrets through the API, but host access defeats that.
- Compromise of the user's own device while unlocked (screen scraping, keyloggers) and anything a secret's consumer does with it.
