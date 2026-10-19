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
| 4 | Stolen laptop with a live session | Reveal, `--out`, `--authorize off` and `requires_authorize` need Touch ID (user verification) | `ku run` of plain secrets does not need Touch ID |
| 5 | Phishing of login | Passkeys (origin-bound); Google login; invite-only | TOTP/recovery codes are phishable |
| 6 | Account takeover via Google account | Second factor required on every login | Compromised Google account + second factor |
| 7 | Leaked CI machine token | Scoped by grants, never reveal, never admin, never exceeds its owner; ~90 d; revoke by removing the machine | Token works until revoked/expired |
| 8 | Malicious or leaving member | Offboarding drill: disable, rotate what they could read | Anything they already saw |
| 9 | Coding agent leaks values | `SKILL.md`; low-value dev secrets; `requires_authorize`; rotate on leak | Accepted: an agent can print what `ku run` injects ([agents.md](agents.md)) |
| 10 | Audit tampering | Insert-only (grants/triggers), hash chain, `Verify`; denials audited | A DB owner can rewrite the whole chain; verification must be run and its head stored elsewhere |
| 11 | Brute force / abuse | Rate limits per IP/token/principal; generic auth errors | No per-account lockout (see ASVS open items) |
| 12 | Misconfigured proxy (plain HTTP, spoofed forwarding) | Server rejects non-HTTPS; trusts forwarded headers only from private ranges | Wrong network layout weakens IP-based limits |
| 13 | Lost master key | Offline age copy; KMS option | Lose both the key and the copy: data is gone |
| 14 | Lost second factor | Recovery codes; break-glass invite from the server terminal | Whoever has a server shell can mint an admin invite |
| 15 | Supply chain | Few audited dependencies; `govulncheck`, `gosec`, `staticcheck` in CI; distroless image | |

## Not defended

- **Reading server RAM** (root on the host, a debugger, a cold-boot dump, a compromised hypervisor): the master key, data
  keys and plaintext values exist in memory while serving.
- **A malicious admin with host or database access**: they can mint an admin invite, read process memory, replace the
  binary or rewrite the audit chain. Admin by role cannot read secrets through the API, but host access defeats that.
- Compromise of the user's own device while unlocked (screen scraping, keyloggers) and anything a secret's consumer does with it.
