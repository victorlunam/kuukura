# Coding agents and kuukura

There is no MCP server and no credential proxy. An agent uses `ku run` with the user's own session, and `ku secret list`
to see which secrets exist. `SKILL.md` in the repo root teaches this: use `ku run`, never `ku secret get --reveal`, never
print, echo or log values.

## Accepted residual risk

`ku run` puts values in the child process's environment (and file secrets in a private temp file). An agent that
runs a command can make that command print its environment, or read the temp file, and so can see or leak the values.
`SKILL.md` asks agents not to; nothing technical stops a determined or confused agent. Revealing a value by hand
(`ku secret get --reveal`) needs a confirmation with your passkey or authenticator app, which an
agent cannot give, but `ku run` does not.

## What to do about it

- Give agents **low-value dev secrets** only: a dev tag set, test API keys, sandbox credentials. Keep production tags out
  of the folders where agents work (grants are per person, so use a separate identity or machine for agent work).
- Treat anything an agent could print as exposed if a transcript leaks. **Rotate on leak** (`ku secret revoke`, then `ku secret set`).
- Mark sensitive secrets `requires_authorize` (`ku secret update NAME --authorize on`): `ku run` then needs a confirmation
  (passkey or authenticator app) that an agent cannot provide.
- Machines (CI) can never confirm and never reveal; for agents prefer a person's session with narrow grants.
