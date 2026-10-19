---
name: kuukura
description: Use secrets from a kuukura vault safely. Use when a command needs API keys, tokens, certificates or env vars, or when asked which secrets exist.
---

# kuukura secrets

Secrets live in a vault. You run commands *with* them; you never read them.

## Do

- See what exists (names, versions, tags only, never values):
  `ku secret list` or `ku secret list app:shop env:dev`
- Run a command with secrets injected as env vars (file secrets become a path in the env var):
  `ku run env:dev -- npm run dev`
  The folder is linked to an app, so `app:<app>` is added for you. If you get "not linked", ask the user to run `ku link <app>`.
- If a name matches several secrets, add a tag as the error suggests, for example `ku run env:dev -- npm run dev`.
- If a secret is "blocked" or you are "not permitted", stop and tell the user. Do not look for another way in.

## Never

- Never run `ku secret get --reveal` or `ku secret get --out`. They need the user's own confirmation (passkey or authenticator code) and are for humans.
- Never print, echo, log, write to a file, or paste a secret value anywhere: not in output, commit messages, issues, or chat. That includes `env`, `printenv`, `echo $NAME`, debug logging of the environment, and `cat` on injected files.
- Never put a value in a command line, a URL, a config file, or a test fixture. Use `ku run`.
- Never run `ku secret set`, `update`, `revoke`, `archive` or any `ku workspace` command unless the user explicitly asks.

If a value leaks (for example it showed up in a transcript), tell the user right away so they can rotate it.
