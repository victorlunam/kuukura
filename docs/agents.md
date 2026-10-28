# Coding agents and kuukura

There is no MCP server and no credential proxy. An agent uses `ku run` with the user's own session, and
`ku secret list` to see which secrets exist. The [Kuukura skill](../skills/kuukura/SKILL.md) teaches discovery,
scoped execution, safe handling of file secrets, and stopping on access or confirmation errors.

## Install the skill

Requires Node.js and npm compatible with the [skills CLI](https://skills.sh/docs/cli). From the project where
you use your coding agent:

```sh
npx skills add victorlunam/kuukura --skill kuukura
```

Choose your agent in the installer, or specify one:

```sh
npx skills add victorlunam/kuukura --skill kuukura --agent claude-code
npx skills add victorlunam/kuukura --skill kuukura --agent codex
```

Installation is project-local by default. Add `--global` to make it available across projects. Review the
skill before installing. It installs instructions only, not `ku`, a server, credentials, grants or a session.
Install the [CLI](install.md) separately, configure a profile, sign in, and link your app yourself before
asking an agent to use secrets. Never include credentials in the installation command.

The source is `skills/kuukura/SKILL.md`, so installing does not copy the server or website into your project.
Discover it on [skills.sh](https://skills.sh/victorlunam/kuukura/kuukura).

## Versions and updates

The skill shares Kuukura's release tags: the Git tag is its version, not a separately maintained frontmatter
number. The default install follows the repository's default branch and may include unreleased changes.
For a released snapshot, choose a tag from [Releases](https://github.com/victorlunam/kuukura/releases), set
`KUUKURA_TAG` to that exact tag, and install:

```sh
npx skills add "https://github.com/victorlunam/kuukura/tree/${KUUKURA_TAG}/skills/kuukura" --skill kuukura
```

Use the same command with a different tag to upgrade or roll back a pinned installation. Do not move published
tags. For stronger source immutability, use a full commit SHA instead of a tag in the URL. Commit the generated
`skills-lock.json` when sharing project skills; review skill and lockfile diffs during upgrades. A lockfile
records installed content but is not a substitute for selecting an explicit source ref.

For installations tracking the default branch:

```sh
npx skills check
npx skills update kuukura
```

Remove with `npx skills remove kuukura` (add `--global` for a global installation).
New releases also attach `kuukura-skill.tar.gz`, containing only `kuukura/SKILL.md`, to the GitHub release;
its SHA-256 is in `checksums.txt` and is covered by the release's artifact attestation. Releases made before
this packaging change do not have that asset or the new skill path; inspect their source before pinning them.

### Publishing and maintenance

There is no separate npm package or `skills publish` step. The public GitHub repository is the distribution
source. [skills.sh's FAQ](https://skills.sh/docs/faq) says directory discovery happens automatically through
installation telemetry; listing and ranking are not guaranteed immediately after pushing a commit.
`DISABLE_TELEMETRY=1` or `DO_NOT_TRACK=1` disables telemetry and security-audit requests in the skills CLI.

Maintainers update the skill, this guide and the Unreleased changelog together. CI checks the skill's format
and safety instructions. A normal Kuukura release tag versions the skill and packages the download through
[release.yml](../.github/workflows/release.yml); no second release counter or registry credential is needed.

## Accepted residual risk

`ku run` puts values in the child process's environment (and file secrets in a private temp file). An agent that
runs a command can make that command print its environment, or read the temp file, and so can see or leak the values.
The skill asks agents not to; nothing technical stops a determined or confused agent. Revealing a value by hand
(`ku secret get --reveal`) needs a confirmation with your passkey or authenticator app, which an
agent cannot give, but `ku run` does not.

## What to do about it

- Give agents **low-value dev secrets** only: a dev tag set, test API keys, sandbox credentials. Keep production tags out
  of the folders where agents work (grants are per person, so use a separate identity or machine for agent work).
- Treat anything an agent could print as exposed if a transcript leaks. **Rotate on leak** (`ku secret revoke`, then `ku secret set`).
- Mark sensitive secrets `requires_authorize` (`ku secret update NAME --authorize on`): `ku run` then needs a confirmation
  (passkey or authenticator app) that an agent cannot provide.
- Machines (CI) can never confirm and never reveal; for agents prefer a person's session with narrow grants.
