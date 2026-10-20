# Installing the CLI (macOS, Linux, Windows)

Download the archive for your system from the release page (`kuukura_<version>_<os>_<arch>.tar.gz`, or `.zip` for
Windows). It holds the same program twice: `kuukura` and the short name `ku`. Put it on your `PATH`.

```sh
ku --version
ku profile add work --url https://vault.example.com     # a profile = a server address
ku login
```

macOS: a signed binary keeps the same identity across versions, so the Keychain stops asking every time. Release
binaries are signed when the repository has the `MACOS_CERT_P12` and `MACOS_CERT_PASSWORD` secrets; otherwise the
maintainer runs `scripts/sign-macos.sh <tag>`. They are signed, not notarized: if Gatekeeper blocks a downloaded
copy, run `xattr -d com.apple.quarantine ku` once.

## Your passkeys and authenticator apps

The commands call them factors:

```sh
ku account factor list                 # what the account has
ku account factor add passkey          # or: add totp (an authenticator app)
ku account factor default <id>         # the one the sign-in and confirmation pages offer first
ku account factor remove <id>          # the id (or its start) from `list`; the last one cannot be removed
```

Adding or removing asks you to confirm with a passkey or authenticator app you already have, then opens a one-time
page to register the new one. To move from an authenticator app to a passkey: add the passkey, then remove the app.

## Where things live

| | macOS | Linux | Windows |
|---|---|---|---|
| Profiles, links (no secrets) | `~/.config/kuukura/` | `~/.config/kuukura/` | `%AppData%\kuukura\` |
| Session, first choice | Keychain | Secret Service (GNOME Keyring, KWallet) | Credential Manager |
| Session, if there is no keychain | `<config>/sessions/<profile>` (private file) | same | same |
| Open the browser | `open` | `xdg-open` | `rundll32 url.dll,FileProtocolHandler` |

`XDG_CONFIG_HOME` moves the configuration folder on every system (do not change `HOME`: the macOS Keychain lives under it).

## How the session is kept

The session token (valid 8 hours, 1 hour idle) is stored in this order:

1. **The system keychain**, encrypted by the OS and tied to this device. Nothing is written to disk.
2. **Only when there is no keychain** (a server, a container, WSL, a Linux box without a desktop): a private file
   `<config>/sessions/<profile>`, readable only by your user (mode `0600`, folder `0700`). `ku` tells you when it does
   this. The file is not encrypted: anyone who can run programs as you can read it. It is bounded by the short session
   life, and `ku workspace disable <person>` ends a session on the server at once. `ku` refuses a session file that
   other users can read.
3. **CI**: set `KU_URL` and `KU_TOKEN` (a machine token); nothing is stored.

The token is never in `config.toml`, and never in both the keychain and a file. `ku profile remove <name>` deletes it
from wherever it is.

## What goes where

`ku` prints only data on stdout: `secret list` rows, a revealed value (`secret get --reveal`), a machine token, an
invite link, `profile list` rows. Every status line (the `✓` and `✗` marks, prompts, `profile: <name>`, "No secrets
found.") goes to stderr, so `ku workspace invite ci --machine | pbcopy` copies the token alone. `ku run` passes the
command's own output through unchanged and returns its exit code.

- An unknown flag (`--profle`) is an error, never ignored.
- An argument with a colon that is not a `key:value` tag is refused and never echoed or sent: values are never
  arguments. No error message repeats what you typed in a place where a value could be.
- `ku run` refuses to inject a secret named like a loader or interpreter hook (`LD_PRELOAD`, `DYLD_*`, `PATH`,
  `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV` and a few more) and does not start the command: such a name could run
  code chosen by whoever saved the secret. Rename the secret.
- Links from the server (confirmation, adding a passkey or authenticator app) are opened in the browser only when they point at the
  profile's own server; anything else is printed and not opened.
- Ctrl-C reaches the command from the terminal itself; `ku run` forwards only `TERM` and `HUP`.

## Errors and exit codes

`ku help` lists every command, one `noun verb` line each (`ku-server help` has the same shape). A failure prints
`✗ <A sentence.>` on stderr and, when one command fixes it, a second line `  Run: <that command>`. Exit codes:

| code | meaning |
|---|---|
| 0 | done |
| 1 | the command ran and failed (not logged in, not permitted, the server said no) |
| 2 | wrong arguments: the command prints its own `Usage:` line and does nothing else |
| other | `ku run` returns the exit code of the command it ran |

## Notes per system

- **macOS**: the first time a new build of `ku` reads its saved session, macOS may ask for your keychain password.
  Choose *Always Allow*. A release binary signed with a Developer ID keeps its identity across versions and stops asking.
- **Linux**: with a desktop keyring running, the session goes there; over SSH or in a container it goes to the private file.
- **Windows**: the Credential Manager holds the session. Windows has no Unix file modes, so the private-file fallback
  relies on your user profile folder's permissions. Use Windows Terminal or PowerShell 7 for the ✓ and ✗ marks.
  `ku run` runs your command directly; file secrets are written to a temporary folder and deleted when it ends.
  The Windows build is tested for compilation and for the OS-specific parts in CI; the full flow is not run on Windows in CI.
