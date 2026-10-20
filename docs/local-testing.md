# Testing locally (real Google login, real Touch ID)

WebAuthn works on `localhost` without HTTPS, so you can exercise the full login and Touch ID flow on your machine.
`VAULT_DEV_HTTP=true` allows plain HTTP, and it is accepted **only** when `VAULT_DOMAIN=localhost`.

1. Google Cloud: create an OAuth client of type "Web application". Authorized redirect URI:
   `http://localhost:8080/auth/callback`. (The OAuth consent screen can stay in "Testing" with your own account as a test user.)
2. Master key and server:
   ```sh
   mkdir -p /tmp/kk && ku-server init --key-file /tmp/kk/master_key --export /tmp/kk/master_key.age
   export VAULT_DOMAIN=localhost VAULT_DEV_HTTP=true VAULT_ADDR=:8080
   export VAULT_STORAGE=sqlite VAULT_SQLITE_PATH=/tmp/kk/kuukura.db VAULT_MASTER_KEY_FILE=/tmp/kk/master_key
   export VAULT_OIDC_CLIENT_ID=... VAULT_OIDC_CLIENT_SECRET=...
   ku-server admin invite --email you@gmail.com      # open the printed link, sign in with that Google account
   ku-server serve
   ```
3. Register a passkey in the browser (Touch ID on macOS), then in a terminal:
   ```sh
   ku profile add local --url http://localhost:8080
   ku login
   ku secret set DEMO_KEY app:demo                   # hidden prompt
   ku secret get DEMO_KEY --reveal                   # opens the browser: confirm with Touch ID
   ```
   Use Chrome or Safari recent enough for `PublicKeyCredential.parseCreationOptionsFromJSON`.

The CLI accepts `http://` server URLs only for `localhost`, `127.0.0.1` and `::1`.

**macOS asks for your keychain password ("ku wants to access key ...")?** That is the Keychain protecting the saved
session. It ties each item to the program that created it, and a CLI you just built is a different, unsigned program
every time you rebuild it. Choose **Always Allow** once per build. A release binary signed with a Developer ID keeps its
identity across versions, so it asks once and then stops. The release workflow signs the macOS binaries when the
`MACOS_CERT_P12` secrets exist; otherwise `scripts/sign-macos.sh <tag>` signs a published release afterwards.

To try the CLI with a throwaway configuration, set `XDG_CONFIG_HOME` (for example `export XDG_CONFIG_HOME=/tmp/ku-test`).
Do not change `HOME`: the macOS Keychain lives under it, and the CLI would fail to store the session
("A keychain cannot be found to store ...").
