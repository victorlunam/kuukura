# Quarterly key rotation drill

Goal: prove you can rotate the master key, a machine token and a secret, recover from the offline key copy, and
offboard a person, and know how long it takes. Do it on a scratch instance first, then on production. Fake names below.

Record start and end time of each part in the table at the bottom.

## A. Rotate the master key (data stays readable, ciphertext untouched)

1. Add a new key version next to the old one, and export a new offline copy:
   ```sh
   docker run --rm -it -v "$PWD/secrets:/s" ghcr.io/victorlunam/kuukura \
     init --rotate --key-file /s/master_key --export /s/master_key.v2.age
   ```
   The key file now holds `1:...` and `2:...`; the highest version wraps new data. Store `master_key.v2.age` offline
   (new passphrase or the same), delete it from the server.
2. Restart the server so it reads the new key file (`docker compose up -d --force-recreate kuukura`).
3. Rewrap every data key and stored authenticator secret to the new version (audited as `key_rotate`):
   ```sh
   docker compose exec kuukura /ku-server admin rotate-key --admin you@example.com
   ```
   Output: `Rewrapped N secret versions and M TOTP secrets to manual:v2.`
4. Check: `ku run ... -- true` still works; `ku workspace audit` shows `key_rotate`; running `rotate-key` again rewraps 0.
5. Only after step 3 reports success, and the old offline copy is destroyed or clearly marked retired, you may remove
   the `1:` line from the key file. Keep it if you might restore an older database backup.

(AWS KMS: rotate the KMS key material in AWS, or point `VAULT_KMS_KEY_ARN` at a new key and run `rotate-key`; old
ARNs must stay usable until the rewrap finishes.)

## B. Rotate one machine token

Machine tokens last about 90 days. To renew: issue a new machine, short overlap, remove the old one.

1. `ku workspace invite ci-deploy-2 --machine` (copy the token) and `ku workspace grant ci-deploy-2 read <tags>`.
2. Update `KU_TOKEN` in CI; run one pipeline.
3. `ku workspace remove ci-deploy` (ends its tokens immediately).

## C. Rotate one secret

1. `ku secret set STRIPE_KEY app:shop env:prod` with the new value from the provider (new version).
2. Deploy consumers (`ku run`). If the old value leaked: `ku secret revoke STRIPE_KEY env:prod` first (blocks reads until the
   next `set`), then set the new value.

## D. Recover from the offline copy

On a scratch machine:

1. `age -d master_key.age > master_key` (offline copy + passphrase).
2. Start a scratch instance with a copy of the database and this key file; read one secret with `ku run`.
3. Wrong passphrase must fail. Destroy the scratch copy.

## E. Rehearse offboarding

1. `ku workspace remove leaver@example.com` (disables login, ends sessions, disables machines they own).
2. List what they could read: `ku workspace audit` for their `read`/`reveal` rows, and check their grants/groups.
3. Rotate each of those secrets (part C).

## Record

| Part | Start | End | Minutes | Notes |
|---|---|---|---|---|
| A master key |  |  |  |  |
| B machine token |  |  |  |  |
| C one secret |  |  |  |  |
| D offline recovery |  |  |  |  |
| E offboarding |  |  |  |  |
