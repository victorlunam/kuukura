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

**AWS KMS.** Either let AWS rotate the key material (nothing to do here), or move to a new KMS key:

1. Give the server's AWS identity `kms:Encrypt` on the new key and keep `kms:Decrypt` on the old one.
2. Set `VAULT_KMS_KEY_ARN` to the new key and restart. New data is wrapped under the new key; existing rows keep
   the ARN they were wrapped with (stored per row) and are still read through it.
3. Run `ku-server admin rotate-key --admin you@example.com`. It rewraps every row to the new key (authenticator
   secrets too) and prints `... to aws-kms:<new arn>.`
4. Only then remove `kms:Decrypt` on the old key and schedule it for deletion (keep the long deletion window). Keep
   it if you might restore an older database backup.

Switching between the two providers (a key file to KMS, or back) is **not supported**: a stored key id such as
`manual:v2` is read only by the manual provider and `aws-kms:...` only by KMS, and there is no migration that
rewraps across them. Pick one at the start; changing needs a purpose-built migration that does not exist yet.

## A2. Verify the audit log

The audit log is a hash chain; nothing in the running server re-checks it, so run it on a schedule (weekly is
reasonable) and after any incident:

```sh
docker compose exec kuukura /ku-server admin verify-audit
```

Output: `OK: audit log verified, 1432 rows, head 3f5a...`. It exits non-zero and says where the chain breaks if
a row was edited or removed in the middle. Copy the row count and head hash to somewhere the database's operator
cannot edit (a ticket, a git repo, another system). The chain alone cannot show that the newest rows were cut
off; comparing a later run with a stored head can: the head you stored must still be in the chain, and the row
count must not have gone down.

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
| A2 audit verification |  |  |  | rows and head stored where: |
| B machine token |  |  |  |  |
| C one secret |  |  |  |  |
| D offline recovery |  |  |  |  |
| E offboarding |  |  |  |  |
