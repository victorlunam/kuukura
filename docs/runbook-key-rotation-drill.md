# Quarterly key rotation drill

Goal: prove you can rotate the master key, a machine token and a secret, restore from the key backup, and
offboard a person, and know how long it takes. Do it on a scratch instance first, then on production. Fake names below.

Record start and end time of each part in the table at the bottom.

## A. Rotate the master key (data stays readable, ciphertext untouched)

When the key lives in a writable key file (the generated `/keys/master_key`, or one made with `key init`):

1. Run it on the host. It adds a version to the key file and rewraps every data key and stored authenticator secret
   to it, together with the `key_rotate` audit row, in one transaction:
   ```sh
   docker compose exec kuukura /ku-server key rotate
   ```
   Output: `Rewrapped N secret versions and M TOTP secrets to manual:v2.` The key file now holds `1:...` and `2:...`;
   the highest version wraps new data. If the rewrap fails after the version was added, fix the cause and run
   `key rotate --rewrap-only` (not `key rotate` again, which would add a third version).
2. Restart the server so it reads the new key file (`docker compose up -d --force-recreate kuukura`). Until then the
   running process only knows version 1 and cannot read the rewrapped data.
3. Back up the new version: `docker compose exec -it kuukura /ku-server key show` prints the whole ring once for
   this version; store it in your password manager. (The server logs a warning at every start until the active
   version has been shown.)
4. Check: `ku run ... -- true` still works; `ku workspace audit` shows `key_rotate`; `key rotate --rewrap-only`
   again rewraps 0.
5. You may remove the `1:` line from the key file only when you will never restore an older database backup, and
   after the old backup entry is clearly marked retired.

When the key comes from `VAULT_MASTER_KEY` or a read-only secret file, `key rotate` cannot write it and says so. Do
the two steps yourself: add a line `2:<base64 of 32 random bytes>` (for example from `openssl rand -base64 32`)
where the key lives, keeping the old lines, restart the server, then run `ku-server key rotate --rewrap-only` and
`key show` as above.

**AWS KMS.** Either let AWS rotate the key material (nothing to do here), or move to a new KMS key:

1. Give the server's AWS identity `kms:Encrypt` on the new key and keep `kms:Decrypt` on the old one.
2. Set `VAULT_KMS_KEY_ARN` to the new key and restart. New data is wrapped under the new key; existing rows keep
   the ARN they were wrapped with (stored per row) and are still read through it.
3. Run `ku-server key rotate`. With aws-kms it rewraps every row to the configured ARN (authenticator secrets
   too) and prints `... to aws-kms:<new arn>.` (`key show` says "not applicable": the key never leaves KMS.)
4. Only then remove `kms:Decrypt` on the old key and schedule it for deletion (keep the long deletion window). Keep
   it if you might restore an older database backup.

Switching between the two providers (a key file to KMS, or back) is **not supported**: a stored key id such as
`manual:v2` is read only by the manual provider and `aws-kms:...` only by KMS, and there is no migration that
rewraps across them. Pick one at the start; changing needs a purpose-built migration that does not exist yet.

## A2. Verify the audit log

The audit log is a hash chain; nothing in the running server re-checks it, so run it on a schedule (weekly is
reasonable) and after any incident:

```sh
docker compose exec kuukura /ku-server audit verify
```

Output: `OK: audit log verified, 1432 rows, head 3f5a...`. It exits non-zero and says where the chain breaks if
a row was edited or removed in the middle. Copy the row count and head hash to somewhere the database's operator
cannot edit (a ticket, a git repo, another system). The chain alone cannot show that the newest rows were cut
off; comparing a later run with a stored head can: the head you stored must still be in the chain, and the row
count must not have gone down.

## B. Rotate one machine token

Machine tokens last about 90 days. To renew: issue a new machine, short overlap, disable the old one.

1. `ku workspace invite ci-deploy-2 --machine` (copy the token) and `ku workspace grant ci-deploy-2 read <tags>`.
2. Update `KU_TOKEN` in CI; run one pipeline.
3. `ku workspace disable ci-deploy` (ends its tokens immediately).

## C. Rotate one secret

1. `ku secret set STRIPE_KEY app:shop env:prod` with the new value from the provider (new version).
2. Deploy consumers (`ku run`). If the old value leaked: `ku secret revoke STRIPE_KEY env:prod` first (blocks reads until the
   next `set`), then set the new value.

## D. Restore from the key backup

On a scratch machine:

1. Copy the key text from your password manager (the ring `key show` printed, all versions) into a key file
   (`VAULT_MASTER_KEY_FILE`) or into `VAULT_MASTER_KEY`.
2. Start a scratch instance with a copy of the database and this key; read one secret with `ku run`. A wrong or
   incomplete key stops the server at start with "the master key does not match the data (key manual:vN cannot open it)".
3. Destroy the scratch copy.

If you need an encrypted file instead of a password-manager entry, encrypt the text with your own tool (age, gpg,
sops).

## E. Rehearse offboarding

1. `ku workspace disable leaver@example.com` (disables login, ends sessions, disables machines they own).
2. List what they could read: `ku workspace audit` for their `read`/`reveal` rows, and check their grants/groups.
3. Rotate each of those secrets (part C).

## Record

| Part | Start | End | Minutes | Notes |
|---|---|---|---|---|
| A master key |  |  |  |  |
| A2 audit verification |  |  |  | rows and head stored where: |
| B machine token |  |  |  |  |
| C one secret |  |  |  |  |
| D restore from backup |  |  |  |  |
| E offboarding |  |  |  |  |
