# How Mitch protects your data

Mitch saves each scan in a local SQLite file, encrypted with a key that only your passphrase can unlock. A stolen database file or a leaked backup is unreadable without the passphrase. To set it up, see [saving-scans.md](saving-scans.md).

## What Mitch stores

- Mount, auth method, plugin, namespace and configuration details from Vault.
- ACL policy text.
- The number of secrets and folders in each KV mount. Key and folder names are not stored.
- The Vault address that was scanned.

All of this is encrypted. Only each scan's id and its start, finish and save times are stored in the clear, so `mitch history` can list scans.

## What Mitch never stores

- Secret values. Mitch never reads them.
- KV key and folder names. Mitch counts them and drops the names.
- Vault tokens or your passphrase.

## Why path names are sensitive

Vault's own docs warn that key names are not filtered by policy and can contain sensitive information ([KV v2 list](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#list-secrets)). An inventory of path names is also a map for an attacker. Mitch never records them, and redacts them in logs (see [logging.md](logging.md)).

## Encryption at rest

Disk encryption alone is not enough: it doesn't protect data once the machine is unlocked, or a database copied into a backup. Mitch encrypts the data itself, using envelope encryption:

1. `mitch init` creates a random 256-bit **data key**. Each scan is encrypted with it using AES-256-GCM from Go's standard library ([crypto/cipher](https://pkg.go.dev/crypto/cipher#NewGCM)), with a fresh random nonce each time.
2. Each encrypted scan is bound to its scan id. A blob copied onto another row fails to decrypt instead of showing the wrong scan.
3. The data key is stored only in wrapped (encrypted) form. It is wrapped with a key derived from your **passphrase** using Argon2id ([x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2)): time 3, 64 MiB of memory, 4 threads, and a random salt per database. These are RFC 9106's settings for machines that can't spare 2 GiB. They are stored in the file, so later versions can raise them.
4. Passphrases must be at least 12 characters. A wrong passphrase is rejected before anything is read.
5. The passphrase comes from a prompt that does not show what you type, `MITCH_PASSPHRASE`, or `--passphrase-file`. Mitch never writes it to disk or to logs.

The database file is created readable only by its owner (`0600`). Mitch warns you if the file or a `--passphrase-file` can be read by other users, with the `chmod` command to fix it.

## Changing the passphrase

`mitch passphrase` wraps the same data key again with your new passphrase and a new salt. The saved scans are not re-encrypted, so the change is instant. See [saving-scans.md](saving-scans.md#5-change-the-passphrase).

What a change does not do:

- **Old copies still open with the old passphrase.** A backup made before the change holds the old wrapped key.
- **The data key stays the same.** Someone who had both the old passphrase and an old copy of the file can recover the data key, and with it read newer copies too.

If the old passphrase may have leaked together with a copy of the database, changing the passphrase is not enough: create a new database with `mitch init` and scan again.

**A lost passphrase cannot be recovered.** No one, including the Mitch maintainers, can decrypt the scans without it.

## Plain-text output

Some commands print scan data in plain text, because other tools need to read it. Mitch logs a warning each time:

- `mitch scan --no-save` and `mitch scan --output FILE`
- `mitch export`
- `mitch report` and `mitch diff`

Files are created readable only by you (`0600`). Treat the output as sensitive: it describes your Vault's layout and contains every ACL policy.
