# How Mitch protects your data

> **Status:** this describes the planned design. Storage and encryption are not built yet. This page will be updated as each part ships.
>
> **Today:** `mitch scan` prints its inventory as plain JSON and stores nothing. With `--output`, the file is created readable only by you (`0600`) and Mitch logs a warning that it is plain text. The inventory never contains secret values or KV key and folder names, but it does contain your Vault layout and the full text of every ACL policy, so treat it as sensitive.

## What Mitch stores

- Mount, auth method, plugin, namespace and configuration details from Vault.
- ACL policy text.
- The number of secrets and folders in each KV mount. Key and folder names are not stored.
- Findings and scan history.

## What Mitch never stores

- Secret values.
- Vault tokens or your passphrase.

## Why path names are sensitive

Vault's own docs warn that key names are not filtered by policy and can contain sensitive information. An inventory of path names is also a map for an attacker. Mitch treats path names as sensitive data.

## Encryption at rest

Disk encryption alone is not enough: it doesn't protect data once the machine is unlocked, or a database copied into a backup. Mitch encrypts sensitive fields itself:

1. Each database has a random **data key**. Sensitive fields are encrypted with it using AES-GCM from Go's standard library.
2. The data key is stored only in wrapped (encrypted) form. It is wrapped with a key derived from your **passphrase** using Argon2id.
3. The passphrase comes from an interactive prompt, or from an environment variable in CI. It is never written to disk or to logs.
4. Changing the passphrase re-wraps the data key only. The data itself does not need to be re-encrypted.

The database file is created readable only by its owner (`0600`).

## Exports

JSON and SARIF exports are written in plain text so other tools can read them. Mitch warns you each time it writes one. Treat exported files as sensitive.
