---
title: Saving scans
weight: 2
---

`mitch scan` saves each scan, encrypted, in a local database. Later commands read from it, so you can look back at earlier scans. How the data is protected is described in [How Mitch protects your data](data-security.md).

## 1. Choose a passphrase

The passphrase unlocks the database. It must be at least 12 characters. **If you lose it, your saved scans cannot be recovered.** Keep it in a password manager.

Mitch looks for it in this order:

| Source | Use it for |
| --- | --- |
| `--passphrase-file FILE` | Scripts. One trailing line break is ignored. The file must be readable only by you (`chmod 600 FILE`), or Mitch refuses it; see [Passphrase files](#passphrase-files). |
| `MITCH_PASSPHRASE` environment variable | CI jobs and Docker, from your secret store |
| A prompt | Running Mitch by hand. What you type is not shown. `mitch init` asks twice. |

Mitch only prompts when it runs in a terminal. In CI or a pipe, with no file or variable set, it fails right away instead of waiting.

## 2. Create the database

```shell
mitch init
```

```text
Passphrase:
Repeat passphrase:
Created mitch.db
```

This creates `mitch.db` in the current directory, readable only by you. To put it somewhere else, pass `--db PATH` or set `MITCH_DB` on every command. `mitch init` never overwrites an existing file.

## 3. Scan

```shell
mitch scan
```

The scan is encrypted and saved, and its id is printed, for example `4c245cda40efc84d`. Mitch unlocks the database before contacting Vault, so a wrong passphrase or missing database fails right away.

To print the inventory as JSON without saving it, use `mitch scan --no-save`. That needs no database or passphrase. See [Scanning Vault](scanning.md) for the scan itself.

## 4. List and export saved scans

```shell
mitch history
```

```text
ID                STARTED (UTC)        DURATION
4c245cda40efc84d  2026-11-13 20:18:32  10ms
```

```shell
mitch export --scan 4c245cda40efc84d --output scan.json
```

`mitch export` prints one saved scan as JSON, in the same format as `mitch scan --no-save`. Without `--output` it prints to standard output. Either way the output is plain text, and Mitch logs a warning.

## 5. Change the passphrase

```shell
mitch passphrase
```

Mitch asks for the current passphrase, then the new one twice. The new one must also be at least 12 characters. Your saved scans are kept.

For scripts, give the current passphrase the usual way and the new one with `MITCH_NEW_PASSPHRASE` or `--new-passphrase-file FILE`:

```shell
MITCH_PASSPHRASE='<current>' MITCH_NEW_PASSPHRASE='<new>' mitch passphrase
```

Afterwards, update `MITCH_PASSPHRASE`, any passphrase files, and your password manager. The old passphrase no longer opens this database, but it still opens backups made before the change. See [How Mitch protects your data](data-security.md#changing-the-passphrase).

## Flags

### Passphrase files

Anyone who can read the passphrase file can decrypt every saved scan. So, like `ssh` with a private key that other users can read ([ssh(1), FILES](https://man.openbsd.org/ssh#FILES)), Mitch refuses a passphrase file that your group or other users can read, and exits with the `chmod 600` command to fix it. This applies to `--new-passphrase-file` too.

`--allow-insecure-passphrase-file` turns the refusal into a warning. It is meant for CI and other non-interactive runs where you can't set the file's permissions, such as a secret mounted into a container or a CI runner's secret file. Don't use it on a machine other people log in to. Prefer `MITCH_PASSPHRASE` from your CI secret store when you can.

These work on `init`, `scan`, `history`, `export`, `report`, `diff` and `passphrase`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--db PATH` | `MITCH_DB`, else `mitch.db` | The database file. |
| `--passphrase-file FILE` | none | Read the passphrase from this file instead of `MITCH_PASSPHRASE`. |
| `--allow-insecure-passphrase-file` | off | Use a passphrase file that other users can read, with a warning. For CI and non-interactive runs only. |

## Common errors

| Message | What to do |
| --- | --- |
| `no Mitch database at ...` | Run `mitch init`, or pass `--db` with the right path. |
| `the passphrase is wrong, or the data was changed or damaged` | Check `MITCH_PASSPHRASE` or `--passphrase-file`. |
| `no passphrase given and no terminal to ask on` | Set `MITCH_PASSPHRASE` or pass `--passphrase-file`. |
| `the two passphrases do not match` | Run `mitch init` again. Nothing was created. |
| `refusing to use the passphrase file: ... has permissions 0644` | Run the `chmod 600` command in the message. In CI or a container where you can't, pass `--allow-insecure-passphrase-file`. |
| `... has permissions 0644; other users on this machine can read it` (a warning about the database) | Run the `chmod 600` command in the message. |
