[Mitch docs](README.md) › Saving scans

# Saving scans

`mitch scan` saves each scan, encrypted, in a local database. Later commands read from it, so you can look back at earlier scans. How the data is protected is described in [data-security.md](data-security.md).

## 1. Choose a passphrase

The passphrase unlocks the database. It must be at least 12 characters. **If you lose it, your saved scans cannot be recovered.** Keep it in a password manager.

Mitch looks for it in this order:

| Source | Use it for |
| --- | --- |
| `--passphrase-file FILE` | Scripts. One trailing line break is ignored. Make the file readable only by you: `chmod 600 FILE` |
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

To print the inventory as JSON without saving it, use `mitch scan --no-save`. That needs no database or passphrase. See [scanning.md](scanning.md) for the scan itself.

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

Afterwards, update `MITCH_PASSPHRASE`, any passphrase files, and your password manager. The old passphrase no longer opens this database, but it still opens backups made before the change. See [data-security.md](data-security.md#changing-the-passphrase).

## Flags

These work on `init`, `scan`, `history`, `export`, `report`, `diff` and `passphrase`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--db PATH` | `MITCH_DB`, else `mitch.db` | The database file. |
| `--passphrase-file FILE` | none | Read the passphrase from this file instead of `MITCH_PASSPHRASE`. |

## Common errors

| Message | What to do |
| --- | --- |
| `no Mitch database at ...` | Run `mitch init`, or pass `--db` with the right path. |
| `the passphrase is wrong, or the data was changed or damaged` | Check `MITCH_PASSPHRASE` or `--passphrase-file`. |
| `no passphrase given and no terminal to ask on` | Set `MITCH_PASSPHRASE` or pass `--passphrase-file`. |
| `the two passphrases do not match` | Run `mitch init` again. Nothing was created. |
| `... has permissions 0644; other users on this machine can read it` | Run the `chmod 600` command in the message. |

---

**Next:** [Scanning Vault](scanning.md)
