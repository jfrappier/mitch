[Mitch docs](README.md) › Comparing scans

# Comparing scans

`mitch diff` shows what changed in Vault between two saved scans: mounts, auth methods, ACL policies, KV secret counts, plugins, namespaces and server settings. It reads only the saved, encrypted scans and never contacts Vault.

It needs the same database and passphrase as the other commands. See [saving-scans.md](saving-scans.md).

## 1. Save at least two scans

```shell
mitch scan
# ...later, after Vault has changed...
mitch scan
```

## 2. Compare the two newest scans

```shell
mitch diff
```

````text
# Mitch diff

- From scan: ed1161e60195efe2 (2026-11-13 20:48:33 UTC, Vault 2.2.2)
- To scan: 758cc50a9f5c6e83 (2026-11-13 21:15:02 UTC, Vault 2.2.2)

## Secrets engines in namespace (root)

```diff
+ e2e-demo/ (kv)
~ secret/
    config.max_lease_ttl: 0 -> 7200
```

## ACL policies in namespace (root)

```diff
+ e2e-demo
```
````

The output is Markdown. It reads as plain text in a terminal, and on GitHub the change blocks are colored. Each line in a block starts with:

| Mark | Meaning |
| --- | --- |
| `+` | Only in the newer scan (added). |
| `-` | Only in the older scan (removed). |
| `~` | In both scans, but different. The changed fields are listed under it as `field: old -> new`. For an ACL policy, the changed lines of its text are listed, with `-` for old lines and `+` for new ones. |

When nothing changed, the output ends with `No changes.`

## 3. Compare any two scans

Pick scan ids from `mitch history`:

```shell
mitch diff --from ed1161e60195efe2 --to 758cc50a9f5c6e83
```

Give both `--from` (the older scan) and `--to` (the newer scan), or neither.

## 4. Save the diff

`--output` saves the diff to a file, and the terminal still shows it. The file name picks the format, so one run gives you both:

```shell
mitch diff --output changes.json
```

How output works is the same for `mitch report`. See [Output and files](reports.md#output-and-files).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--from ID` | second newest scan | The older scan. |
| `--to ID` | newest scan | The newer scan. |
| `--format markdown\|json` | `markdown` | What the terminal shows. Use `json` to pipe into tools such as `jq`. |
| `--output FILE` | none | Also save to `FILE`: `.json` saves JSON, `.md` saves Markdown. |
| `--db PATH`, `--passphrase-file FILE` | | See [saving-scans.md](saving-scans.md). |

`mitch diff` exits with `0` whether or not anything changed. See [exit-codes.md](exit-codes.md) for failures.

## Warnings

Some differences are not real changes in Vault. `mitch diff` lists a warning at the top when:

- **A scan skipped checks.** If a scan could not read something (for example after an HTTP 403), those items look removed or added. Fix the policy and scan again; see [scanning.md](scanning.md).
- **A part was collected in only one scan.** Audit devices and plugin runtimes need `--sudo`, server config is missing when the scan could not read it, and KV counts can be turned off with `--kv=false`. A part missing from either scan is not compared.
- **The scans are of different Vault addresses.** The differences are then between two clusters.

## What is compared

| Part | Matched across scans by |
| --- | --- |
| Vault health (version, seal status, cluster name) | |
| Server config | each setting |
| Plugins | type, name and version |
| Plugin runtimes, audit devices | type and name, path |
| Namespaces | path |
| Secrets engines, auth methods | mount path |
| ACL policies | name |
| KV counts | mount path |

A mount that was disabled and enabled again at the same path shows as changed, with a new `accessor` and `uuid`.

## The output is plain text

The diff contains policy text and mount settings from the encrypted scans. See [data-security.md](data-security.md#plain-text-output).
