[Mitch docs](README.md) › Reports

# Reports

`mitch report` summarizes one saved scan: what is in Vault, counted and grouped, and anything the scan could not read. It reads only the saved, encrypted scan and never contacts Vault.

It needs the same database and passphrase as the other commands. See [saving-scans.md](saving-scans.md).

## 1. Show a report

```shell
mitch report
```

This shows the newest saved scan as Markdown in the terminal. To pick another scan, pass its id from `mitch history`:

```shell
mitch report --scan 4895f3d21c84b3d1
```

## 2. Save it

```shell
mitch report --output report.json
```

The terminal still shows the Markdown, and `report.json` gets the same report as JSON. Use `--output report.md` to save the Markdown instead.

## What the report shows

| Section | What it lists |
| --- | --- |
| Header | Scan id and time, Vault address, version, edition, cluster name, and whether sudo checks ran. |
| Summary | Counts of namespaces, secrets engines, auth methods, ACL policies, KV secrets, plugins, deprecated items and skipped checks. |
| Scan gaps | Checks that could not run (with the HTTP status, reason and next step) and checks left out on purpose, such as sudo checks. Only shown when there are any. |
| Mounts by type | Secrets engines and auth methods counted by type, most common first. |
| Secrets engines, Auth methods | Every mount, by namespace, with its type, plugin version and description. |
| KV secrets | Secrets and folders per KV mount. "no, counts are a lower bound" means part of the mount could not be listed. |
| Registered plugins | Plugins added to the catalog by hand, not shipped with Vault. The SHA256 needs `--sudo`. Built-in plugins are counted by type. |
| Deprecated | Mounts, and plugins registered by hand, that Vault marks as deprecated, pending removal or removed ([Vault deprecation](https://developer.hashicorp.com/vault/docs/updates/deprecation)). Only shown when there are any. |
| ACL policies | Each policy's name and number of lines. The full text is in `mitch export`. |
| Audit devices | Each audit device. Needs `--sudo`. |
| Vault version history | Every version this cluster has run. |

If the scan skipped checks, Mitch also logs a warning that the report is incomplete. The counts leave out what could not be read, so "at least" is shown where a count may be low.

> **Not built yet:** last-updated age of KV secrets, unused policies, and policy findings.

## Output and files

`mitch report` and `mitch diff` handle output the same way:

| You run | The terminal shows | The file gets |
| --- | --- | --- |
| `mitch report` | Markdown | no file |
| `mitch report --output report.json` | Markdown | JSON |
| `mitch report --output report.md` | Markdown | Markdown |
| `mitch report --format json` | JSON, for piping into `jq` | no file |

The file's format comes from its extension: `.json` or `.md`, in any case. Any other extension is rejected before the passphrase is read. Files are created readable only by you (`0600`). In JSON, every list is `[]` when empty, except `kv_counts` and `audit_devices`, which are `null` when the scan did not collect them.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--scan ID` | newest scan | The scan to report on. |
| `--format markdown\|json` | `markdown` | What the terminal shows. |
| `--output FILE` | none | Also save to `FILE`: `.json` saves JSON, `.md` saves Markdown. |
| `--db PATH`, `--passphrase-file FILE` | | See [saving-scans.md](saving-scans.md). |

## The output is plain text

The report describes your Vault's layout from the encrypted scan, so Mitch logs a warning each time it shows or saves one. See [data-security.md](data-security.md#plain-text-output).

---

**Next:** [Comparing scans](comparing-scans.md)
