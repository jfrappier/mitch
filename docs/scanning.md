# Scanning Vault

`mitch scan` reads a Vault cluster and saves an encrypted inventory of what it found. It never writes to Vault and never reads secret values.

Before your first saved scan, create the database with `mitch init`. See [saving-scans.md](saving-scans.md). To print the inventory as JSON without saving it, use `--no-save`.

To see what changed between two saved scans, use `mitch diff`. See [comparing-scans.md](comparing-scans.md).

## 1. Create the Mitch policy and token

Print the base policy, load it into Vault, and create a token for Mitch:

```shell
mitch policy > mitch-scanner.hcl
vault policy write mitch-scanner mitch-scanner.hcl
vault token create -policy=mitch-scanner -ttl=1h
```

The base policy grants only `read` and `list` on the endpoints Mitch uses, plus `update` on `sys/capabilities-self` so Mitch can check its own permissions before scanning. It never grants `sudo` and never grants access to secret data.

### KV secret counts

Mitch counts the secrets in each KV mount by listing key names. To allow that, print a policy that names your KV mounts. Use `--kv2-mount` for KV version 2 mounts and `--kv1-mount` for version 1, and repeat the flag for each mount:

```shell
mitch policy --kv2-mount secret/ --kv1-mount legacy/ > mitch-scanner-kv.hcl
vault policy write mitch-scanner-kv mitch-scanner-kv.hcl
vault token create -policy=mitch-scanner -policy=mitch-scanner-kv -ttl=1h
```

`vault secrets list -detailed` shows each mount's KV version in its options column.

The policy grants only `list`: on `<mount>/metadata/*` for KV v2 and on `<mount>/*` for KV v1. Listing returns key names, never values ([KV v2 list](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#list-secrets), [KV v1 list](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#list-secrets)). It names each mount exactly instead of using a wildcard, so add a mount to the policy when you create one. Until you do, the scan skips that mount, exits with code 5, and logs the exact `mitch policy` command to run.

On Vault Enterprise, write this policy in the namespace that holds the mounts.

### Optional: sudo checks

A few endpoints need the `sudo` capability: audit devices, registered plugin checksums, and plugin runtimes. Mitch skips them unless you pass `--sudo`. To use them, also load the add-on policy and include it in the token:

```shell
mitch policy --sudo > mitch-scanner-sudo.hcl
vault policy write mitch-scanner-sudo mitch-scanner-sudo.hcl
vault token create -policy=mitch-scanner -policy=mitch-scanner-sudo -ttl=1h
```

`sudo` only works together with another capability, so `read` plus `sudo` is still read-only ([Vault policy docs](https://developer.hashicorp.com/vault/docs/concepts/policies#capabilities)).

## 2. Run the scan

Mitch uses the same environment variables as the `vault` CLI: `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_CACERT`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY`, `VAULT_SKIP_VERIFY`, and so on.

```shell
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=<token from step 1>

mitch scan
```

Mitch asks for your passphrase. In CI, set `MITCH_PASSPHRASE` instead.

The scan is saved and its id is printed. Use `mitch history` and `mitch export` to see it ([saving-scans.md](saving-scans.md)).

| Flag | Default | Meaning |
| --- | --- | --- |
| `--sudo` | off | Also run checks that need `sudo`. |
| `--kv` | on | Count secrets in KV mounts. `--kv=false` turns it off. |
| `--no-save` | off | Do not save the scan. Print the JSON to standard output instead. Needs no database. |
| `--output FILE` | none | Also write the JSON to a file, in plain text. The file is created readable only by you (`0600`). |
| `--db PATH`, `--passphrase-file FILE` | see [saving-scans.md](saving-scans.md) | Where to save, and how to unlock. |
| `--timeout DURATION` | `10m` | Stop the scan if it takes longer than this, for example `30s` or `1h`. |

`VAULT_NAMESPACE` is ignored on purpose. Mitch always starts at the root namespace and, on Vault Enterprise, scans every child namespace it can see.

## What the scan does

1. **Health:** reads `sys/health` to get the Vault version and edition. A sealed or uninitialized Vault stops the scan.
2. **Preflight:** asks `sys/capabilities-self` which grants the token has. Each missing grant is logged as a warning, and that check is skipped instead of failing later. If the token cannot call `sys/capabilities-self`, Mitch tries every check and records each failure.
3. **Cluster-wide checks** (root namespace only): sanitized server config, version history, plugin catalog, and with `--sudo`, audit devices, registered plugin details and plugin runtimes.
4. **Per-namespace checks:** secrets engines, auth methods, and ACL policies with their text. On Vault Enterprise, Mitch walks the namespace tree and repeats these in every namespace.
5. **KV secret counts** (per namespace, unless `--kv=false`): checks that the token can list each KV mount, then lists every folder in it, one request at a time. A folder it cannot list is counted as a failure and the rest of the mount is still counted.

Large KV mounts take one request per folder. If a scan hits `--timeout`, raise it or count with `--kv=false` first to see the rest of the inventory.

## Exit codes and skipped checks

| Result | Exit code |
| --- | --- |
| Every check ran | 0 |
| Some checks were skipped (missing grant, HTTP 403 or 404), or a KV mount was only partly counted | 5 |
| The scan could not run or could not be saved (no database, wrong passphrase, no token, Vault unreachable, sealed, HTTP 5xx) | 1 |

Every skipped check is listed in the JSON under `skipped` and logged as a `check skipped` warning with the HTTP status and the next step. A KV mount gets one `skipped` entry no matter how many of its folders failed. Checks left out on purpose, such as sudo checks without `--sudo`, KV counts with `--kv=false`, or Enterprise checks on Vault Community, are listed under `not_requested` and do not change the exit code. See [exit-codes.md](exit-codes.md).

## Output

The inventory is JSON with these top-level fields:

| Field | Contents |
| --- | --- |
| `health` | Vault version, edition, cluster name and ID |
| `preflight` | Each grant Mitch checked, what the token has, and whether it is enough |
| `config` | Sanitized server configuration, as Vault returned it |
| `version_history` | Every Vault version this cluster has run |
| `plugins` | Every plugin, with `builtin` true or false; with `--sudo`, registered plugins also have `sha256`, `command` and `args` |
| `audit_devices`, `plugin_runtimes` | Only with `--sudo`. `null` means not collected; `[]` means collected and none found |
| `namespaces` | Per namespace: `secrets_engines`, `auth_methods`, `acl_policies`, `kv_counts`. The root namespace is first, with path `""` |
| `skipped`, `not_requested` | See above |

Each `kv_counts` entry looks like this:

```json
{ "mount": "secret/", "kv_version": 2, "secrets": 4, "folders": 2, "complete": true }
```

- `secrets` counts keys. For KV v2 this includes secrets whose versions were all deleted but whose metadata still exists.
- `complete` is `false` when some folders could not be listed. The counts are then a lower bound, and the reason is under `skipped`.
- `kv_counts` is `null` when counting was off or the namespace's secrets engines could not be read, and `[]` when the namespace has no KV mounts.
- Key and folder names are never recorded.

Saved scans are encrypted. JSON printed with `--no-save`, `--output` or `mitch export` is plain text. Treat it as sensitive: it describes your Vault's layout and contains every ACL policy. See [data-security.md](data-security.md).

## Tested versions

Integration tests run against Vault Community 1.19.5 and 2.2.2 on every pull request. Enterprise namespace handling is covered by unit tests against a simulated Vault, but has not been run against a real Vault Enterprise cluster yet.
