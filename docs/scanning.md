# Scanning Vault

`mitch scan` reads a Vault cluster and prints a JSON inventory of what it found. It never writes to Vault and never reads secret values.

> **Not built yet:** counting secrets under KV paths, storing scans, and comparing scans. Today the inventory is printed as JSON.

## 1. Create the Mitch policy and token

Print the base policy, load it into Vault, and create a token for Mitch:

```shell
mitch policy > mitch-scanner.hcl
vault policy write mitch-scanner mitch-scanner.hcl
vault token create -policy=mitch-scanner -ttl=1h
```

The base policy grants only `read` and `list` on the endpoints Mitch uses, plus `update` on `sys/capabilities-self` so Mitch can check its own permissions before scanning. It never grants `sudo` and never grants access to secret data.

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

mitch scan --output inventory.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--sudo` | off | Also run checks that need `sudo`. |
| `--output FILE` | standard output | Write the JSON to a file. The file is created readable only by you (`0600`). |
| `--timeout DURATION` | `10m` | Stop the scan if it takes longer than this, for example `30s` or `1h`. |

`VAULT_NAMESPACE` is ignored on purpose. Mitch always starts at the root namespace and, on Vault Enterprise, scans every child namespace it can see.

## What the scan does

1. **Health:** reads `sys/health` to get the Vault version and edition. A sealed or uninitialized Vault stops the scan.
2. **Preflight:** asks `sys/capabilities-self` which grants the token has. Each missing grant is logged as a warning, and that check is skipped instead of failing later. If the token cannot call `sys/capabilities-self`, Mitch tries every check and records each failure.
3. **Cluster-wide checks** (root namespace only): sanitized server config, version history, plugin catalog, and with `--sudo`, audit devices, registered plugin details and plugin runtimes.
4. **Per-namespace checks:** secrets engines, auth methods, and ACL policies with their text. On Vault Enterprise, Mitch walks the namespace tree and repeats these in every namespace.

## Exit codes and skipped checks

| Result | Exit code |
| --- | --- |
| Every check ran | 0 |
| Some checks were skipped (missing grant, HTTP 403 or 404) | 5 |
| The scan could not run (no token, Vault unreachable, sealed, HTTP 5xx) | 1 |

Every skipped check is listed in the JSON under `skipped` and logged as a `check skipped` warning with the HTTP status and the next step. Checks left out on purpose, such as sudo checks without `--sudo` or Enterprise checks on Vault Community, are listed under `not_requested` and do not change the exit code. See [exit-codes.md](exit-codes.md).

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
| `namespaces` | Per namespace: `secrets_engines`, `auth_methods`, `acl_policies`. The root namespace is first, with path `""` |
| `skipped`, `not_requested` | See above |

The inventory is plain text. Treat it as sensitive: it describes your Vault's layout and contains every ACL policy. See [data-security.md](data-security.md).

## Tested versions

Integration tests run against Vault Community 1.19.5 and 2.2.2 on every pull request. Enterprise namespace handling is covered by unit tests against a simulated Vault, but has not been run against a real Vault Enterprise cluster yet.
