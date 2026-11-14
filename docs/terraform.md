# Generating Terraform

`mitch terraform` writes Terraform configuration for the Vault setup in a saved scan, with [import blocks](https://developer.hashicorp.com/terraform/language/import) so Terraform adopts what already exists instead of creating it again. It reads only the saved, encrypted scan and never contacts Vault.

This is the first step toward managing Vault as code (see [design-decisions.md](design-decisions.md#git-as-the-source-of-truth)): generate, review, commit to git, and let Terraform own the configuration from then on.

You need Terraform 1.5 or later. The files use the `hashicorp/vault` provider, version 5.

## 1. Generate

```shell
mitch terraform --output-dir vault-terraform
```

This uses the newest saved scan. Pass `--scan ID` for another one. The folder must not exist yet, or be empty, so existing files are never overwritten.

For the most complete result, scan with a token that can read everything you want managed. Audit devices are only included when the scan ran with `--sudo`; see [scanning.md](scanning.md).

## 2. Check the plan

```shell
cd vault-terraform
terraform init
terraform plan
```

Terraform reads `VAULT_ADDR` and `VAULT_TOKEN` like the Vault CLI does. The token needs to read every imported object; for audit devices that includes `sudo` on `sys/audit`.

The plan should end with something like:

```text
Plan: 14 to import, 0 to add, 1 to change, 0 to destroy.
```

That example has one auth method; the next paragraph explains its one change.

One change is expected for each auth method: `+ disable_remount = false`. That is a setting of the Terraform provider only; Vault has no such setting. Import leaves it empty in Terraform state, and the provider's default is `false`, so Terraform plans to record it. Applying it writes only Terraform state and sends nothing to Vault ([provider source](https://github.com/hashicorp/terraform-provider-vault/blob/v5.13.0/internal/provider/schema_util.go)). So with 2 auth methods, expect `2 to change`.

Anything else to add, change or destroy is a difference between the files and Vault, usually because Vault changed after the scan, or a setting Mitch does not record yet (see [What is left out](#what-is-left-out)). Review it before going further: applying it changes Vault.

## 3. Import

```shell
terraform apply
```

This only records the existing objects in Terraform state. After that, change Vault by editing these files. You can delete `imports.tf` once the apply succeeds.

## What is generated

| File | Contents |
| --- | --- |
| `versions.tf` | The Terraform and provider versions. |
| `providers.tf` | The provider, plus one alias per Enterprise namespace. |
| `namespaces.tf` | [`vault_namespace`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/namespace) for each namespace. |
| `secrets_engines.tf` | [`vault_mount`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/mount) for each secrets engine: path, type, description, TTLs, options, local, seal wrap, external entropy and plugin version. |
| `auth_methods.tf` | [`vault_auth_backend`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/auth_backend) for each auth method, with TTLs and token type in its `tune` block. |
| `policies.tf` and `policies/` | [`vault_policy`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/policy) for each ACL policy. Each policy's text is its own `.hcl` file under `policies/<namespace>/`, loaded with `file()`, so policies are reviewed as policy files in git. Each file holds exactly the text Vault returned; if an editor adds a final line break, the plan shows a policy change. |
| `audit_devices.tf` | [`vault_audit`](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/audit) for each audit device. |
| `imports.tf` | One import block per resource. |

Files are created readable only by you (`0600`), and folders `0700`. They describe your Vault's layout and contain every ACL policy, so treat them as sensitive. Mitch logs a warning when it writes them.

### Namespaces

Each namespace gets its own provider alias with `namespace` set, and every resource in that namespace uses it. Import IDs are then plain paths, which is how the provider documents [importing namespaced resources](https://registry.terraform.io/providers/hashicorp/vault/latest/docs#importing-namespaced-resources). A namespace itself is created with its parent's provider.

### What is left out

- **Secret values, always.** Importing KV secrets would copy their values into Terraform state.
- **Objects Vault creates itself:** the `sys/`, `identity/`, `cubbyhole/` and (Vault 2.x) `agent-registry/` secrets engines, the `token/` auth method, and the `root` policy. The `default` policy is included, because you can edit it, but `terraform destroy` cannot remove it.
- **Anything the scan could not read.** Mitch logs a warning for each skipped check and for audit devices when the scan ran without `--sudo`.

> **Not built yet:** these mount settings are not recorded by the scan, so they are not written: listing visibility, passthrough request headers, allowed response headers, and audit non-HMAC request and response keys. If you set any of them, the plan shows a change that removes them. Add them to the files by hand before you apply.

> **Not built yet:** settings inside secrets engines and auth methods, such as LDAP or OIDC configuration and roles. These have their own resources, and some, such as an LDAP `bindpass`, need values Vault never returns.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--output-dir DIR` | required | Folder to write to. It must not exist yet, or be empty. |
| `--scan ID` | newest scan | The scan to generate from. |
| `--db PATH`, `--passphrase-file FILE` | | See [saving-scans.md](saving-scans.md). |
