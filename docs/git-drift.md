---
title: Comparing with git
weight: 6
---

Mitch can compare a saved scan with the Terraform in a local git checkout, and report every ACL policy, secrets engine and auth method that is in Vault but not in git, in git but not in Vault, or different between the two. This is how you confirm that Vault is managed as code, and catch changes someone made by hand.

Mitch reads the `.tf` files itself. It never runs Terraform, never clones, and never needs git credentials. Like the rest of the report, it never contacts Vault: it compares the files with the saved scan.

## 1. Point the report at your checkout

```shell
mitch report --repo ~/src/vault-terraform
```

`--repo` is the folder that holds your Vault Terraform. Mitch reads every `.tf` and `.tf.json` file in it and in every folder below it, except `.terraform` and `.git`. Differences show up in the **Findings** section, with the Terraform file and line. The **Git comparison** section says how many files and resources were read, and lists anything Mitch could not check.

If you have no Terraform for Vault yet, `mitch terraform` writes a starting point with import blocks. See [Generating Terraform](terraform.md).

## 2. Fail a CI job on drift

```shell
mitch report --repo . --fail-on medium
```

Run this from the checkout in CI. Every git rule below is `medium` or higher, except whitespace-only differences, so `--fail-on medium` fails the job on any real drift. See [Policy findings](findings.md#2-fail-a-ci-job-on-findings) for how `--fail-on` works.

## Without --repo

Every report without `--repo` gets exactly one high finding, MITCH-GIT-001, in namespace `(all)`. It says Mitch cannot confirm that Vault is managed as code. It is reported once, not per policy or mount, and it does not change any other finding. `--fail-on` never counts it, because a CI job often cannot reach the repository where a team keeps its Terraform; a report without `--repo` passes or fails on its other findings only. The reason is in [Design decisions](design-decisions.md#git-as-the-source-of-truth).

## Rules

| Rule | Severity | What it finds |
| --- | --- | --- |
| MITCH-GIT-001 | high | No `--repo` was given. Never counted by `--fail-on`. |
| MITCH-GIT-002 | high | A policy's text in Vault is not the text in git. It was changed outside Terraform, or git has changes not yet applied. |
| MITCH-GIT-003 | low | A policy differs from git only in spaces or line breaks. `terraform plan` still shows it as a change. |
| MITCH-GIT-004 | medium | A policy is in Vault, but no `vault_policy` resource in git manages it. |
| MITCH-GIT-005 | medium | A `vault_policy` resource is in git, but the policy is not in Vault. |
| MITCH-GIT-006 | medium | A secrets engine or auth method is enabled in Vault, but no resource in git manages it. |
| MITCH-GIT-007 | medium | A resource in git enables a secrets engine or auth method that is not enabled in Vault. |
| MITCH-GIT-008 | medium | A mount's type in Vault is not the type in git. Changing the type in Terraform replaces the mount, which deletes everything in it. |

Never reported as "not in git": the `root` and `default` policies, and the mounts Vault creates itself (`sys/`, `identity/`, `cubbyhole/`, `agent-registry/` and `token/`). If git does manage `default`, its text is compared like any other policy.

## What Mitch reads

| Terraform resource | Compared as |
| --- | --- |
| `vault_policy` | ACL policy, by `name` and `policy` text |
| `vault_mount` | Secrets engine, by `path` and `type` |
| `vault_auth_backend` | Auth method, by `path` (default: the `type`) and `type` |
| `vault_database_secrets_mount`, `vault_ad_secret_backend`, `vault_aws_secret_backend`, `vault_azure_secret_backend`, `vault_consul_secret_backend`, `vault_gcp_secret_backend`, `vault_gcpkms_secret_backend`, `vault_kmip_secret_backend`, `vault_kubernetes_secret_backend`, `vault_ldap_secret_backend`, `vault_nomad_secret_backend`, `vault_rabbitmq_secret_backend`, `vault_terraform_cloud_secret_backend` | Secrets engine, by path |
| `vault_gcp_auth_backend`, `vault_github_auth_backend`, `vault_jwt_auth_backend`, `vault_ldap_auth_backend`, `vault_okta_auth_backend`, `vault_saml_auth_backend` | Auth method, by path |

Where a resource leaves its path out, Mitch uses the default from the [Vault provider docs](https://registry.terraform.io/providers/hashicorp/vault/latest/docs), for example `aws` for `vault_aws_secret_backend`. Resources that only configure an existing mount, such as `vault_kubernetes_auth_backend_config`, are not read.

Namespaces follow the provider's rules: a resource's `namespace` is relative to the `namespace` of its `provider "vault"` block, and `provider = vault.alias` picks that block ([provider namespace docs](https://registry.terraform.io/providers/hashicorp/vault/latest/docs#namespace)). Enterprise namespaces are untested.

Mitch works out plain values, `file("...")` for files inside the checkout, `path.module`, and references to another resource's path or name, such as `vault_mount.kv.path`.

## What Mitch cannot check

Anything that needs Terraform to run is listed under **Not checked** in the Git comparison section, with its file and line, and is never reported as drift:

- values from variables, locals, module inputs or data sources;
- resources with `count` or `for_each`;
- `file()` paths outside the checkout, which Mitch refuses to read;
- resources inside modules that are not in the checkout.

When Mitch cannot tell which policy or mount a resource manages, it could be any of them. So Mitch does not report policies or mounts of that kind as "not in git", in that namespace, or in every namespace when the namespace is unknown too. The report says so under **Not compared**.

The comparison also skips anything the scan could not list. If the scan could not list policies in a namespace, for example, no policy in that namespace is compared, and the report says so under **Not compared**.

## In the web UI

`mitch serve --repo PATH` compares every report page with the checkout. Mitch reads the checkout once, when `mitch serve` starts; restart it to pick up new commits. See [The web UI](web-ui.md).

## Errors

| Problem | What happens |
| --- | --- |
| `--repo` does not exist, or is a file | Exit code 2, before the passphrase is read. |
| A `.tf` file is not valid HCL | Exit code 1. The log names the file and line, the same error `terraform validate` gives. |
| The folder holds no `.tf` files | The report runs, and Mitch logs a warning, because everything in Vault will show as not in git. |

## JSON fields

The JSON report has a `git` object: `repo_given`, `path`, `files_read`, `resources`, `not_checked` (each with `address`, `file`, `line` and `reason`) and `not_compared` (plain sentences). Git findings are in the same `findings` list as policy findings, with `file` set to the Terraform file, relative to the checkout, and `line` to the line in that file.
