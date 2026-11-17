---
title: Policy findings
weight: 4
---

Mitch checks every ACL policy in a saved scan for grants that are broader than they look, and for rules that do not do what they seem to. Findings show up in `mitch report`, in the JSON report, and in the `mitch serve` report page. `mitch report --fail-on` turns them into an exit code for CI.

Findings are worked out from the saved scan each time you run a report. They are not stored, so a newer Mitch with better rules gives better findings on your old scans too. Mitch never contacts Vault to do this.

## 1. See the findings

```shell
mitch report
```

The **Policy findings** section lists each finding, most serious first, with its rule, namespace, policy, path, the line where the path block starts, what is wrong, and what to do about it. The summary counts findings by severity.

## 2. Fail a CI job on findings

```shell
mitch report --fail-on high
```

The report prints as usual. If any finding is at or above `high`, Mitch logs an error with the count and exits with code 4 (see [Exit codes](exit-codes.md)). Without `--fail-on`, findings never change the exit code.

`--fail-on` takes `critical`, `high`, `medium` or `low`. Any other value fails with exit code 2 before the passphrase is read.

## Severities

| Severity | Meaning |
| --- | --- |
| critical | The policy is as good as root. |
| high | The policy can reach everything, all of `sys/`, or can grant itself more access. |
| medium | Risky but sometimes needed, or a rule that does not do what it appears to. |
| low | Clean-up: the rule does nothing useful. |

## Rules

Rule ids never change meaning, so scripts can filter on them.

| Rule | Severity | What it finds |
| --- | --- | --- |
| MITCH-POL-001 | critical | `path "*"` with `sudo`. It matches every path in the namespace, so the policy is equivalent to root. |
| MITCH-POL-002 | high | `path "*"` with any other capability. It covers every mount and all of `sys/`. |
| MITCH-POL-003 | high | A glob that covers all of `sys/`, such as `path "sys/*"` or `path "s*"`. `sys/` controls policies, auth methods, mounts and audit devices. |
| MITCH-POL-004 | medium | `sudo` on any other path. `sudo` unlocks root-protected endpoints. |
| MITCH-POL-005 | high | `create`, `update`, `patch` or `delete` on a path that changes ACL policies (`sys/policies/acl/...`, `sys/policy/...`), auth methods (`sys/auth/...`) or secrets engines (`sys/mounts/...`). A token with this policy can grant itself more access. Not repeated when 002 or 003 already covers the path. |
| MITCH-POL-006 | medium | A `deny` that a more specific grant in the same policy overrides for some paths. Vault applies the most specific matching path, not the deny, so the deny does not block everything it appears to. |
| MITCH-POL-007 | low | A path that matches no secrets engine or auth method the scan found, in the policy's namespace or the namespaces below it. Usually left over after a mount was disabled or moved. |

### Example

```hcl
path "secret/*" {
  capabilities = ["deny"]
}

path "secret/data/*" {
  capabilities = ["read"]
}
```

This gives MITCH-POL-006 on `secret/*`: for `secret/data/app`, Vault picks `secret/data/*` because its glob starts later, so the read is allowed. To block those paths, deny them directly or remove the grant.

## How Mitch reads policies

Mitch parses each policy with the same library and version Vault uses for ACL policies, `github.com/hashicorp/hcl` v1 (HashiCorp's `v1.0.1-vault` fork). HCL and JSON policies both work, and the old `policy = "read"` shorthand is expanded exactly as Vault expands it. A path block with `deny` keeps only `deny`, as in Vault.

When more than one path block matches a request, Mitch picks the winner with Vault's priority rules. See [Priority matching](https://developer.hashicorp.com/vault/docs/concepts/policies#priority-matching) in the Vault docs. A path segment holding an identity template, such as `{{identity.entity.id}}`, is treated like `+`, because Mitch cannot know its value.

## What findings do not cover

- **Each policy is checked on its own.** A token usually has several policies, and Vault merges them. A deny in one policy and a grant in another are not compared.
- **Unparsable policies are not checked.** They are listed under the findings with the parser's error, and Mitch logs a warning. Vault checks a policy when it is written, so this should not happen; if it does, Mitch reads that policy differently from Vault, and it is worth reporting as a Mitch bug.
- **Missing mounts are not reported where the scan could not list mounts.** If the scan could not list secrets engines, auth methods or child namespaces in a namespace, paths into that namespace are not checked for MITCH-POL-007. The report lists namespaces that were skipped completely, and the skipped checks appear under **Scan gaps**.
- **Mitch's own sudo add-on is flagged, on purpose.** If you loaded it, it gets three MITCH-POL-004 (medium) findings, one per root-protected path it needs. Mitch's base and KV policies get none.
- **The `root` policy is skipped.** Vault does not return its text. The `default` policy is checked like any other, because people edit it.
- **Sentinel policies** (Enterprise) are not read in v1.
- **No folder-level suggestions.** Mitch does not suggest replacing a glob such as `secret/data/*` with the exact folders in use, because that needs folder names, and Mitch never stores them (see [Design decisions](design-decisions.md#kv-secrets-are-counted-not-named)).
- **Not built yet:** the "no git repository" finding, which comes with the planned `--repo` option. See [Design decisions](design-decisions.md#git-as-the-source-of-truth).

## JSON fields

In the JSON report, `findings` is a list of objects with `rule`, `severity`, `namespace`, `policy`, `path`, `line`, `message` and `suggestion`. `summary.findings` has the counts by severity. `policies_not_analyzed` lists policies that could not be parsed, with a `reason`. `unknown_mount_check_skipped` lists namespaces where MITCH-POL-007 did not run. All three lists are `[]` when empty.
