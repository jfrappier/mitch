package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jfrappier/mitch/internal/builtin"
	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/findings"
	"github.com/jfrappier/mitch/internal/scan"
)

// Rule ids for git findings. They never change meaning, so scripts can
// filter on them.
const (
	RuleNoRepo            = "MITCH-GIT-001"
	RulePolicyTextDiffers = "MITCH-GIT-002"
	RulePolicyWhitespace  = "MITCH-GIT-003"
	RulePolicyNotInGit    = "MITCH-GIT-004"
	RulePolicyNotInVault  = "MITCH-GIT-005"
	RuleMountNotInGit     = "MITCH-GIT-006"
	RuleMountNotInVault   = "MITCH-GIT-007"
	RuleMountTypeDiffers  = "MITCH-GIT-008"
)

// allNamespacesForMessage is how messages name every namespace at once.
const allNamespacesForMessage = "every namespace"

// NoRepoFinding is the one finding a report gets when no git checkout was
// given: Vault's configuration cannot be confirmed as managed as code.
// It is reported once, never per mount or per policy.
func NoRepoFinding() findings.Finding {
	return findings.Finding{
		Rule:       RuleNoRepo,
		Severity:   findings.SeverityHigh,
		Message:    "no git repository was given (--repo), so Mitch cannot confirm that Vault's policies and mounts are managed as code",
		Suggestion: "Keep your Vault policies and configuration as Terraform in git, and run mitch report --repo <checkout>. \"mitch terraform\" writes a starting point.",
	}
}

// Result is the outcome of comparing one scan with one checkout.
type Result struct {
	Findings []findings.Finding `json:"findings"`
	// NotCompared says, in plain words, what was left out and why: for
	// example a namespace whose policies the scan could not list.
	NotCompared []string `json:"not_compared"`
}

// objectKey identifies one Vault object: its kind, namespace and name.
type objectKey struct {
	kind      string
	namespace string
	name      string
}

// Compare reports the differences between a scan and a checkout.
func Compare(repo Repo, inventory scan.Inventory) Result {
	result := Result{Findings: []findings.Finding{}, NotCompared: []string{}}
	comparer := newComparer(repo, inventory)

	comparer.compareGitToVault(&result)
	comparer.compareVaultToGit(&result)

	result.NotCompared = append(result.NotCompared, comparer.notCompared...)
	sort.Strings(result.NotCompared)
	result.NotCompared = unique(result.NotCompared)
	sortGitFindings(result.Findings)
	return result
}

// comparer holds both sides, indexed for lookups.
type comparer struct {
	repo      Repo
	inventory scan.Inventory

	// inGit maps each object to the resource that manages it.
	inGit map[objectKey]Resource
	// inVault maps each object to what the scan found.
	vaultPolicies map[objectKey]scan.Policy
	vaultMounts   map[objectKey]scan.Mount
	// namespaces the scan found, such as "" and "team-a/".
	namespaces map[string]bool

	// skipped holds "kind|namespace" pairs the scan could not list.
	skipped map[string]bool
	// namespacesUnlisted is true when the scan could not list namespaces
	// somewhere, so a namespace missing from the scan may still exist.
	namespacesUnlisted bool

	notCompared []string
}

func newComparer(repo Repo, inventory scan.Inventory) *comparer {
	c := &comparer{
		repo:          repo,
		inventory:     inventory,
		inGit:         map[objectKey]Resource{},
		vaultPolicies: map[objectKey]scan.Policy{},
		vaultMounts:   map[objectKey]scan.Mount{},
		namespaces:    map[string]bool{},
		skipped:       map[string]bool{},
	}

	for _, resource := range repo.Resources {
		key := objectKey{kind: resource.Kind, namespace: resource.Namespace, name: resource.Name}
		if _, duplicate := c.inGit[key]; duplicate {
			continue
		}
		c.inGit[key] = resource
	}

	for _, namespace := range inventory.Namespaces {
		c.namespaces[namespace.Path] = true
		for _, policy := range namespace.ACLPolicies {
			c.vaultPolicies[objectKey{kind: KindPolicy, namespace: namespace.Path, name: policy.Name}] = policy
		}
		for _, mount := range namespace.SecretsEngines {
			c.vaultMounts[objectKey{kind: KindSecretsEngine, namespace: namespace.Path, name: mount.Path}] = mount
		}
		for _, mount := range namespace.AuthMethods {
			c.vaultMounts[objectKey{kind: KindAuthMethod, namespace: namespace.Path, name: mount.Path}] = mount
		}
	}

	// Checks the scan skipped. Docs for each check: internal/checks.
	kindOfCheck := map[string]string{
		checks.CheckPolicyList:  KindPolicy,
		checks.CheckMounts:      KindSecretsEngine,
		checks.CheckAuthMethods: KindAuthMethod,
	}
	for _, skipped := range inventory.Skipped {
		if skipped.Check == checks.CheckNamespaces {
			c.namespacesUnlisted = true
			continue
		}
		if kind, found := kindOfCheck[skipped.Check]; found {
			c.skipped[kind+"|"+skipped.Namespace] = true
			c.notCompared = append(c.notCompared, fmt.Sprintf("%ss in namespace %s: the scan could not list them (%s)", kind, label(skipped.Namespace), skipped.Check))
		}
	}
	if c.namespacesUnlisted {
		c.notCompared = append(c.notCompared, "resources in namespaces the scan did not find: the scan could not list every namespace, so they may exist")
	}
	return c
}

// compareGitToVault checks every resource in git against the scan.
func (c *comparer) compareGitToVault(result *Result) {
	for _, resource := range c.repo.Resources {
		key := objectKey{kind: resource.Kind, namespace: resource.Namespace, name: resource.Name}
		if c.inGit[key].Address != resource.Address {
			// A second resource for the same object; the first one counts.
			continue
		}
		if c.skipped[resource.Kind+"|"+resource.Namespace] {
			continue
		}
		if !c.namespaces[resource.Namespace] && c.namespacesUnlisted {
			continue
		}

		if resource.Kind == KindPolicy {
			c.comparePolicy(resource, key, result)
		} else {
			c.compareMount(resource, key, result)
		}
	}
}

// comparePolicy checks one vault_policy against the scan.
func (c *comparer) comparePolicy(resource Resource, key objectKey, result *Result) {
	policy, inVault := c.vaultPolicies[key]
	if !inVault {
		result.Findings = append(result.Findings, gitFinding(resource, RulePolicyNotInVault, findings.SeverityMedium,
			fmt.Sprintf("policy %q is in git (%s) but not in Vault", resource.Name, resource.Address),
			"Run terraform apply if the policy should exist, or remove the resource from git if it was deleted on purpose."))
		return
	}
	if !resource.PolicyTextKnown {
		return
	}
	if policy.Text == "" {
		c.notCompared = append(c.notCompared, fmt.Sprintf("text of policy %q in namespace %s: the scan could not read it", policy.Name, label(key.namespace)))
		return
	}
	if policy.Text == resource.PolicyText {
		return
	}
	if strings.Join(strings.Fields(policy.Text), " ") == strings.Join(strings.Fields(resource.PolicyText), " ") {
		result.Findings = append(result.Findings, gitFinding(resource, RulePolicyWhitespace, findings.SeverityLow,
			fmt.Sprintf("policy %q differs from git only in spaces or line breaks, which terraform plan still shows as a change", resource.Name),
			"Make the file in git match Vault exactly, or run terraform apply to write git's version."))
		return
	}
	result.Findings = append(result.Findings, gitFinding(resource, RulePolicyTextDiffers, findings.SeverityHigh,
		fmt.Sprintf("policy %q in Vault is not the text in git (%s); it was changed outside Terraform, or git has changes not yet applied", resource.Name, resource.Address),
		"Compare the two with mitch export and the file in git. Keep the version you want in git, then run terraform apply."))
}

// compareMount checks one secrets engine or auth method resource.
func (c *comparer) compareMount(resource Resource, key objectKey, result *Result) {
	mount, inVault := c.vaultMounts[key]
	if !inVault {
		finding := gitFinding(resource, RuleMountNotInVault, findings.SeverityMedium,
			fmt.Sprintf("%s %q is in git (%s) but not enabled in Vault", resource.Kind, resource.Name, resource.Address),
			"Run terraform apply if it should be enabled, or remove the resource from git if it was disabled on purpose.")
		finding.Path = resource.Name
		result.Findings = append(result.Findings, finding)
		return
	}
	if resource.MountType != "" && mount.Type != resource.MountType {
		finding := gitFinding(resource, RuleMountTypeDiffers, findings.SeverityMedium,
			fmt.Sprintf("%s %q is type %q in Vault but type %q in git (%s)", resource.Kind, resource.Name, mount.Type, resource.MountType, resource.Address),
			"Check which is right. Changing the type in Terraform replaces the mount, which deletes everything in it.")
		finding.Path = resource.Name
		result.Findings = append(result.Findings, finding)
	}
}

// compareVaultToGit reports Vault objects no resource in git manages.
func (c *comparer) compareVaultToGit(result *Result) {
	unknown := c.unknownScopes()

	for key, policy := range c.vaultPolicies {
		if policy.Name == builtin.RootPolicy || policy.Name == builtin.DefaultPolicy {
			// Built in; Terraform may manage "default", but need not.
			continue
		}
		if _, managed := c.inGit[key]; managed || unknown.covers(key) {
			continue
		}
		result.Findings = append(result.Findings, findings.Finding{
			Rule: RulePolicyNotInGit, Severity: findings.SeverityMedium,
			Namespace: key.namespace, Policy: policy.Name,
			Message:    fmt.Sprintf("policy %q is in Vault but no vault_policy resource in git manages it", policy.Name),
			Suggestion: "Add it to git as a vault_policy resource (mitch terraform writes one with an import block), or delete it from Vault if it is not needed.",
		})
	}

	for key, mount := range c.vaultMounts {
		if key.kind == KindSecretsEngine && builtin.IsSecretsEngine(mount.Path) {
			continue
		}
		if key.kind == KindAuthMethod && builtin.IsAuthMethod(mount.Path) {
			continue
		}
		if _, managed := c.inGit[key]; managed || unknown.covers(key) {
			continue
		}
		result.Findings = append(result.Findings, findings.Finding{
			Rule: RuleMountNotInGit, Severity: findings.SeverityMedium,
			Namespace: key.namespace, Path: mount.Path,
			Message:    fmt.Sprintf("%s %q (type %s) is enabled in Vault but no resource in git manages it", key.kind, mount.Path, mount.Type),
			Suggestion: "Add it to git (mitch terraform writes a resource with an import block), or disable it in Vault if it is not needed.",
		})
	}
}

// unknownScope records which Vault objects a not-checked resource might be,
// so they are not reported as "not in git".
type unknownScope struct {
	// byKindNamespace holds "kind|namespace" pairs.
	byKindNamespace map[string]bool
	// byKind holds kinds whose namespace is unknown, so it could be any.
	byKind map[string]bool
}

func (c *comparer) unknownScopes() unknownScope {
	scope := unknownScope{byKindNamespace: map[string]bool{}, byKind: map[string]bool{}}
	for _, gap := range c.repo.NotChecked {
		if gap.identityKnown {
			continue
		}
		if !gap.namespaceKnown {
			scope.byKind[gap.kind] = true
			c.notCompared = append(c.notCompared, fmt.Sprintf("%ss in Vault but not in git, in %s: %s could be any of them (%s:%d)", gap.kind, allNamespacesForMessage, gap.Address, gap.File, gap.Line))
			continue
		}
		scope.byKindNamespace[gap.kind+"|"+gap.namespace] = true
		c.notCompared = append(c.notCompared, fmt.Sprintf("%ss in Vault but not in git, in namespace %s: %s could be any of them (%s:%d)", gap.kind, label(gap.namespace), gap.Address, gap.File, gap.Line))
	}
	return scope
}

func (s unknownScope) covers(key objectKey) bool {
	return s.byKind[key.kind] || s.byKindNamespace[key.kind+"|"+key.namespace]
}

// gitFinding fills in the fields every finding about a resource in git shares.
func gitFinding(resource Resource, rule string, severity string, message string, suggestion string) findings.Finding {
	finding := findings.Finding{
		Rule: rule, Severity: severity, Namespace: resource.Namespace,
		File: resource.File, Line: resource.Line, Message: message, Suggestion: suggestion,
	}
	if resource.Kind == KindPolicy {
		finding.Policy = resource.Name
	}
	return finding
}

// label shows the root namespace as "(root)".
func label(namespace string) string {
	if namespace == "" {
		return "(root)"
	}
	return namespace
}

// unique removes repeated lines from a sorted list.
func unique(sorted []string) []string {
	kept := []string{}
	for index, line := range sorted {
		if index > 0 && sorted[index-1] == line {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

// sortGitFindings orders findings by severity, then namespace, then the
// object, so output is stable.
func sortGitFindings(found []findings.Finding) {
	sort.SliceStable(found, func(i, j int) bool {
		left, right := found[i], found[j]
		if left.Severity != right.Severity {
			return findings.AtOrAbove(left.Severity, right.Severity)
		}
		if left.Namespace != right.Namespace {
			return left.Namespace < right.Namespace
		}
		if left.Policy+left.Path != right.Policy+right.Path {
			return left.Policy+left.Path < right.Policy+right.Path
		}
		return left.Rule < right.Rule
	})
}
