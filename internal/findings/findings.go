// Package findings checks the ACL policies in a saved scan for grants that
// are broader or riskier than they look, and for rules that do not do what
// they seem to.
//
// Every rule is deterministic: the same scan always gives the same findings.
// Policies are parsed with HCL v1, the same library and version Vault uses,
// so Mitch reads each policy the way Vault enforces it.
package findings

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jfrappier/mitch/internal/builtin"
	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/scan"
)

// Severity levels, from most to least serious.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// severityRank orders severities; a higher number is more serious.
var severityRank = map[string]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Severities lists every severity, most serious first.
func Severities() []string {
	return []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
}

// IsSeverity reports whether name is a known severity.
func IsSeverity(name string) bool {
	_, known := severityRank[name]
	return known
}

// AtOrAbove reports whether severity is at least as serious as threshold.
func AtOrAbove(severity string, threshold string) bool {
	return severityRank[severity] >= severityRank[threshold]
}

// Rule ids. They never change meaning, so scripts can filter on them.
const (
	RuleRootEquivalent     = "MITCH-POL-001"
	RuleGrantsEverything   = "MITCH-POL-002"
	RuleGrantsAllOfSys     = "MITCH-POL-003"
	RuleSudo               = "MITCH-POL-004"
	RulePrivilegeEscalates = "MITCH-POL-005"
	RuleShadowedDeny       = "MITCH-POL-006"
	RuleUnknownMount       = "MITCH-POL-007"
)

// Finding is one problem Mitch found. Policy findings (MITCH-POL-*) are about
// one path block of one policy. Git findings (MITCH-GIT-*) compare Vault with
// the Terraform in a git checkout.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	// Namespace is the namespace the finding is about, "" for root.
	Namespace string `json:"namespace"`
	// Policy is the ACL policy's name, when the finding is about a policy.
	Policy string `json:"policy"`
	// Path is the policy path (for policy findings) or the mount path (for
	// git findings about a secrets engine or auth method).
	Path string `json:"path"`
	// File is the Terraform file in the git checkout, relative to the
	// checkout, for git findings about a resource in git. Empty otherwise.
	File string `json:"file"`
	// Line is where the path block starts in the policy text (policy
	// findings), or where the resource starts in File (git findings).
	// 0 when there is no line to point at.
	Line       int    `json:"line"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

// NotAnalyzed is a policy Mitch could not check, with the reason.
type NotAnalyzed struct {
	Namespace string `json:"namespace"`
	Policy    string `json:"policy"`
	Reason    string `json:"reason"`
}

// Result is every finding for one scan.
type Result struct {
	// Findings are sorted by severity (most serious first), then namespace,
	// policy and line.
	Findings []Finding `json:"findings"`
	// NotAnalyzed lists policies that could not be parsed.
	NotAnalyzed []NotAnalyzed `json:"not_analyzed"`
	// UnknownMountCheckSkipped lists namespaces whose policies were not
	// checked for paths to missing mounts, because the scan could not list
	// the mounts there.
	UnknownMountCheckSkipped []string `json:"unknown_mount_check_skipped"`
}

// CountAtOrAbove counts findings at or above a severity.
func (r Result) CountAtOrAbove(threshold string) int {
	count := 0
	for _, finding := range r.Findings {
		if AtOrAbove(finding.Severity, threshold) {
			count++
		}
	}
	return count
}

// Analyze checks every ACL policy in a scan.
func Analyze(inventory scan.Inventory) Result {
	result := Result{Findings: []Finding{}, NotAnalyzed: []NotAnalyzed{}, UnknownMountCheckSkipped: []string{}}
	mountIndex := newMountIndex(inventory)

	for _, namespace := range inventory.Namespaces {
		mounts := mountIndex.prefixesUnder(namespace.Path)
		if mounts.allUnseen {
			result.UnknownMountCheckSkipped = append(result.UnknownMountCheckSkipped, namespace.Path)
		}

		for _, policy := range namespace.ACLPolicies {
			// "root" cannot be read as text. "default" is checked like any
			// other policy, because people edit it.
			if policy.Name == builtin.RootPolicy {
				continue
			}
			rules, err := parsePolicy(policy.Text)
			if err != nil {
				result.NotAnalyzed = append(result.NotAnalyzed, NotAnalyzed{Namespace: namespace.Path, Policy: policy.Name, Reason: err.Error()})
				continue
			}

			checked := policyCheck{namespace: namespace.Path, policy: policy.Name, rules: rules}
			result.Findings = append(result.Findings, checked.broadGrants()...)
			result.Findings = append(result.Findings, checked.shadowedDenies()...)
			if !mounts.allUnseen {
				result.Findings = append(result.Findings, checked.unknownMounts(mounts)...)
			}
		}
	}

	sortFindings(result.Findings)
	return result
}

// sortFindings orders findings so the most serious come first and the
// order is the same every run.
func sortFindings(found []Finding) {
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Policy != b.Policy {
			return a.Policy < b.Policy
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
}

// policyCheck runs the rules over one parsed policy.
type policyCheck struct {
	namespace string
	policy    string
	rules     []pathRule
}

// newFinding fills in the fields every finding about this policy shares.
func (c policyCheck) newFinding(rule pathRule, ruleID string, severity string, message string, suggestion string) Finding {
	return Finding{
		Rule:       ruleID,
		Severity:   severity,
		Namespace:  c.namespace,
		Policy:     c.policy,
		Path:       rule.Pattern,
		Line:       rule.Line,
		Message:    message,
		Suggestion: suggestion,
	}
}

// escalationProbes are request paths that change policies, auth methods or
// secrets engines. A token that can write to them can grant itself more
// access. Docs:
// https://developer.hashicorp.com/vault/api-docs/system/policies,
// https://developer.hashicorp.com/vault/api-docs/system/policy,
// https://developer.hashicorp.com/vault/api-docs/system/auth and
// https://developer.hashicorp.com/vault/api-docs/system/mounts
var escalationProbes = []string{
	"sys/policies/acl/" + probeSegment,
	"sys/policy/" + probeSegment,
	"sys/auth/" + probeSegment,
	"sys/auth/" + probeSegment + "/tune",
	"sys/mounts/" + probeSegment,
	"sys/mounts/" + probeSegment + "/tune",
}

// writeCapabilities are the capabilities that change data.
var writeCapabilities = []string{capabilityCreate, capabilityUpdate, capabilityPatch, capabilityDelete}

// broadGrants finds rules MITCH-POL-001 to 005: grants on every path, on all
// of sys/, sudo, and write access to policies, auth methods or mounts.
func (c policyCheck) broadGrants() []Finding {
	found := []Finding{}
	for _, rule := range c.rules {
		if !rule.grantsAnything() {
			continue
		}
		matcher := newPattern(rule.Pattern)
		coversEverything := matcher.isPrefix && !matcher.hasSegmentWildcards && matcher.literal == ""
		coversAllOfSys := matcher.isPrefix && !matcher.hasSegmentWildcards && matcher.literal != "" && strings.HasPrefix("sys/", matcher.literal)

		switch {
		case coversEverything && rule.has(capabilitySudo):
			found = append(found, c.newFinding(rule, RuleRootEquivalent, SeverityCritical,
				fmt.Sprintf("path %q with sudo matches every path in the namespace, which makes this policy equivalent to root", rule.Pattern),
				"Replace it with path blocks for the specific mounts and paths this policy's users need."))
		case coversEverything:
			found = append(found, c.newFinding(rule, RuleGrantsEverything, SeverityHigh,
				fmt.Sprintf("path %q grants %s on every path in the namespace, including sys/", rule.Pattern, strings.Join(rule.Capabilities, ", ")),
				"Replace it with path blocks for the specific mounts this policy needs, for example path \"secret/data/app/*\"."))
		case coversAllOfSys:
			found = append(found, c.newFinding(rule, RuleGrantsAllOfSys, SeverityHigh,
				fmt.Sprintf("path %q grants %s on all of sys/, which controls policies, auth methods, mounts and audit devices", rule.Pattern, strings.Join(rule.Capabilities, ", ")),
				"Grant only the sys/ endpoints needed, for example path \"sys/health\" or path \"sys/mounts\" with read."))
		}

		if rule.has(capabilitySudo) && !coversEverything {
			found = append(found, c.newFinding(rule, RuleSudo, SeverityMedium,
				fmt.Sprintf("path %q grants sudo, which unlocks root-protected endpoints", rule.Pattern),
				"Keep sudo only on the exact root-protected paths this policy needs, and on a separate policy given to fewer people."))
		}

		if coversEverything || coversAllOfSys {
			// Already reported as a broader finding above.
			continue
		}
		escalation := c.escalationTarget(rule, matcher)
		if escalation != "" {
			found = append(found, c.newFinding(rule, RulePrivilegeEscalates, SeverityHigh,
				fmt.Sprintf("path %q can change %s, so a token with this policy can grant itself more access", rule.Pattern, escalation),
				"Give write access to policies, auth methods and mounts only to an admin policy, ideally applied through Terraform."))
		}
	}
	return found
}

// escalationTarget names what a rule can change among policies, auth methods
// and mounts, or returns "" when it cannot change any of them.
func (c policyCheck) escalationTarget(rule pathRule, matcher pattern) string {
	canWrite := false
	for _, capability := range writeCapabilities {
		if rule.has(capability) {
			canWrite = true
		}
	}
	if !canWrite {
		return ""
	}

	targets := []string{}
	for _, probe := range escalationProbes {
		if !matcher.matches(probe) {
			continue
		}
		target := escalationName(probe)
		if !contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return strings.Join(targets, ", ")
}

// escalationName turns a probe path into words for the message.
func escalationName(probe string) string {
	switch {
	case strings.HasPrefix(probe, "sys/policies/"), strings.HasPrefix(probe, "sys/policy/"):
		return "ACL policies"
	case strings.HasPrefix(probe, "sys/auth/"):
		return "auth methods"
	default:
		return "secrets engines"
	}
}

// shadowedDenies finds MITCH-POL-006: a deny that a more specific grant in
// the same policy overrides for some paths, so it does not block everything
// it appears to.
func (c policyCheck) shadowedDenies() []Finding {
	found := []Finding{}
	for _, deny := range c.rules {
		if !deny.isDeny() {
			continue
		}
		denyPattern := newPattern(deny.Pattern)

		winners := []string{}
		for _, grant := range c.rules {
			if !grant.grantsAnything() || grant.Pattern == deny.Pattern {
				continue
			}
			grantPattern := newPattern(grant.Pattern)
			probe := grantPattern.probePath()
			if !denyPattern.matches(probe) {
				continue
			}
			if grantPattern.priorityFor(probe).beats(denyPattern.priorityFor(probe)) {
				winners = append(winners, grant.Pattern)
			}
		}
		if len(winners) == 0 {
			continue
		}
		found = append(found, c.newFinding(deny, RuleShadowedDeny, SeverityMedium,
			fmt.Sprintf("the deny on path %q does not apply where more specific paths in this policy grant access: %s", deny.Pattern, quoteAll(winners)),
			"If those paths must stay blocked, add a deny for each of them, or remove the grants. Vault uses the most specific matching path, not the deny."))
	}
	return found
}

// unknownMounts finds MITCH-POL-007: paths that point at no mount the scan
// found, often left over after a mount was disabled or moved.
func (c policyCheck) unknownMounts(mounts mountsUnder) []Finding {
	found := []Finding{}
	for _, rule := range c.rules {
		if !rule.grantsAnything() {
			continue
		}
		matcher := newPattern(rule.Pattern)
		if strings.HasPrefix(rule.Pattern, "+") || strings.HasPrefix(rule.Pattern, templateMarker) || (matcher.isPrefix && matcher.literal == "") {
			// Matches some path in every mount.
			continue
		}
		if reachesMount(matcher, mounts.known) {
			continue
		}
		// A path into a child namespace the scan could not fully list may
		// lead to a mount Mitch never saw, so it is not reported.
		if reachesMount(matcher, mounts.unseen) {
			continue
		}
		found = append(found, c.newFinding(rule, RuleUnknownMount, SeverityLow,
			fmt.Sprintf("path %q matches no secrets engine or auth method that the scan found in this namespace or below", rule.Pattern),
			"Remove the path block if the mount is gone, or fix the mount name if it moved."))
	}
	return found
}

// reachesMount reports whether the pattern can match a path inside any of
// the given mount prefixes, or the prefix itself.
func reachesMount(matcher pattern, prefixes []string) bool {
	for _, prefix := range prefixes {
		if matcher.matches(prefix+probeSegment) || matcher.matches(strings.TrimSuffix(prefix, "/")) || matcher.matches(prefix) {
			return true
		}
		// A pattern such as "secret/data/app/*" lies inside mount "secret/".
		probe := matcher.probePath()
		if strings.HasPrefix(probe, prefix) {
			return true
		}
	}
	return false
}

// mountIndex knows every mount path in every namespace.
type mountIndex struct {
	namespaces []scan.NamespaceInventory
	// unknown holds namespaces where the scan could not list secrets
	// engines, auth methods or child namespaces. Paths under such a
	// namespace may lead to mounts Mitch never saw.
	unknown map[string]bool
}

// unknownMountChecks are the scan checks that, when skipped, leave mounts
// in a namespace unseen: its secrets engines, its auth methods, or its
// child namespaces (and so every mount inside them).
var unknownMountChecks = map[string]bool{
	checks.CheckMounts:      true,
	checks.CheckAuthMethods: true,
	checks.CheckNamespaces:  true,
}

// newMountIndex records where mounts were and were not collected.
func newMountIndex(inventory scan.Inventory) mountIndex {
	index := mountIndex{namespaces: inventory.Namespaces, unknown: map[string]bool{}}
	for _, skipped := range inventory.Skipped {
		if unknownMountChecks[skipped.Check] {
			index.unknown[skipped.Namespace] = true
		}
	}
	return index
}

// mountsUnder describes every mount path a policy in one namespace can
// reach, relative to that namespace.
type mountsUnder struct {
	// known are its own mounts, and those of child namespaces (written
	// "child/secret/"), which a parent namespace's policy can grant.
	known []string
	// unseen are relative prefixes, such as "team-a/", under which the scan
	// could not list everything. Paths there are not checked.
	unseen []string
	// allUnseen is true when the namespace itself could not be listed, so
	// no path in its policies can be checked.
	allUnseen bool
}

// prefixesUnder returns the mount paths a policy in namespace can reach.
func (m mountIndex) prefixesUnder(namespace string) mountsUnder {
	under := mountsUnder{known: []string{}, unseen: []string{}}
	for _, candidate := range m.namespaces {
		if !strings.HasPrefix(candidate.Path, namespace) {
			continue
		}
		relative := strings.TrimPrefix(candidate.Path, namespace)
		for _, mount := range candidate.SecretsEngines {
			under.known = append(under.known, relative+mount.Path)
		}
		for _, mount := range candidate.AuthMethods {
			under.known = append(under.known, relative+"auth/"+mount.Path)
		}
		// Mounts every namespace has, even when a scan list leaves them out.
		under.known = append(under.known, relative+"sys/", relative+"identity/", relative+"cubbyhole/", relative+"auth/token/")
	}

	for unknownNamespace := range m.unknown {
		if !strings.HasPrefix(unknownNamespace, namespace) {
			continue
		}
		relative := strings.TrimPrefix(unknownNamespace, namespace)
		if relative == "" {
			under.allUnseen = true
		}
		under.unseen = append(under.unseen, relative)
	}
	sort.Strings(under.unseen)
	return under
}

// contains reports whether list holds value.
func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// quoteAll writes values as "a", "b".
func quoteAll(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return strings.Join(quoted, ", ")
}
