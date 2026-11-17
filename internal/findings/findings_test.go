package findings

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/scan"
)

func TestParseHCLPolicy(t *testing.T) {
	text := `
# comment
path "secret/data/app/*" {
  capabilities = ["read", "list"]
}

path "/sys/health" {
  policy = "read"
}

path "secret/data/app/locked" {
  capabilities = ["read", "deny"]
}
`
	rules, err := parsePolicy(text)
	if err != nil {
		t.Fatalf("parsePolicy failed: %v", err)
	}
	expected := []pathRule{
		{Pattern: "secret/data/app/*", Line: 3, Capabilities: []string{"read", "list"}},
		{Pattern: "sys/health", Line: 7, Capabilities: []string{"read", "list"}},
		{Pattern: "secret/data/app/locked", Line: 11, Capabilities: []string{"deny"}},
	}
	if !reflect.DeepEqual(rules, expected) {
		t.Errorf("rules:\ngot  %+v\nwant %+v", rules, expected)
	}
}

func TestParseJSONPolicy(t *testing.T) {
	// Vault accepts policies written as JSON too.
	text := `{"path": {"secret/*": {"capabilities": ["create", "update"]}}}`
	rules, err := parsePolicy(text)
	if err != nil {
		t.Fatalf("parsePolicy failed: %v", err)
	}
	if len(rules) != 1 || rules[0].Pattern != "secret/*" || !rules[0].has("update") {
		t.Errorf("unexpected rules: %+v", rules)
	}
}

func TestOldPolicyShorthand(t *testing.T) {
	cases := map[string][]string{
		"deny":  {"deny"},
		"read":  {"read", "list"},
		"write": {"create", "read", "update", "delete", "list"},
		"sudo":  {"create", "read", "update", "delete", "list", "sudo"},
	}
	for shorthand, expected := range cases {
		got, err := expandCapabilities(pathBlock{Policy: shorthand})
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Errorf("policy = %q: got %v (%v), want %v", shorthand, got, err, expected)
		}
	}
	_, err := expandCapabilities(pathBlock{Policy: "admin"})
	if err == nil {
		t.Error("an unknown shorthand must be an error")
	}
}

func TestParseErrors(t *testing.T) {
	for _, text := range []string{`path "x" {`, `"just a string"`} {
		_, err := parsePolicy(text)
		if err == nil {
			t.Errorf("parsePolicy(%q) should fail", text)
		}
	}
}

// The matching examples from Vault's policy docs:
// https://developer.hashicorp.com/vault/docs/concepts/policies#policy-syntax
func TestMatchesLikeVaultDocs(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		matches bool
	}{
		{"secret/foo", "secret/foo", true},
		{"secret/foo", "secret/food", false},
		{"secret/foo", "secret/foo/bar", false},
		{"secret/bar/*", "secret/bar/zip", true},
		{"secret/bar/*", "secret/bar/zip/zap", true},
		{"secret/bar/*", "secret/bars/zip", false},
		{"secret/zip-*", "secret/zip-zap", true},
		{"secret/zip-*", "secret/zip-zap/zong", true},
		{"secret/zip-*", "secret/zip/zap", false},
		{"secret/+/teamb", "secret/foo/teamb", true},
		{"secret/+/teamb", "secret/foo/bar/teamb", false},
		{"secret/+/+/teamb", "secret/foo/bar/teamb", true},
		{"secret/+/teamb/*", "secret/foo/teamb/x/y", true},
		{"*", "anything/at/all", true},
		{"secret/data/{{identity.entity.id}}/*", "secret/data/abc/key", true},
	}
	for _, testCase := range cases {
		if got := newPattern(testCase.pattern).matches(testCase.path); got != testCase.matches {
			t.Errorf("%q matches %q = %v, want %v", testCase.pattern, testCase.path, got, testCase.matches)
		}
	}
}

// The priority examples from Vault's docs:
// https://developer.hashicorp.com/vault/docs/concepts/policies#priority-matching
func TestPriorityLikeVaultDocs(t *testing.T) {
	cases := []struct {
		winner string
		loser  string
		path   string
	}{
		// Rule 3: same first wildcard, both end in *, fewer + wins.
		{"secret/*", "secret/+/+/foo/*", "secret/a/b/foo/c"},
		// Rule 4: longer wins.
		{"ns1/ns2/ns3/secret/apps/*", "ns1/ns2/ns3/secret/*", "ns1/ns2/ns3/secret/apps/x"},
		// Rule 1: later first wildcard wins.
		{"secret/data/*", "secret/*", "secret/data/x"},
		// Rule 2: not ending in * wins.
		{"secret/+/x", "secret/*", "secret/a/x"},
		// Exact always wins.
		{"secret/data/app", "secret/data/*", "secret/data/app"},
	}
	for _, testCase := range cases {
		winner := newPattern(testCase.winner)
		loser := newPattern(testCase.loser)
		if !winner.matches(testCase.path) || !loser.matches(testCase.path) {
			t.Fatalf("both %q and %q must match %q", testCase.winner, testCase.loser, testCase.path)
		}
		if !winner.priorityFor(testCase.path).beats(loser.priorityFor(testCase.path)) {
			t.Errorf("%q should beat %q for %q", testCase.winner, testCase.loser, testCase.path)
		}
		if loser.priorityFor(testCase.path).beats(winner.priorityFor(testCase.path)) {
			t.Errorf("%q must not beat %q for %q", testCase.loser, testCase.winner, testCase.path)
		}
	}
}

// inventoryWithPolicies builds a root namespace with secret/ and approle/,
// plus the given policies.
func inventoryWithPolicies(policies map[string]string) scan.Inventory {
	namespace := scan.NamespaceInventory{
		Path:           "",
		SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}, {Path: "sys/", Type: "system"}},
		AuthMethods:    []scan.Mount{{Path: "approle/", Type: "approle"}, {Path: "token/", Type: "token"}},
	}
	for name, text := range policies {
		namespace.ACLPolicies = append(namespace.ACLPolicies, scan.Policy{Name: name, Text: text})
	}
	return scan.Inventory{Namespaces: []scan.NamespaceInventory{namespace}}
}

// rulesFound lists "rule policy path" for each finding, for easy comparison.
func rulesFound(result Result) []string {
	found := []string{}
	for _, finding := range result.Findings {
		found = append(found, finding.Rule+" "+finding.Policy+" "+finding.Path)
	}
	return found
}

func requireFindings(t *testing.T, result Result, expected ...string) {
	t.Helper()
	got := rulesFound(result)
	// No findings expected: an empty list and a nil list both mean "none".
	if len(got) == 0 && len(expected) == 0 {
		return
	}
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("findings:\ngot  %q\nwant %q", got, expected)
	}
}

func TestRootEquivalentAndGrantsEverything(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"admin":  `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`,
		"reader": `path "*" { capabilities = ["read"] }`,
	}))
	requireFindings(t, result,
		"MITCH-POL-001 admin *",
		"MITCH-POL-002 reader *",
	)
	if result.Findings[0].Severity != SeverityCritical || result.Findings[1].Severity != SeverityHigh {
		t.Errorf("severities: %+v", result.Findings)
	}
}

func TestAllOfSysAndSudo(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"ops": `
path "sys/*" { capabilities = ["read"] }
path "sys/raw/*" { capabilities = ["read", "sudo"] }
`,
	}))
	requireFindings(t, result,
		"MITCH-POL-003 ops sys/*",
		"MITCH-POL-004 ops sys/raw/*",
	)
}

func TestPrivilegeEscalation(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"policy-admin": `path "sys/policies/acl/*" { capabilities = ["create", "update"] }`,
		"auth-admin":   `path "sys/auth/+" { capabilities = ["update"] }`,
		"mount-reader": `path "sys/mounts/*" { capabilities = ["read", "list"] }`,
		"tuner":        `path "sys/mounts/+/tune" { capabilities = ["update"] }`,
	}))
	requireFindings(t, result,
		"MITCH-POL-005 auth-admin sys/auth/+",
		"MITCH-POL-005 policy-admin sys/policies/acl/*",
		"MITCH-POL-005 tuner sys/mounts/+/tune",
	)
	if !strings.Contains(result.Findings[1].Message, "ACL policies") {
		t.Errorf("message should name what can be changed: %s", result.Findings[1].Message)
	}
}

func TestShadowedDeny(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"app": `
path "secret/data/*" { capabilities = ["deny"] }
path "secret/data/app/*" { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["deny"] }
path "secret/*" { capabilities = ["read"] }
`,
	}))
	// The first deny loses to the more specific grant. The second deny is
	// more specific than "secret/*", so it does block, and is not reported.
	requireFindings(t, result, "MITCH-POL-006 app secret/data/*")
	if !strings.Contains(result.Findings[0].Message, `"secret/data/app/*"`) {
		t.Errorf("message should name the winning grant: %s", result.Findings[0].Message)
	}
}

func TestSamePatternDenyIsNotShadowed(t *testing.T) {
	// The same path twice: Vault merges them and deny wins.
	result := Analyze(inventoryWithPolicies(map[string]string{
		"app": `
path "secret/data/x" { capabilities = ["read"] }
path "secret/data/x" { capabilities = ["deny"] }
`,
	}))
	requireFindings(t, result)
}

func TestUnknownMount(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"app": `
path "secret/data/app/*" { capabilities = ["read"] }
path "old-kv/*" { capabilities = ["read"] }
path "auth/approle/role/app/secret-id" { capabilities = ["update"] }
path "auth/ldap/login" { capabilities = ["update"] }
path "sys/health" { capabilities = ["read"] }
path "identity/entity/id/*" { capabilities = ["read"] }
path "+/data/x" { capabilities = ["read"] }
path "gone/*" { capabilities = ["deny"] }
`,
	}))
	requireFindings(t, result,
		"MITCH-POL-007 app old-kv/*",
		"MITCH-POL-007 app auth/ldap/login",
	)
}

func TestUnknownMountSkippedWhenMountsWereNotRead(t *testing.T) {
	inventory := inventoryWithPolicies(map[string]string{"app": `path "old-kv/*" { capabilities = ["read"] }`})
	inventory.Skipped = []scan.SkippedCheck{{Check: checks.CheckMounts, Namespace: ""}}
	result := Analyze(inventory)
	requireFindings(t, result)
	if !reflect.DeepEqual(result.UnknownMountCheckSkipped, []string{""}) {
		t.Errorf("the skipped namespace must be listed: %+v", result.UnknownMountCheckSkipped)
	}
}

func TestChildNamespaceMountsCount(t *testing.T) {
	// A root policy can grant paths in a child namespace.
	inventory := inventoryWithPolicies(map[string]string{"app": `path "team-a/kv/*" { capabilities = ["read"] }`})
	inventory.Namespaces = append(inventory.Namespaces, scan.NamespaceInventory{
		Path:           "team-a/",
		SecretsEngines: []scan.Mount{{Path: "kv/", Type: "kv"}},
	})
	requireFindings(t, Analyze(inventory))
}

func TestUnseenChildNamespaceSkipsOnlyItsOwnPaths(t *testing.T) {
	// The scan could not list mounts in team-a/, so a root policy path into
	// team-a/ is not reported, but a root path to a missing mount still is.
	inventory := inventoryWithPolicies(map[string]string{"app": `
path "team-a/kv/*" { capabilities = ["read"] }
path "old-kv/*" { capabilities = ["read"] }
`})
	inventory.Namespaces = append(inventory.Namespaces, scan.NamespaceInventory{Path: "team-a/"})
	inventory.Skipped = []scan.SkippedCheck{{Check: checks.CheckMounts, Namespace: "team-a/"}}

	result := Analyze(inventory)
	requireFindings(t, result, RuleUnknownMount+" app old-kv/*")
	if len(result.UnknownMountCheckSkipped) != 1 || result.UnknownMountCheckSkipped[0] != "team-a/" {
		t.Errorf("only team-a/ must be listed as skipped, got %v", result.UnknownMountCheckSkipped)
	}
}

func TestUnlistedChildNamespacesSkipTheWholeNamespace(t *testing.T) {
	// The scan could not list child namespaces of root, so any root path
	// could lead into a namespace Mitch never saw.
	inventory := inventoryWithPolicies(map[string]string{"app": `path "old-kv/*" { capabilities = ["read"] }`})
	inventory.Skipped = []scan.SkippedCheck{{Check: checks.CheckNamespaces, Namespace: ""}}

	result := Analyze(inventory)
	requireFindings(t, result)
	if !reflect.DeepEqual(result.UnknownMountCheckSkipped, []string{""}) {
		t.Errorf("the root namespace must be listed as skipped, got %v", result.UnknownMountCheckSkipped)
	}
}

func TestRootPolicySkippedAndBadPolicyReported(t *testing.T) {
	result := Analyze(inventoryWithPolicies(map[string]string{
		"root":   ``,
		"broken": `path "x" {`,
	}))
	requireFindings(t, result)
	if len(result.NotAnalyzed) != 1 || result.NotAnalyzed[0].Policy != "broken" {
		t.Errorf("not analyzed: %+v", result.NotAnalyzed)
	}
}

func TestSeverityHelpers(t *testing.T) {
	if !AtOrAbove(SeverityCritical, SeverityHigh) || AtOrAbove(SeverityMedium, SeverityHigh) || !AtOrAbove(SeverityLow, SeverityLow) {
		t.Error("AtOrAbove is wrong")
	}
	if !IsSeverity("high") || IsSeverity("urgent") {
		t.Error("IsSeverity is wrong")
	}
	result := Result{Findings: []Finding{{Severity: SeverityHigh}, {Severity: SeverityLow}, {Severity: SeverityCritical}}}
	if result.CountAtOrAbove(SeverityHigh) != 2 {
		t.Errorf("CountAtOrAbove(high) = %d, want 2", result.CountAtOrAbove(SeverityHigh))
	}
}

// TestMitchsOwnPolicies keeps Mitch honest: the policies it asks you to load
// must not be flagged, except for sudo on the opt-in sudo add-on.
func TestMitchsOwnPolicies(t *testing.T) {
	inventory := scan.Inventory{Namespaces: []scan.NamespaceInventory{{
		Path:           "",
		SecretsEngines: []scan.Mount{{Path: "secret/", Type: "kv"}},
		ACLPolicies: []scan.Policy{
			{Name: checks.BasePolicyName, Text: checks.RenderBasePolicy()},
			{Name: checks.KVPolicyName, Text: checks.RenderKVPolicy([]checks.KVMount{{Path: "secret/", Version: 2}})},
			{Name: checks.SudoPolicyName, Text: checks.RenderSudoPolicy()},
		},
	}}}
	result := Analyze(inventory)
	if len(result.NotAnalyzed) != 0 {
		t.Fatalf("Mitch's own policies must parse: %+v", result.NotAnalyzed)
	}
	for _, finding := range result.Findings {
		if finding.Policy != checks.SudoPolicyName || finding.Rule != RuleSudo {
			t.Errorf("unexpected finding on Mitch's own policy: %+v", finding)
		}
	}
}
