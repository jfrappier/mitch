package checks

import (
	"strings"
	"testing"
)

func TestNormalizeMountPath(t *testing.T) {
	validCases := map[string]string{
		"secret":       "secret/",
		"secret/":      "secret/",
		"/secret/":     "secret/",
		" team/kv/ ":   "team/kv/",
		"kv-v1":        "kv-v1/",
		"apps/payroll": "apps/payroll/",
	}
	for input, expected := range validCases {
		got, err := NormalizeMountPath(input)
		if err != nil {
			t.Errorf("NormalizeMountPath(%q) returned an unexpected error: %v", input, err)
			continue
		}
		if got != expected {
			t.Errorf("NormalizeMountPath(%q): expected %q, got %q", input, expected, got)
		}
	}

	invalidInputs := []string{"", "/", "  ", "*", "secret/*", "+/kv", "se\"cret", "a\\b", "a\nb"}
	for _, input := range invalidInputs {
		_, err := NormalizeMountPath(input)
		if err == nil {
			t.Errorf("NormalizeMountPath(%q) should fail", input)
		}
	}
}

func TestKVPaths(t *testing.T) {
	v1 := KVMount{Path: "kv1/", Version: 1}
	v2 := KVMount{Path: "secret/", Version: 2}

	cases := []struct{ got, expected string }{
		{KVListPath(v1, ""), "kv1/"},
		{KVListPath(v1, "app/"), "kv1/app/"},
		{KVListPath(v2, ""), "secret/metadata/"},
		{KVListPath(v2, "app/db/"), "secret/metadata/app/db/"},
		{KVPolicyPath(v1), "kv1/*"},
		{KVPolicyPath(v2), "secret/metadata/*"},
	}
	for _, testCase := range cases {
		if testCase.got != testCase.expected {
			t.Errorf("expected %q, got %q", testCase.expected, testCase.got)
		}
	}
}

func TestKVPolicyGrantsOnlyList(t *testing.T) {
	policy := RenderKVPolicy([]KVMount{{Path: "secret/", Version: 2}, {Path: "kv1/", Version: 1}})

	for _, expected := range []string{
		"# " + KVPolicyName,
		`path "secret/metadata/*" {`,
		`path "kv1/*" {`,
		kvV2ListDocsURL,
		kvV1ListDocsURL,
	} {
		if !strings.Contains(policy, expected) {
			t.Errorf("KV policy is missing %q\n%s", expected, policy)
		}
	}

	if strings.Count(policy, `capabilities = ["list"]`) != 2 {
		t.Errorf("expected exactly two list-only blocks\n%s", policy)
	}
	for _, forbidden := range []string{`"read"`, `"sudo"`, `"create"`, `"update"`, `"delete"`, "/data/"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("KV policy must not contain %s\n%s", forbidden, policy)
		}
	}
}
