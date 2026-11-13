package checks

import (
	"strings"
	"testing"
)

func TestEveryCheckIsComplete(t *testing.T) {
	seenNames := make(map[string]bool)

	for _, check := range All() {
		if check.Name == "" || check.Description == "" || check.PolicyPath == "" ||
			check.ProbePath == "" || len(check.Capabilities) == 0 || check.DocsURL == "" {
			t.Errorf("check %q is missing a required field: %+v", check.Name, check)
		}
		if seenNames[check.Name] {
			t.Errorf("check name %q is used twice", check.Name)
		}
		seenNames[check.Name] = true

		// A sudo check must ask for sudo, and only sudo checks may.
		asksForSudo := false
		for _, capability := range check.Capabilities {
			if capability == "sudo" {
				asksForSudo = true
			}
		}
		if asksForSudo != check.NeedsSudo {
			t.Errorf("check %q: NeedsSudo is %v but capabilities are %v", check.Name, check.NeedsSudo, check.Capabilities)
		}

		// Mitch is read-only: no write capabilities, except "update" on
		// sys/capabilities-self, which only reports permissions.
		for _, capability := range check.Capabilities {
			isWrite := capability == "create" || capability == "update" || capability == "delete" || capability == "patch"
			if isWrite && check.PolicyPath != "sys/capabilities-self" {
				t.Errorf("check %q asks for write capability %q", check.Name, capability)
			}
		}
	}
}

func TestHasCapabilities(t *testing.T) {
	testCases := []struct {
		name     string
		granted  []string
		required []string
		expected bool
	}{
		{"exact match", []string{"read"}, []string{"read"}, true},
		{"extra granted", []string{"read", "list"}, []string{"read"}, true},
		{"missing one", []string{"read"}, []string{"read", "sudo"}, false},
		{"root grants all", []string{"root"}, []string{"read", "sudo"}, true},
		{"deny wins", []string{"deny"}, []string{"read"}, false},
		{"nothing granted", []string{}, []string{"read"}, false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := HasCapabilities(testCase.granted, testCase.required)
			if result != testCase.expected {
				t.Errorf("HasCapabilities(%v, %v) = %v, expected %v",
					testCase.granted, testCase.required, result, testCase.expected)
			}
		})
	}
}

func TestBasePolicyHasNoSudo(t *testing.T) {
	policy := RenderBasePolicy()

	if strings.Contains(policy, `"sudo"`) {
		t.Errorf("base policy must not grant sudo:\n%s", policy)
	}
	if !strings.Contains(policy, `path "sys/mounts"`) {
		t.Errorf("base policy is missing sys/mounts:\n%s", policy)
	}
}

func TestSudoPolicyOnlyHasSudoPaths(t *testing.T) {
	policy := RenderSudoPolicy()

	if !strings.Contains(policy, `path "sys/audit"`) {
		t.Errorf("sudo policy is missing sys/audit:\n%s", policy)
	}
	if strings.Contains(policy, `path "sys/mounts"`) {
		t.Errorf("sudo policy must not contain base paths:\n%s", policy)
	}
}
