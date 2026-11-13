package checks

import (
	"fmt"
	"strings"
)

// Names of the two Vault policies Mitch publishes.
const (
	BasePolicyName = "mitch-scanner"
	SudoPolicyName = "mitch-scanner-sudo"
)

// RenderBasePolicy returns the HCL text of the base policy: every check that
// does not need sudo. Attach this policy to the token Mitch uses.
func RenderBasePolicy() string {
	var selected []Check
	for _, check := range All() {
		if !check.NeedsSudo {
			selected = append(selected, check)
		}
	}

	header := []string{
		"# " + BasePolicyName,
		"#",
		"# Read-only policy for Mitch. It never grants read on secret data.",
		"# Attach it to the token Mitch uses (VAULT_TOKEN).",
		"#",
		"# Paths marked \"root namespace only\" are only served from the root namespace.",
		"# Paths marked \"Enterprise only\" can stay in the policy on Vault Community;",
		"# Mitch skips those checks there.",
	}
	return renderPolicy(header, selected)
}

// RenderSudoPolicy returns the HCL text of the optional sudo add-on policy.
// Mitch only uses it when run with --sudo.
func RenderSudoPolicy() string {
	var selected []Check
	for _, check := range All() {
		if check.NeedsSudo {
			selected = append(selected, check)
		}
	}

	header := []string{
		"# " + SudoPolicyName,
		"#",
		"# Optional add-on for \"mitch scan --sudo\". These endpoints require the",
		"# sudo capability. sudo only works together with another capability",
		"# (read or list here), so this policy is still read-only.",
	}
	return renderPolicy(header, selected)
}

// renderPolicy writes one path block per check, with a comment saying why.
func renderPolicy(headerLines []string, selected []Check) string {
	var output strings.Builder

	for _, line := range headerLines {
		output.WriteString(line)
		output.WriteString("\n")
	}

	for _, check := range selected {
		output.WriteString("\n")
		output.WriteString("# " + check.Description + notesFor(check) + "\n")
		output.WriteString("# " + check.DocsURL + "\n")

		quotedCapabilities := make([]string, 0, len(check.Capabilities))
		for _, capability := range check.Capabilities {
			quotedCapabilities = append(quotedCapabilities, fmt.Sprintf("%q", capability))
		}

		fmt.Fprintf(&output, "path %q {\n", check.PolicyPath)
		fmt.Fprintf(&output, "  capabilities = [%s]\n", strings.Join(quotedCapabilities, ", "))
		output.WriteString("}\n")
	}

	return output.String()
}

// notesFor returns " (root namespace only, Enterprise only)" style notes.
func notesFor(check Check) string {
	var notes []string
	if check.RootNamespaceOnly {
		notes = append(notes, "root namespace only")
	}
	if check.EnterpriseOnly {
		notes = append(notes, "Enterprise only")
	}
	if len(notes) == 0 {
		return ""
	}
	return " (" + strings.Join(notes, ", ") + ")"
}
