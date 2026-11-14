package diff

import (
	"fmt"
	"io"
	"strings"
)

// timeLayout is how scan start times are shown (always UTC).
const timeLayout = "2006-01-02 15:04:05 UTC"

// WriteMarkdown writes a Result for people to read. It reads well as plain
// text in a terminal, and on GitHub the change blocks are colored.
//
// Each changed item is on its own line, starting with "+" (added),
// "-" (removed) or "~" (changed). Changed fields are listed under their item
// as "field: old -> new".
func WriteMarkdown(output io.Writer, result Result) error {
	text := &strings.Builder{}

	fmt.Fprintf(text, "# Mitch diff\n\n")
	fmt.Fprintf(text, "- From scan: %s (%s, Vault %s)\n", result.From.ID, result.From.StartedAt.UTC().Format(timeLayout), result.From.VaultVersion)
	fmt.Fprintf(text, "- To scan: %s (%s, Vault %s)\n", result.To.ID, result.To.StartedAt.UTC().Format(timeLayout), result.To.VaultVersion)

	if len(result.Warnings) > 0 {
		fmt.Fprintf(text, "\n## Warnings\n\n")
		for _, warning := range result.Warnings {
			fmt.Fprintf(text, "- %s\n", warning)
		}
	}

	if !result.HasChanges() {
		fmt.Fprintf(text, "\nNo changes.\n")
		_, err := io.WriteString(output, text.String())
		return err
	}

	for _, section := range result.Sections {
		fmt.Fprintln(text)
		writeSection(text, section)
	}

	_, err := io.WriteString(output, text.String())
	return err
}

// writeSection writes one section: a heading, then every added, removed and
// changed item inside a "diff" code block.
func writeSection(text *strings.Builder, section Section) {
	if section.Namespace == "" {
		fmt.Fprintf(text, "## %s\n\n", sectionTitle(section.Name))
	} else {
		fmt.Fprintf(text, "## %s in namespace %s\n\n", sectionTitle(section.Name), section.Namespace)
	}

	// A fenced block keeps the layout exactly as written, and the "diff"
	// language colors + and - lines where Markdown is rendered.
	fmt.Fprintf(text, "```diff\n")
	for _, label := range section.Added {
		fmt.Fprintf(text, "+ %s\n", label)
	}
	for _, label := range section.Removed {
		fmt.Fprintf(text, "- %s\n", label)
	}
	for _, change := range section.Changed {
		fmt.Fprintf(text, "~ %s\n", change.Key)
		for _, field := range change.Fields {
			fmt.Fprintf(text, "    %s: %s -> %s\n", field.Field, field.Old, field.New)
		}
		for _, line := range change.TextLines {
			fmt.Fprintf(text, "  %s\n", line)
		}
	}
	fmt.Fprintf(text, "```\n")
}

// sectionTitles are the headings used for each section.
var sectionTitles = map[string]string{
	SectionVault:          "Vault",
	SectionServerConfig:   "Server config",
	SectionPlugins:        "Plugins",
	SectionPluginRuntimes: "Plugin runtimes",
	SectionAuditDevices:   "Audit devices",
	SectionNamespaces:     "Namespaces",
	SectionSecretsEngines: "Secrets engines",
	SectionAuthMethods:    "Auth methods",
	SectionACLPolicies:    "ACL policies",
	SectionKVCounts:       "KV counts",
}

// sectionTitle returns the heading for a section, or the raw name if there
// is no heading for it.
func sectionTitle(name string) string {
	title, known := sectionTitles[name]
	if !known {
		return name
	}
	return title
}
