package report

import (
	"fmt"
	"io"
	"strings"
)

// timeLayout is how times are shown in the report (always UTC).
const timeLayout = "2006-01-02 15:04:05 UTC"

// WriteMarkdown writes the report as Markdown. It reads well as plain text
// in a terminal and renders as tables on GitHub or in a wiki.
func WriteMarkdown(output io.Writer, built Report) error {
	text := &strings.Builder{}

	writeHeader(text, built)
	writeSummary(text, built)
	writeGaps(text, built)
	writeMountTypes(text, built)
	writeMounts(text, "Secrets engines", built.SecretsEngines)
	writeMounts(text, "Auth methods", built.AuthMethods)
	writeKVCounts(text, built)
	writePlugins(text, built)
	writeDeprecated(text, built)
	writePolicies(text, built)
	writeAuditDevices(text, built)
	writeVersionHistory(text, built)

	_, err := io.WriteString(output, text.String())
	return err
}

func writeHeader(text *strings.Builder, built Report) {
	fmt.Fprintf(text, "# Mitch report\n\n")
	fmt.Fprintf(text, "- Scan: %s\n", built.Scan.ID)
	fmt.Fprintf(text, "- Started: %s\n", built.Scan.StartedAt.UTC().Format(timeLayout))
	fmt.Fprintf(text, "- Vault: %s\n", built.Scan.VaultAddress)
	edition := "Community"
	if built.Scan.Enterprise {
		edition = "Enterprise"
	}
	fmt.Fprintf(text, "- Version: %s (%s)\n", built.Scan.VaultVersion, edition)
	if built.Scan.ClusterName != "" {
		fmt.Fprintf(text, "- Cluster: %s\n", built.Scan.ClusterName)
	}
	fmt.Fprintf(text, "- Sudo checks: %s\n", yesNo(built.Scan.SudoRequested))
}

func writeSummary(text *strings.Builder, built Report) {
	summary := built.Summary
	fmt.Fprintf(text, "\n## Summary\n\n")

	rows := [][]string{
		{"Namespaces", fmt.Sprint(summary.Namespaces)},
		{"Secrets engines", fmt.Sprint(summary.SecretsEngines)},
		{"Auth methods", fmt.Sprint(summary.AuthMethods)},
		{"ACL policies", fmt.Sprint(summary.ACLPolicies)},
	}
	if summary.KVCounted {
		secrets := fmt.Sprint(summary.KVSecrets)
		if !summary.KVComplete {
			secrets = "at least " + secrets
		}
		rows = append(rows,
			[]string{"KV secrets", fmt.Sprintf("%s, in %d mount(s)", secrets, summary.KVMounts)},
		)
	} else {
		rows = append(rows, []string{"KV secrets", "not counted"})
	}
	rows = append(rows,
		[]string{"Plugins (built-in / registered)", fmt.Sprintf("%d / %d", summary.BuiltinPlugins, summary.RegisteredPlugins)},
		[]string{"Deprecated mounts and registered plugins", fmt.Sprint(summary.Deprecated)},
		[]string{"Skipped checks", fmt.Sprint(summary.SkippedChecks)},
	)
	writeTable(text, []string{"Item", "Count"}, rows)
}

// writeGaps lists checks the scan could not run, so nobody mistakes a
// partial scan for a complete one.
func writeGaps(text *strings.Builder, built Report) {
	if len(built.Skipped) == 0 && len(built.NotRequested) == 0 {
		return
	}
	fmt.Fprintf(text, "\n## Scan gaps\n\n")

	if len(built.Skipped) > 0 {
		fmt.Fprintf(text, "These checks could not run, so the counts in this report leave them out.\n\n")
		rows := [][]string{}
		for _, skipped := range built.Skipped {
			status := "-"
			if skipped.HTTPStatus != 0 {
				status = fmt.Sprint(skipped.HTTPStatus)
			}
			rows = append(rows, []string{skipped.Check, namespaceLabel(skipped.Namespace), skipped.Path, status, skipped.Reason, skipped.NextStep})
		}
		writeTable(text, []string{"Check", "Namespace", "Path", "HTTP", "Reason", "Next step"}, rows)
	}

	if len(built.NotRequested) > 0 {
		if len(built.Skipped) > 0 {
			fmt.Fprintln(text)
		}
		fmt.Fprintf(text, "Left out on purpose:\n\n")
		rows := [][]string{}
		for _, notRequested := range built.NotRequested {
			rows = append(rows, []string{notRequested.Check, notRequested.Reason})
		}
		writeTable(text, []string{"Check", "Reason"}, rows)
	}
}

func writeMountTypes(text *strings.Builder, built Report) {
	if len(built.MountTypes) == 0 {
		return
	}
	fmt.Fprintf(text, "\n## Mounts by type\n\n")
	rows := [][]string{}
	for _, count := range built.MountTypes {
		rows = append(rows, []string{count.Kind, count.Type, fmt.Sprint(count.Count)})
	}
	writeTable(text, []string{"Kind", "Type", "Count"}, rows)
}

func writeMounts(text *strings.Builder, title string, mounts []MountRow) {
	fmt.Fprintf(text, "\n## %s\n\n", title)
	if len(mounts) == 0 {
		fmt.Fprintf(text, "None found.\n")
		return
	}
	rows := [][]string{}
	for _, mount := range mounts {
		rows = append(rows, []string{mount.Namespace, mount.Path, mount.Type, mount.PluginVersion, mount.Description})
	}
	writeTable(text, []string{"Namespace", "Path", "Type", "Plugin version", "Description"}, rows)
}

func writeKVCounts(text *strings.Builder, built Report) {
	fmt.Fprintf(text, "\n## KV secrets\n\n")
	if built.KVCounts == nil {
		fmt.Fprintf(text, "Not counted in this scan (it ran with --kv=false, or secrets engines could not be read).\n")
		return
	}
	if len(built.KVCounts) == 0 {
		fmt.Fprintf(text, "No KV mounts.\n")
		return
	}
	rows := [][]string{}
	for _, count := range built.KVCounts {
		complete := "yes"
		if !count.Complete {
			complete = "no, counts are a lower bound"
		}
		rows = append(rows, []string{count.Namespace, count.Mount, fmt.Sprintf("v%d", count.KVVersion), fmt.Sprint(count.Secrets), fmt.Sprint(count.Folders), complete})
	}
	writeTable(text, []string{"Namespace", "Mount", "KV", "Secrets", "Folders", "Complete"}, rows)
}

func writePlugins(text *strings.Builder, built Report) {
	fmt.Fprintf(text, "\n## Registered plugins\n\n")
	if len(built.RegisteredPlugins) == 0 {
		fmt.Fprintf(text, "None. Every plugin in the catalog is built in.\n")
	} else {
		fmt.Fprintf(text, "Added to the catalog by hand, not shipped with Vault.\n\n")
		rows := [][]string{}
		for _, plugin := range built.RegisteredPlugins {
			checksum := plugin.SHA256
			if checksum == "" {
				checksum = "(needs --sudo)"
			}
			rows = append(rows, []string{plugin.Type, plugin.Name, plugin.Version, checksum, plugin.OCIImage})
		}
		writeTable(text, []string{"Type", "Name", "Version", "SHA256", "OCI image"}, rows)
	}

	if len(built.BuiltinPlugins) > 0 {
		fmt.Fprintf(text, "\nBuilt-in plugins in the catalog:\n\n")
		rows := [][]string{}
		for _, count := range built.BuiltinPlugins {
			rows = append(rows, []string{count.Type, fmt.Sprint(count.Count)})
		}
		writeTable(text, []string{"Type", "Count"}, rows)
	}
}

func writeDeprecated(text *strings.Builder, built Report) {
	if len(built.Deprecated) == 0 {
		return
	}
	fmt.Fprintf(text, "\n## Deprecated\n\n")
	fmt.Fprintf(text, "Vault reports these as deprecated, pending removal or removed. See https://developer.hashicorp.com/vault/docs/updates/deprecation\n\n")
	rows := [][]string{}
	for _, deprecated := range built.Deprecated {
		rows = append(rows, []string{deprecated.Where, deprecated.Kind, deprecated.Name, deprecated.Status})
	}
	writeTable(text, []string{"Where", "Kind", "Name", "Status"}, rows)
}

func writePolicies(text *strings.Builder, built Report) {
	fmt.Fprintf(text, "\n## ACL policies\n\n")
	if len(built.ACLPolicies) == 0 {
		fmt.Fprintf(text, "None found.\n")
		return
	}
	rows := [][]string{}
	for _, policy := range built.ACLPolicies {
		rows = append(rows, []string{policy.Namespace, policy.Name, fmt.Sprint(policy.Lines)})
	}
	writeTable(text, []string{"Namespace", "Name", "Lines"}, rows)
}

func writeAuditDevices(text *strings.Builder, built Report) {
	fmt.Fprintf(text, "\n## Audit devices\n\n")
	if built.AuditDevices == nil {
		fmt.Fprintf(text, "Not checked. Reading audit devices needs --sudo.\n")
		return
	}
	if len(built.AuditDevices) == 0 {
		fmt.Fprintf(text, "None. Vault is not writing an audit log.\n")
		return
	}
	rows := [][]string{}
	for _, device := range built.AuditDevices {
		rows = append(rows, []string{device.Path, device.Type, device.Description})
	}
	writeTable(text, []string{"Path", "Type", "Description"}, rows)
}

func writeVersionHistory(text *strings.Builder, built Report) {
	if len(built.VersionHistory) == 0 {
		return
	}
	fmt.Fprintf(text, "\n## Vault version history\n\n")
	rows := [][]string{}
	for _, entry := range built.VersionHistory {
		rows = append(rows, []string{entry.Version, entry.TimestampInstalled, entry.BuildDate})
	}
	writeTable(text, []string{"Version", "Installed", "Build date"}, rows)
}

// writeTable writes a Markdown table. Cells are escaped so a "|" or a line
// break inside a value cannot break the table.
func writeTable(text *strings.Builder, headers []string, rows [][]string) {
	fmt.Fprintf(text, "| %s |\n", strings.Join(escapeCells(headers), " | "))
	separators := make([]string, len(headers))
	for i := range separators {
		separators[i] = "---"
	}
	fmt.Fprintf(text, "| %s |\n", strings.Join(separators, " | "))
	for _, row := range rows {
		fmt.Fprintf(text, "| %s |\n", strings.Join(escapeCells(row), " | "))
	}
}

// escapeCells makes values safe to put in a Markdown table cell.
func escapeCells(cells []string) []string {
	escaped := make([]string, len(cells))
	for i, cell := range cells {
		cell = strings.ReplaceAll(cell, `\`, `\\`)
		cell = strings.ReplaceAll(cell, "|", `\|`)
		cell = strings.ReplaceAll(cell, "\r\n", " ")
		cell = strings.ReplaceAll(cell, "\n", " ")
		if cell == "" {
			cell = "-"
		}
		escaped[i] = cell
	}
	return escaped
}

// yesNo shows a true/false value as a word.
func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
