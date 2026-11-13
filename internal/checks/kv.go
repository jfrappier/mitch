package checks

import (
	"fmt"
	"strings"
)

// CheckKVCount is the check that counts secrets in a KV mount. It is not in
// All(), because its policy path depends on each KV mount's path, which
// Mitch only learns during the scan.
const CheckKVCount = "kv_secret_count"

// KVPolicyName is the name of the optional policy that lets Mitch count
// secrets in KV mounts.
const KVPolicyName = "mitch-scanner-kv"

// Docs for the LIST endpoints Mitch uses to count secrets.
const (
	kvV1ListDocsURL = "https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#list-secrets"
	kvV2ListDocsURL = "https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#list-secrets"
)

// KVMount names one KV mount and its KV version (1 or 2).
type KVMount struct {
	// Path is the mount path with a trailing slash, for example "secret/".
	Path string

	// Version is 1 or 2.
	Version int
}

// KVListPath returns the path Mitch lists to see the keys in one folder of
// a KV mount. folder is "" for the top of the mount, or a folder such as
// "app/" or "app/db/".
//
// KV v2 lists keys under <mount>/metadata/; KV v1 lists them directly under
// <mount>/. Neither returns secret values.
func KVListPath(mount KVMount, folder string) string {
	if mount.Version == 2 {
		return mount.Path + "metadata/" + folder
	}
	return mount.Path + folder
}

// KVPolicyPath is the path as written in the Vault policy, which covers every
// folder in the mount.
func KVPolicyPath(mount KVMount) string {
	return KVListPath(mount, "") + "*"
}

// KVDocsURL links to the LIST docs for the mount's KV version.
func KVDocsURL(mount KVMount) string {
	if mount.Version == 2 {
		return kvV2ListDocsURL
	}
	return kvV1ListDocsURL
}

// NormalizeMountPath checks a mount path typed by the user and returns it
// with exactly one trailing slash and no leading slash, the way Vault writes
// mount paths in sys/mounts.
//
// It rejects policy wildcards ("*" and "+"), so the printed policy grants
// exactly the mounts the user named.
func NormalizeMountPath(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	trimmed = strings.Trim(trimmed, "/")

	if trimmed == "" {
		return "", fmt.Errorf("mount path %q is empty", input)
	}
	if strings.ContainsAny(trimmed, "*+") {
		return "", fmt.Errorf("mount path %q contains a wildcard (* or +); name each mount exactly", input)
	}
	if strings.ContainsAny(trimmed, "\"\\\n") {
		return "", fmt.Errorf("mount path %q contains a quote, backslash or line break", input)
	}

	return trimmed + "/", nil
}

// RenderKVPolicy returns the HCL text of the KV counting policy for the
// given mounts. It grants only "list", which returns key names and never
// secret values.
func RenderKVPolicy(mounts []KVMount) string {
	var output strings.Builder

	header := []string{
		"# " + KVPolicyName,
		"#",
		"# Optional policy that lets Mitch count secrets in KV mounts.",
		"# It grants only \"list\", which returns key names, never secret values.",
		"# Write it in the namespace that holds these mounts.",
	}
	for _, line := range header {
		output.WriteString(line)
		output.WriteString("\n")
	}

	for _, mount := range mounts {
		output.WriteString("\n")
		fmt.Fprintf(&output, "# count secrets in KV v%d mount %s\n", mount.Version, mount.Path)
		output.WriteString("# " + KVDocsURL(mount) + "\n")
		fmt.Fprintf(&output, "path %q {\n", KVPolicyPath(mount))
		output.WriteString("  capabilities = [\"list\"]\n")
		output.WriteString("}\n")
	}

	return output.String()
}
