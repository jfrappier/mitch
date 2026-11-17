package findings

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
)

// Capability names, as Vault spells them.
// Docs: https://developer.hashicorp.com/vault/docs/concepts/policies#capabilities
const (
	capabilityCreate = "create"
	capabilityRead   = "read"
	capabilityUpdate = "update"
	capabilityPatch  = "patch"
	capabilityDelete = "delete"
	capabilityList   = "list"
	capabilitySudo   = "sudo"
	capabilityDeny   = "deny"
)

// pathRule is one "path" block of a policy, the way Vault reads it.
type pathRule struct {
	// Pattern is the path as written, for example "secret/data/*".
	Pattern string
	// Line is where the path block starts in the policy text.
	Line int
	// Capabilities after the old "policy = ..." shorthand is expanded. When
	// the block has "deny", this is only ["deny"], because Vault drops every
	// other capability in that case.
	Capabilities []string
}

// has reports whether the rule lists a capability.
func (r pathRule) has(capability string) bool {
	for _, listed := range r.Capabilities {
		if listed == capability {
			return true
		}
	}
	return false
}

// isDeny reports whether the rule is a deny rule.
func (r pathRule) isDeny() bool {
	return r.has(capabilityDeny)
}

// grantsAnything reports whether the rule allows at least one operation.
func (r pathRule) grantsAnything() bool {
	return !r.isDeny() && len(r.Capabilities) > 0
}

// pathBlock is the part of a path block Mitch decodes. Vault decodes the
// same keys with the same HCL library (vault/policy.go, parsePaths).
type pathBlock struct {
	Policy       string   `hcl:"policy"`
	Capabilities []string `hcl:"capabilities"`
}

// parsePolicy reads a policy's text with HCL v1, the parser Vault itself
// uses for ACL policies, so Mitch sees the same rules Vault enforces.
// Source: https://github.com/hashicorp/vault/blob/main/vault/policy.go
func parsePolicy(text string) ([]pathRule, error) {
	// hcl.Parse reads HCL and JSON policies alike, as Vault does.
	root, err := hcl.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("parsing the policy failed: %w", err)
	}
	list, isObjectList := root.Node.(*ast.ObjectList)
	if !isObjectList {
		return nil, fmt.Errorf("the policy has no top-level object")
	}

	rules := []pathRule{}
	for _, item := range list.Filter("path").Items {
		rule, err := readPathBlock(item)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// readPathBlock turns one path block into a pathRule.
func readPathBlock(item *ast.ObjectItem) (pathRule, error) {
	if len(item.Keys) == 0 {
		return pathRule{}, fmt.Errorf("a path block has no path")
	}
	pattern, isString := item.Keys[0].Token.Value().(string)
	if !isString {
		return pathRule{}, fmt.Errorf("a path block's path is not a string")
	}
	// Vault strips one leading "/" (PathRules.normalizePath).
	pattern = strings.TrimPrefix(pattern, "/")

	var block pathBlock
	err := hcl.DecodeObject(&block, item.Val)
	if err != nil {
		return pathRule{}, fmt.Errorf("path %q: %w", pattern, err)
	}

	capabilities, err := expandCapabilities(block)
	if err != nil {
		return pathRule{}, fmt.Errorf("path %q: %w", pattern, err)
	}
	rule := pathRule{
		Pattern:      pattern,
		Line:         item.Keys[0].Pos().Line,
		Capabilities: capabilities,
	}
	return rule, nil
}

// expandCapabilities maps the old "policy = ..." shorthand to capabilities
// exactly as Vault does, and keeps only "deny" when deny is listed.
func expandCapabilities(block pathBlock) ([]string, error) {
	capabilities := append([]string{}, block.Capabilities...)

	switch block.Policy {
	case "":
		// No shorthand.
	case "deny":
		capabilities = []string{capabilityDeny}
	case "read":
		capabilities = append(capabilities, capabilityRead, capabilityList)
	case "write":
		capabilities = append(capabilities, capabilityCreate, capabilityRead, capabilityUpdate, capabilityDelete, capabilityList)
	case "sudo":
		capabilities = append(capabilities, capabilityCreate, capabilityRead, capabilityUpdate, capabilityDelete, capabilityList, capabilitySudo)
	default:
		return nil, fmt.Errorf("unknown policy shorthand %q", block.Policy)
	}

	for _, capability := range capabilities {
		if capability == capabilityDeny {
			return []string{capabilityDeny}, nil
		}
	}
	return capabilities, nil
}
