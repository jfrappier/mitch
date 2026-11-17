// Package drift compares a saved scan with the Terraform in a local git
// checkout, and reports where they differ: ACL policies, secrets engines and
// auth methods that exist on only one side, and policies whose text differs.
//
// Mitch reads the .tf files itself with HCL v2, the language library
// Terraform uses. It never runs Terraform, never clones, and never needs git
// credentials. A value it cannot work out without running Terraform, such as
// a variable or a module input, is listed as "not checked" and is never
// reported as drift.
package drift

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

// Kinds of Vault object Mitch compares.
const (
	KindPolicy        = "ACL policy"
	KindSecretsEngine = "secrets engine"
	KindAuthMethod    = "auth method"
)

// Resource is one Vault object a Terraform resource manages.
type Resource struct {
	Kind string `json:"kind"`
	// Address is the Terraform address, such as vault_policy.app.
	Address string `json:"address"`
	// File is relative to the checkout; Line is where the resource starts.
	File string `json:"file"`
	Line int    `json:"line"`
	// Namespace is the full namespace path with a trailing "/", such as
	// "team-a/", or "" for the root namespace.
	Namespace string `json:"namespace"`
	// Name is the policy name, or the mount path with a trailing "/", such
	// as "secret/".
	Name string `json:"name"`
	// MountType is the secrets engine or auth method type, when the
	// resource sets it as a plain value. Empty otherwise.
	MountType string `json:"mount_type"`
	// PolicyText is the policy as Terraform would send it to Vault.
	// PolicyTextKnown is false when Mitch could not work it out.
	PolicyText      string `json:"-"`
	PolicyTextKnown bool   `json:"policy_text_known"`
}

// NotChecked is a Terraform resource, or part of one, that Mitch could not
// work out without running Terraform.
type NotChecked struct {
	Address string `json:"address"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Reason  string `json:"reason"`

	// kind and namespace say which comparison this gap affects, so Mitch
	// does not report a Vault object as "not in git" when it might be this
	// resource. namespaceKnown is false when even the namespace is unknown.
	kind           string
	namespace      string
	namespaceKnown bool
	// identityKnown is true when only part of the resource is unknown (for
	// example a policy's text), so the resource still counts as in git.
	identityKnown bool
}

// Repo is what Mitch read from a git checkout.
type Repo struct {
	// Path is the checkout path as the user gave it.
	Path       string       `json:"path"`
	FilesRead  int          `json:"files_read"`
	Resources  []Resource   `json:"resources"`
	NotChecked []NotChecked `json:"not_checked"`
}

// mountResource describes a Terraform resource type that creates a secrets
// engine or an auth method, taken from the Vault provider's resource docs:
// https://registry.terraform.io/providers/hashicorp/vault/latest/docs
// (source: website/docs/r in github.com/hashicorp/terraform-provider-vault).
type mountResource struct {
	kind string
	// pathAttribute is the argument that holds the mount path.
	pathAttribute string
	// defaultPath is the documented default when the argument is left out.
	// Empty means the argument is required or has no documented default.
	defaultPath string
	// typeAttribute names the argument that holds the mount type, when the
	// resource has one (vault_mount and vault_auth_backend).
	typeAttribute string
}

// mountResources lists every resource type in the Vault provider that
// enables a secrets engine or an auth method. Resources that only configure
// an existing mount (for example vault_kubernetes_auth_backend_config) are
// not listed, because they do not create one.
var mountResources = map[string]mountResource{
	// Generic resources. The type is an argument.
	"vault_mount":        {kind: KindSecretsEngine, pathAttribute: "path", typeAttribute: "type"},
	"vault_auth_backend": {kind: KindAuthMethod, pathAttribute: "path", typeAttribute: "type"},

	// Secrets engines with their own resource type.
	"vault_database_secrets_mount":         {kind: KindSecretsEngine, pathAttribute: "path"},
	"vault_ad_secret_backend":              {kind: KindSecretsEngine, pathAttribute: "backend", defaultPath: "ad"},
	"vault_aws_secret_backend":             {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "aws"},
	"vault_azure_secret_backend":           {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "azure"},
	"vault_consul_secret_backend":          {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "consul"},
	"vault_gcp_secret_backend":             {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "gcp"},
	"vault_gcpkms_secret_backend":          {kind: KindSecretsEngine, pathAttribute: "path"},
	"vault_kmip_secret_backend":            {kind: KindSecretsEngine, pathAttribute: "path"},
	"vault_kubernetes_secret_backend":      {kind: KindSecretsEngine, pathAttribute: "path"},
	"vault_ldap_secret_backend":            {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "ldap"},
	"vault_nomad_secret_backend":           {kind: KindSecretsEngine, pathAttribute: "backend", defaultPath: "nomad"},
	"vault_rabbitmq_secret_backend":        {kind: KindSecretsEngine, pathAttribute: "path", defaultPath: "rabbitmq"},
	"vault_terraform_cloud_secret_backend": {kind: KindSecretsEngine, pathAttribute: "backend", defaultPath: "terraform"},

	// Auth methods with their own resource type. The GitHub and SAML docs
	// write the default as "auth/github" and "auth/saml", which is the API
	// path; the mount path itself is "github" and "saml".
	"vault_gcp_auth_backend":    {kind: KindAuthMethod, pathAttribute: "path", defaultPath: "gcp"},
	"vault_github_auth_backend": {kind: KindAuthMethod, pathAttribute: "path", defaultPath: "github"},
	"vault_jwt_auth_backend":    {kind: KindAuthMethod, pathAttribute: "path"},
	"vault_ldap_auth_backend":   {kind: KindAuthMethod, pathAttribute: "path"},
	"vault_okta_auth_backend":   {kind: KindAuthMethod, pathAttribute: "path", defaultPath: "okta"},
	"vault_saml_auth_backend":   {kind: KindAuthMethod, pathAttribute: "path", defaultPath: "saml"},
}

// policyResource is the resource type for ACL policies.
// Docs: https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/policy
const policyResource = "vault_policy"

// vaultProvider is the provider name whose blocks set namespaces.
// Docs: https://registry.terraform.io/providers/hashicorp/vault/latest/docs#namespace
const vaultProvider = "vault"

// skippedFolders are never read: .terraform holds modules Terraform
// downloaded, and .git holds git's own files.
var skippedFolders = map[string]bool{".terraform": true, ".git": true}

// resourceBlock is one resource block, before its values are worked out.
type resourceBlock struct {
	resourceType string
	name         string
	file         string
	line         int
	folder       string
	attributes   hcl.Attributes
}

// providerSettings is one provider "vault" block.
type providerSettings struct {
	namespace      string
	namespaceKnown bool
	file           string
	line           int
}

// PathError means the --repo path itself cannot be used: it does not exist,
// cannot be read, or is not a folder. It is a mistake in how Mitch was run,
// not a problem in the Terraform, so the CLI exits with the usage error code.
type PathError struct {
	Path string
	Err  error
}

// Error says which path failed and why.
func (e *PathError) Error() string {
	return fmt.Sprintf("--repo %q: %v", e.Path, e.Err)
}

// Unwrap gives errors.Is and errors.As the underlying error.
func (e *PathError) Unwrap() error {
	return e.Err
}

// errNotAFolder is the reason given when --repo names a file.
var errNotAFolder = errors.New("is not a folder; give the folder that holds your Terraform")

// ReadRepo reads every .tf and .tf.json file under path. It fails, naming
// the file and line, when a file is not valid HCL, the same way Terraform
// would refuse it. A path that cannot be used at all fails with *PathError.
func ReadRepo(path string) (Repo, error) {
	root, err := filepath.Abs(path)
	if err != nil {
		return Repo{}, &PathError{Path: path, Err: err}
	}
	info, err := os.Stat(root)
	if err != nil {
		return Repo{}, &PathError{Path: path, Err: err}
	}
	if !info.IsDir() {
		return Repo{}, &PathError{Path: path, Err: errNotAFolder}
	}
	// Resolve symbolic links once, so file() can check that every file it
	// reads stays inside the checkout.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return Repo{}, &PathError{Path: path, Err: err}
	}

	repo := Repo{Path: path, Resources: []Resource{}, NotChecked: []NotChecked{}}
	reader := &repoReader{root: root, parser: hclparse.NewParser(), providers: map[string][]providerSettings{}}

	err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if skippedFolders[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filePath, ".tf") && !strings.HasSuffix(filePath, ".tf.json") {
			return nil
		}
		repo.FilesRead++
		return reader.readFile(filePath)
	})
	if err != nil {
		return Repo{}, err
	}

	reader.resolve(&repo)
	sortRepo(&repo)
	return repo, nil
}

// repoReader holds what has been read so far.
type repoReader struct {
	root      string
	parser    *hclparse.Parser
	resources []resourceBlock
	// providers maps a provider alias ("" for the default provider) to
	// every provider "vault" block with that alias.
	providers map[string][]providerSettings
}

// topLevelSchema picks out the blocks Mitch reads. Everything else, such as
// variable and terraform blocks, is ignored.
var topLevelSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "provider", LabelNames: []string{"name"}},
	},
}

// resourceSchema lists the arguments Mitch reads from a resource. Nested
// blocks, such as tune {}, are ignored.
var resourceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name"}, {Name: "policy"}, {Name: "path"}, {Name: "backend"}, {Name: "type"},
		{Name: "namespace"}, {Name: "provider"}, {Name: "count"}, {Name: "for_each"},
	},
}

// providerSchema lists the provider arguments Mitch reads.
var providerSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{{Name: "alias"}, {Name: "namespace"}},
}

// readFile parses one Terraform file and keeps its vault resources and
// provider blocks.
func (r *repoReader) readFile(filePath string) error {
	var file *hcl.File
	var diagnostics hcl.Diagnostics
	if strings.HasSuffix(filePath, ".tf.json") {
		file, diagnostics = r.parser.ParseJSONFile(filePath)
	} else {
		file, diagnostics = r.parser.ParseHCLFile(filePath)
	}
	if diagnostics.HasErrors() {
		return fmt.Errorf("reading Terraform failed: %s", diagnostics.Error())
	}

	content, _, diagnostics := file.Body.PartialContent(topLevelSchema)
	if diagnostics.HasErrors() {
		return fmt.Errorf("reading Terraform failed: %s", diagnostics.Error())
	}

	relative := r.relative(filePath)
	for _, block := range content.Blocks {
		switch block.Type {
		case "resource":
			resourceType := block.Labels[0]
			if resourceType != policyResource && !isMountResource(resourceType) {
				continue
			}
			body, _, diagnostics := block.Body.PartialContent(resourceSchema)
			if diagnostics.HasErrors() {
				return fmt.Errorf("reading Terraform failed: %s", diagnostics.Error())
			}
			r.resources = append(r.resources, resourceBlock{
				resourceType: resourceType,
				name:         block.Labels[1],
				file:         relative,
				line:         block.DefRange.Start.Line,
				folder:       filepath.Dir(filePath),
				attributes:   body.Attributes,
			})
		case "provider":
			if block.Labels[0] != vaultProvider {
				continue
			}
			err := r.readProvider(block, relative)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// readProvider records one provider "vault" block's alias and namespace.
func (r *repoReader) readProvider(block *hcl.Block, relative string) error {
	body, _, diagnostics := block.Body.PartialContent(providerSchema)
	if diagnostics.HasErrors() {
		return fmt.Errorf("reading Terraform failed: %s", diagnostics.Error())
	}
	settings := providerSettings{namespaceKnown: true, file: relative, line: block.DefRange.Start.Line}

	alias := ""
	if attribute, found := body.Attributes["alias"]; found {
		value, known := plainString(attribute.Expr, nil)
		if !known {
			// Terraform requires a plain string here, so this is unusual.
			return fmt.Errorf("%s:%d: provider \"vault\" has an alias that is not a plain string", relative, settings.line)
		}
		alias = value
	}
	if attribute, found := body.Attributes["namespace"]; found {
		value, known := plainString(attribute.Expr, nil)
		settings.namespace = value
		settings.namespaceKnown = known
	}
	r.providers[alias] = append(r.providers[alias], settings)
	return nil
}

// resolve works out every resource's values. It runs twice, so a value that
// refers to another resource's path (vault_auth_backend.ldap.path) can use
// what the first pass found.
func (r *repoReader) resolve(repo *Repo) {
	firstPass := map[string]Resource{}
	for _, block := range r.resources {
		resource, _ := r.resolveBlock(block, nil)
		firstPass[block.resourceType+"."+block.name] = resource
	}
	references := referenceVariables(firstPass)

	for _, block := range r.resources {
		resource, gaps := r.resolveBlock(block, references)
		if resource.Name != "" {
			repo.Resources = append(repo.Resources, resource)
		}
		repo.NotChecked = append(repo.NotChecked, gaps...)
	}
}

// resolveBlock works out one resource. It returns the resource (with an
// empty Name when its identity is unknown) and anything not checked.
func (r *repoReader) resolveBlock(block resourceBlock, references map[string]cty.Value) (Resource, []NotChecked) {
	address := block.resourceType + "." + block.name
	resource := Resource{Address: address, File: block.file, Line: block.line}
	gap := NotChecked{Address: address, File: block.file, Line: block.line}

	if block.resourceType == policyResource {
		resource.Kind = KindPolicy
	} else {
		resource.Kind = mountResources[block.resourceType].kind
	}
	gap.kind = resource.Kind

	namespace, namespaceKnown, reason := r.namespaceOf(block, references)
	gap.namespace = namespace
	gap.namespaceKnown = namespaceKnown

	// count and for_each make any number of copies, so the resource cannot
	// be matched to one Vault object without running Terraform.
	for _, metaArgument := range []string{"count", "for_each"} {
		if _, found := block.attributes[metaArgument]; found {
			gap.Reason = fmt.Sprintf("it uses %s, so Mitch cannot tell how many copies Terraform makes", metaArgument)
			return Resource{}, []NotChecked{gap}
		}
	}
	if !namespaceKnown {
		gap.Reason = reason
		return Resource{}, []NotChecked{gap}
	}
	resource.Namespace = namespace

	context := r.evalContext(block.folder, references)
	if block.resourceType == policyResource {
		return r.resolvePolicy(block, resource, gap, context)
	}
	return r.resolveMount(block, resource, gap, context)
}

// resolvePolicy works out a vault_policy's name and text.
func (r *repoReader) resolvePolicy(block resourceBlock, resource Resource, gap NotChecked, context *hcl.EvalContext) (Resource, []NotChecked) {
	name, known := attributeString(block.attributes, "name", context)
	if !known {
		gap.Reason = notPlainReason("name")
		return Resource{}, []NotChecked{gap}
	}
	resource.Name = name

	attribute, found := block.attributes["policy"]
	if !found {
		gap.identityKnown = true
		gap.Reason = "it has no policy argument, so its text was not compared"
		return resource, []NotChecked{gap}
	}
	text, known, err := evaluateString(attribute.Expr, context)
	if err != nil {
		gap.identityKnown = true
		gap.Reason = "its policy text could not be read: " + err.Error()
		return resource, []NotChecked{gap}
	}
	if !known {
		gap.identityKnown = true
		gap.Reason = notPlainReason("policy") + ", so its text was not compared"
		return resource, []NotChecked{gap}
	}
	resource.PolicyText = text
	resource.PolicyTextKnown = true
	return resource, nil
}

// resolveMount works out a secrets engine or auth method's path and type.
func (r *repoReader) resolveMount(block resourceBlock, resource Resource, gap NotChecked, context *hcl.EvalContext) (Resource, []NotChecked) {
	settings := mountResources[block.resourceType]

	mountType := ""
	if settings.typeAttribute != "" {
		value, known := attributeString(block.attributes, settings.typeAttribute, context)
		if !known {
			gap.Reason = notPlainReason(settings.typeAttribute)
			return Resource{}, []NotChecked{gap}
		}
		mountType = value
	}
	resource.MountType = mountType

	path := settings.defaultPath
	if block.resourceType == "vault_auth_backend" {
		// Docs: "path - (Optional) The path to mount the auth method — this
		// defaults to the name of the type."
		path = mountType
	}
	if _, found := block.attributes[settings.pathAttribute]; found {
		value, known := attributeString(block.attributes, settings.pathAttribute, context)
		if !known {
			gap.Reason = notPlainReason(settings.pathAttribute)
			return Resource{}, []NotChecked{gap}
		}
		path = value
	}
	path = strings.Trim(path, "/")
	if path == "" {
		gap.Reason = fmt.Sprintf("it has no %s argument and the provider documents no default", settings.pathAttribute)
		return Resource{}, []NotChecked{gap}
	}
	resource.Name = path + "/"
	return resource, nil
}

// namespaceOf works out the full namespace a resource is created in: its
// provider's namespace, then its own namespace argument, which the provider
// docs say "is always relative to the provider's configured namespace".
func (r *repoReader) namespaceOf(block resourceBlock, references map[string]cty.Value) (string, bool, string) {
	alias := ""
	if attribute, found := block.attributes["provider"]; found {
		traversal, diagnostics := hcl.AbsTraversalForExpr(attribute.Expr)
		if diagnostics.HasErrors() || len(traversal) != 2 || traversal.RootName() != vaultProvider {
			return "", false, "its provider argument is not of the form vault.<alias>"
		}
		step, isAttribute := traversal[1].(hcl.TraverseAttr)
		if !isAttribute {
			return "", false, "its provider argument is not of the form vault.<alias>"
		}
		alias = step.Name
	}

	providerNamespace := ""
	settings := r.providers[alias]
	switch {
	case len(settings) == 0 && alias != "":
		return "", false, fmt.Sprintf("its provider vault.%s is not defined in any .tf file under --repo", alias)
	case len(settings) > 1:
		return "", false, fmt.Sprintf("provider vault%s is defined %d times under --repo, so Mitch cannot tell which one this resource uses", aliasSuffix(alias), len(settings))
	case len(settings) == 1:
		if !settings[0].namespaceKnown {
			return "", false, fmt.Sprintf("the namespace of provider vault%s (%s:%d) is not a plain value", aliasSuffix(alias), settings[0].file, settings[0].line)
		}
		providerNamespace = settings[0].namespace
	}

	resourceNamespace := ""
	if _, found := block.attributes["namespace"]; found {
		context := r.evalContext(block.folder, references)
		value, known := attributeString(block.attributes, "namespace", context)
		if !known {
			return "", false, notPlainReason("namespace")
		}
		resourceNamespace = value
	}
	return joinNamespace(providerNamespace, resourceNamespace), true, ""
}

// joinNamespace joins a provider namespace and a relative namespace into
// the scan's form: "team-a/dev/", or "" for root.
func joinNamespace(parts ...string) string {
	cleaned := []string{}
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	return strings.Join(cleaned, "/") + "/"
}

// aliasSuffix writes an alias as Terraform does: vault.<alias>, or vault.
func aliasSuffix(alias string) string {
	if alias == "" {
		return ""
	}
	return "." + alias
}

// notPlainReason explains why an argument was not checked.
func notPlainReason(argument string) string {
	return fmt.Sprintf("its %s argument is not a plain value (it uses a variable, a module input or another expression Mitch cannot work out without running Terraform)", argument)
}

// evalContext is what an expression may use: path.module, path.root and
// path.cwd, references to other vault resources' paths and names, and the
// file() function. Anything else, such as var.x, makes the value unknown.
func (r *repoReader) evalContext(folder string, references map[string]cty.Value) *hcl.EvalContext {
	variables := map[string]cty.Value{
		// Docs: https://developer.hashicorp.com/terraform/language/expressions/references#filesystem-and-workspace-info
		"path": cty.ObjectVal(map[string]cty.Value{
			"module": cty.StringVal(folder),
			"root":   cty.StringVal(r.root),
			"cwd":    cty.StringVal(r.root),
		}),
	}
	for name, value := range references {
		variables[name] = value
	}
	return &hcl.EvalContext{
		Variables: variables,
		Functions: map[string]function.Function{"file": r.fileFunction()},
	}
}

// fileFunction is Terraform's file(): it returns a file's contents as text.
// A relative path is relative to the root module, which Mitch takes to be
// the --repo folder. A file outside the checkout is refused.
// Docs: https://developer.hashicorp.com/terraform/language/functions/file
func (r *repoReader) fileFunction() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{Name: "path", Type: cty.String}},
		Type:   function.StaticReturnType(cty.String),
		Impl: func(arguments []cty.Value, _ cty.Type) (cty.Value, error) {
			requested := arguments[0].AsString()
			if !filepath.IsAbs(requested) {
				requested = filepath.Join(r.root, requested)
			}
			resolved, err := filepath.EvalSymlinks(requested)
			if err != nil {
				return cty.NilVal, fmt.Errorf("file(%q): %w", r.relative(requested), err)
			}
			if resolved != r.root && !strings.HasPrefix(resolved, r.root+string(filepath.Separator)) {
				return cty.NilVal, fmt.Errorf("file(%q) points outside --repo, so Mitch does not read it", requested)
			}
			content, err := os.ReadFile(resolved)
			if err != nil {
				return cty.NilVal, fmt.Errorf("file(%q): %w", r.relative(resolved), err)
			}
			// Terraform's file() refuses text that is not UTF-8.
			if !utf8.Valid(content) {
				return cty.NilVal, fmt.Errorf("file(%q) is not valid UTF-8 text", r.relative(resolved))
			}
			return cty.StringVal(string(content)), nil
		},
	})
}

// relative writes a path relative to the checkout, for messages.
func (r *repoReader) relative(path string) string {
	relative, err := filepath.Rel(r.root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}

// referenceVariables lets one resource refer to another's path or name, as
// in path = vault_auth_backend.ldap.path. Only values found in the first
// pass are offered.
func referenceVariables(resources map[string]Resource) map[string]cty.Value {
	byType := map[string]map[string]cty.Value{}
	for address, resource := range resources {
		if resource.Name == "" {
			continue
		}
		resourceType, name, _ := strings.Cut(address, ".")
		attributes := map[string]cty.Value{}
		if resource.Kind == KindPolicy {
			attributes["name"] = cty.StringVal(resource.Name)
		} else {
			path := strings.TrimSuffix(resource.Name, "/")
			attributes["path"] = cty.StringVal(path)
			// Some resources call the path "backend" or "mount".
			attributes["backend"] = cty.StringVal(path)
			attributes["mount"] = cty.StringVal(path)
		}
		if byType[resourceType] == nil {
			byType[resourceType] = map[string]cty.Value{}
		}
		byType[resourceType][name] = cty.ObjectVal(attributes)
	}
	variables := map[string]cty.Value{}
	for resourceType, named := range byType {
		variables[resourceType] = cty.ObjectVal(named)
	}
	return variables
}

// attributeString evaluates an argument that must be a plain string.
func attributeString(attributes hcl.Attributes, name string, context *hcl.EvalContext) (string, bool) {
	attribute, found := attributes[name]
	if !found {
		return "", true
	}
	value, known, err := evaluateString(attribute.Expr, context)
	if err != nil {
		return "", false
	}
	return value, known
}

// plainString evaluates an expression with no variables or functions.
func plainString(expression hcl.Expression, context *hcl.EvalContext) (string, bool) {
	value, known, err := evaluateString(expression, context)
	if err != nil {
		return "", false
	}
	return value, known
}

// evaluateString works out a string. known is false when the expression
// needs something Mitch does not have, such as a variable. err is set when a
// function such as file() failed, so the message can say why.
func evaluateString(expression hcl.Expression, context *hcl.EvalContext) (string, bool, error) {
	value, diagnostics := expression.Value(context)
	if diagnostics.HasErrors() {
		for _, diagnostic := range diagnostics {
			// A failed file() call says what went wrong; pass that on.
			if diagnostic.Summary == "Error in function call" {
				return "", false, errors.New(diagnostic.Detail)
			}
		}
		return "", false, nil
	}
	if value.IsNull() || !value.IsWhollyKnown() || !value.Type().Equals(cty.String) {
		return "", false, nil
	}
	return value.AsString(), true, nil
}

// isMountResource reports whether a resource type creates a mount.
func isMountResource(resourceType string) bool {
	_, found := mountResources[resourceType]
	return found
}

// sortRepo keeps output stable: by file, then line.
func sortRepo(repo *Repo) {
	sort.SliceStable(repo.Resources, func(i, j int) bool {
		if repo.Resources[i].File != repo.Resources[j].File {
			return repo.Resources[i].File < repo.Resources[j].File
		}
		return repo.Resources[i].Line < repo.Resources[j].Line
	})
	sort.SliceStable(repo.NotChecked, func(i, j int) bool {
		if repo.NotChecked[i].File != repo.NotChecked[j].File {
			return repo.NotChecked[i].File < repo.NotChecked[j].File
		}
		return repo.NotChecked[i].Line < repo.NotChecked[j].Line
	})
}
