package scan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/vaultclient"
)

// fakeVault is a tiny stand-in for Vault. Each route maps
// "METHOD namespace path" to a status code and JSON body.
// These tests cover Enterprise behavior (namespaces) and failure cases that
// a Vault Community dev server cannot produce.
type fakeVault struct {
	mutex    sync.Mutex
	routes   map[string]fakeAnswer
	requests []string
}

// grantAll is a fake answer body that grants every capability-self path.
const grantAll = "GRANT_ALL"

type fakeAnswer struct {
	status int
	body   string
}

func (f *fakeVault) set(method string, namespace string, path string, status int, body string) {
	f.routes[method+" "+namespace+" "+path] = fakeAnswer{status: status, body: body}
}

func (f *fakeVault) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	namespace := request.Header.Get(vaultapi.NamespaceHeaderName)
	path := strings.TrimPrefix(request.URL.Path, "/v1/")

	// Mitch sends LIST as GET with list=true; route it as LIST.
	method := request.Method
	if method == http.MethodGet && request.URL.Query().Get("list") == "true" {
		method = "LIST"
	}
	key := method + " " + namespace + " " + path

	f.mutex.Lock()
	f.requests = append(f.requests, key)
	answer, found := f.routes[key]
	f.mutex.Unlock()

	// The special body "GRANT_ALL" answers sys/capabilities-self with "root"
	// for every path that was asked about, like a root token would get.
	if found && answer.body == grantAll {
		var requestBody struct {
			Paths []string `json:"paths"`
		}
		_ = json.NewDecoder(request.Body).Decode(&requestBody)
		capabilitiesByPath := map[string][]string{}
		for _, askedPath := range requestBody.Paths {
			capabilitiesByPath[askedPath] = []string{"root"}
		}
		encoded, _ := json.Marshal(map[string]any{"data": capabilitiesByPath})
		writer.WriteHeader(http.StatusOK)
		writer.Write(encoded)
		return
	}

	if !found {
		writer.WriteHeader(http.StatusNotFound)
		io.WriteString(writer, `{"errors":[]}`)
		return
	}
	writer.WriteHeader(answer.status)
	io.WriteString(writer, answer.body)
}

// newFakeVault returns a fake Community Vault where every check succeeds.
// Tests change routes to create the case they need.
func newFakeVault() *fakeVault {
	fake := &fakeVault{routes: make(map[string]fakeAnswer)}

	fake.set("GET", "", "sys/health", 200, `{"initialized":true,"sealed":false,"version":"2.2.2","enterprise":false}`)
	fake.set("PUT", "", "sys/capabilities-self", 200, grantAll)
	fake.set("GET", "", "sys/config/state/sanitized", 200, `{"data":{"api_addr":""}}`)
	fake.set("LIST", "", "sys/version-history", 200, `{"data":{"keys":["2.2.2"],"key_info":{"2.2.2":{"build_date":"2026-11-11T13:53:02Z","previous_version":null,"timestamp_installed":"2026-11-13T00:00:00Z"}}}}`)
	fake.set("GET", "", "sys/plugins/catalog", 200, `{"data":{"detailed":[
		{"name":"kv","type":"secret","version":"v0.27.0+builtin","builtin":true,"deprecation_status":"supported"},
		{"name":"my-plugin","type":"secret","version":"v1.0.0","builtin":false}]}}`)
	fake.set("GET", "", "sys/mounts", 200, `{"data":{"secret/":{"type":"kv","options":{"version":"2"},"config":{"default_lease_ttl":0,"max_lease_ttl":0}}}}`)
	fake.set("GET", "", "sys/auth", 200, `{"data":{"token/":{"type":"token","config":{"token_type":"default-service"}}}}`)
	fake.set("LIST", "", "sys/policies/acl", 200, `{"data":{"keys":["default"]}}`)
	fake.set("GET", "", "sys/policies/acl/default", 200, `{"data":{"name":"default","policy":"path \"x\" {}"}}`)
	fake.set("GET", "", "sys/audit", 200, `{"data":{"file/":{"type":"file","description":"","options":{"file_path":"/tmp/audit.log"}}}}`)
	fake.set("LIST", "", "sys/plugins/runtimes/catalog", 200, `{"data":{"runtimes":[]}}`)
	fake.set("GET", "", "sys/plugins/catalog/secret/my-plugin", 200, `{"data":{"sha256":"abc123","command":"my-plugin","args":[]}}`)

	return fake
}

// runFakeScan scans the fake Vault and returns the result.
func runFakeScan(t *testing.T, fake *fakeVault, options Options) (*Inventory, error) {
	t.Helper()

	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)

	config := vaultapi.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0
	apiClient, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatalf("creating the official client failed: %v", err)
	}
	apiClient.SetToken("test-token")

	logger, _ := logging.New(logging.Options{Output: io.Discard, Format: logging.FormatText, Level: logging.LevelInfo})
	client := vaultclient.NewFromAPIClient(apiClient, logger)

	return New(client, logger, options).Run(context.Background())
}

func TestCommunityScanReadsEverything(t *testing.T) {
	inventory, err := runFakeScan(t, newFakeVault(), Options{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(inventory.Skipped) != 0 {
		t.Errorf("expected no skipped checks, got %+v", inventory.Skipped)
	}
	if len(inventory.Namespaces) != 1 {
		t.Fatalf("expected only the root namespace, got %d", len(inventory.Namespaces))
	}
	root := inventory.Namespaces[0]
	if len(root.SecretsEngines) != 1 || root.SecretsEngines[0].Path != "secret/" || root.SecretsEngines[0].Options["version"] != "2" {
		t.Errorf("unexpected secrets engines: %+v", root.SecretsEngines)
	}
	if len(root.AuthMethods) != 1 || root.AuthMethods[0].Config.TokenType != "default-service" {
		t.Errorf("unexpected auth methods: %+v", root.AuthMethods)
	}
	if len(root.ACLPolicies) != 1 || root.ACLPolicies[0].Text == "" {
		t.Errorf("unexpected policies: %+v", root.ACLPolicies)
	}
	if inventory.AuditDevices != nil {
		t.Errorf("audit devices must not be read without --sudo")
	}
}

func TestSudoScanReadsRegisteredPluginDetailsOnly(t *testing.T) {
	fake := newFakeVault()
	inventory, err := runFakeScan(t, fake, Options{Sudo: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, plugin := range inventory.Plugins {
		if plugin.Name == "my-plugin" && plugin.SHA256 != "abc123" {
			t.Errorf("expected sha256 for the registered plugin, got %+v", plugin)
		}
		if plugin.Name == "kv" && plugin.SHA256 != "" {
			t.Errorf("built-in plugins must not be read in detail, got %+v", plugin)
		}
	}
	for _, request := range fake.requests {
		if strings.Contains(request, "sys/plugins/catalog/secret/kv") {
			t.Errorf("Mitch requested details for a built-in plugin: %s", request)
		}
	}
	if len(inventory.AuditDevices) != 1 || inventory.AuditDevices[0].Path != "file/" {
		t.Errorf("unexpected audit devices: %+v", inventory.AuditDevices)
	}
}

func TestEnterpriseScanWalksNestedNamespaces(t *testing.T) {
	fake := newFakeVault()
	fake.set("GET", "", "sys/health", 200, `{"initialized":true,"sealed":false,"version":"2.2.2+ent","enterprise":true}`)
	fake.set("LIST", "", "sys/namespaces", 200, `{"data":{"keys":["team-a/"]}}`)
	fake.set("LIST", "team-a/", "sys/namespaces", 200, `{"data":{"keys":["dev/"]}}`)
	// team-a/dev/ has no children: the fake answers 404, like Vault does.
	for _, namespace := range []string{"team-a/", "team-a/dev/"} {
		fake.set("PUT", namespace, "sys/capabilities-self", 200, grantAll)
		fake.set("GET", namespace, "sys/mounts", 200, `{"data":{}}`)
		fake.set("GET", namespace, "sys/auth", 200, `{"data":{}}`)
		fake.set("LIST", namespace, "sys/policies/acl", 200, `{"data":{"keys":[]}}`)
	}

	inventory, err := runFakeScan(t, fake, Options{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var paths []string
	for _, namespace := range inventory.Namespaces {
		paths = append(paths, namespace.Path)
	}
	expected := []string{"", "team-a/", "team-a/dev/"}
	if strings.Join(paths, ",") != strings.Join(expected, ",") {
		t.Errorf("expected namespaces %v, got %v", expected, paths)
	}
	if len(inventory.Skipped) != 0 {
		t.Errorf("expected no skipped checks, got %+v", inventory.Skipped)
	}

	// Root-only endpoints must never be sent to a child namespace.
	for _, request := range fake.requests {
		if strings.Contains(request, "team-a/") && strings.Contains(request, "sys/config/state") {
			t.Errorf("root-only endpoint was sent to a child namespace: %s", request)
		}
	}
}

func TestPreflightSkipsChecksTheTokenCannotRun(t *testing.T) {
	fake := newFakeVault()
	fake.set("PUT", "", "sys/capabilities-self", 200, `{"data":{"sys/mounts":["deny"],"sys/auth":["read"]}}`)

	inventory, err := runFakeScan(t, fake, Options{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundSkip := false
	for _, skipped := range inventory.Skipped {
		if skipped.Check == "secrets_engines" && skipped.HTTPStatus == 0 {
			foundSkip = true
		}
	}
	if !foundSkip {
		t.Errorf("expected secrets_engines to be skipped by preflight, got %+v", inventory.Skipped)
	}
	for _, request := range fake.requests {
		if request == "GET  sys/mounts" {
			t.Error("Mitch called sys/mounts even though preflight showed it is denied")
		}
	}
}

func TestSealedVaultStopsTheScan(t *testing.T) {
	fake := newFakeVault()
	fake.set("GET", "", "sys/health", 200, `{"initialized":true,"sealed":true,"version":"2.2.2"}`)

	_, err := runFakeScan(t, fake, Options{})
	if err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Errorf("expected a sealed error, got %v", err)
	}
}

func TestServerErrorStopsTheScan(t *testing.T) {
	fake := newFakeVault()
	fake.set("GET", "", "sys/mounts", 500, `{"errors":["internal error"]}`)

	_, err := runFakeScan(t, fake, Options{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected the scan to stop with HTTP 500, got %v", err)
	}
}

func TestNotFoundIsRecordedAndScanContinues(t *testing.T) {
	fake := newFakeVault()
	delete(fake.routes, "GET  sys/config/state/sanitized")

	inventory, err := runFakeScan(t, fake, Options{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(inventory.Skipped) != 1 || inventory.Skipped[0].HTTPStatus != 404 {
		t.Errorf("expected one skipped check with HTTP 404, got %+v", inventory.Skipped)
	}
	if len(inventory.Namespaces) != 1 {
		t.Error("expected the scan to continue after the 404")
	}
}

func TestInventoryJSONUsesSnakeCase(t *testing.T) {
	inventory, err := runFakeScan(t, newFakeVault(), Options{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	for _, key := range []string{`"secrets_engines"`, `"auth_methods"`, `"acl_policies"`, `"not_requested"`, `"skipped"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("expected key %s in the JSON output", key)
		}
	}
}
