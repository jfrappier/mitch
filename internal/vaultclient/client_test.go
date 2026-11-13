package vaultclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jfrappier/mitch/internal/logging"
)

// newTestClient starts a fake Vault server that answers with handler, and
// returns a Mitch client pointed at it plus the buffer its logs go to.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *bytes.Buffer) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	config := vaultapi.DefaultConfig()
	config.Address = server.URL
	config.MaxRetries = 0

	apiClient, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatalf("creating the official client failed: %v", err)
	}
	apiClient.SetToken("test-token")

	var logOutput bytes.Buffer
	logger, err := logging.New(logging.Options{Output: &logOutput, Format: logging.FormatText, Level: logging.LevelDebug})
	if err != nil {
		t.Fatalf("creating the logger failed: %v", err)
	}

	return NewFromAPIClient(apiClient, logger), &logOutput
}

func TestReadReturnsDataField(t *testing.T) {
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/sys/mounts" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"data":{"secret/":{"type":"kv"}}}`)
	})

	response, err := client.Read(context.Background(), "list_mounts", "", "sys/mounts")
	if err != nil {
		t.Fatalf("Read returned an unexpected error: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", response.StatusCode)
	}
	if !strings.Contains(string(response.Data), `"secret/"`) {
		t.Errorf("expected the data field, got %s", response.Data)
	}
}

func TestListSendsGetWithListTrue(t *testing.T) {
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Query().Get("list") != "true" {
			t.Errorf("expected GET with list=true, got %s %s", request.Method, request.URL.String())
		}
		io.WriteString(writer, `{"data":{"keys":["default"]}}`)
	})

	_, err := client.List(context.Background(), "list_policies", "", "sys/policies/acl")
	if err != nil {
		t.Fatalf("List returned an unexpected error: %v", err)
	}
}

func TestNamespaceHeaderIsSetOnlyWhenGiven(t *testing.T) {
	var seenNamespaces []string
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		seenNamespaces = append(seenNamespaces, request.Header.Get(vaultapi.NamespaceHeaderName))
		io.WriteString(writer, `{"data":{}}`)
	})

	_, _ = client.Read(context.Background(), "test", "", "sys/mounts")
	_, _ = client.Read(context.Background(), "test", "team-a/", "sys/mounts")

	if seenNamespaces[0] != "" {
		t.Errorf("root request should have no namespace header, got %q", seenNamespaces[0])
	}
	if seenNamespaces[1] != "team-a/" {
		t.Errorf("expected namespace header %q, got %q", "team-a/", seenNamespaces[1])
	}
}

func TestCheckOwnCapabilitiesSendsPaths(t *testing.T) {
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/v1/sys/capabilities-self" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		var body struct {
			Paths []string `json:"paths"`
		}
		err := json.NewDecoder(request.Body).Decode(&body)
		if err != nil || len(body.Paths) != 2 {
			t.Errorf("expected two paths in the body, got %v (error %v)", body.Paths, err)
		}
		io.WriteString(writer, `{"data":{"sys/mounts":["read"],"sys/auth":["deny"]}}`)
	})

	_, err := client.CheckOwnCapabilities(context.Background(), "", []string{"sys/mounts", "sys/auth"})
	if err != nil {
		t.Fatalf("CheckOwnCapabilities returned an unexpected error: %v", err)
	}
}

func TestPermissionDeniedIsLoudAndSpecific(t *testing.T) {
	client, logOutput := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		io.WriteString(writer, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
	})

	_, err := client.Read(context.Background(), "list_audit_devices", "", "sys/audit")
	if err == nil {
		t.Fatal("expected an error for HTTP 403, got none")
	}

	requestError, found := AsRequestError(err)
	if !found {
		t.Fatalf("expected a RequestError, got %T", err)
	}
	if !requestError.IsPermissionDenied() {
		t.Errorf("expected IsPermissionDenied to be true for status %d", requestError.StatusCode)
	}

	message := err.Error()
	expectedParts := []string{"list_audit_devices", "GET sys/audit", "HTTP 403", "permission denied", "mitch policy"}
	for _, expected := range expectedParts {
		if !strings.Contains(message, expected) {
			t.Errorf("error message is missing %q\nfull message: %s", expected, message)
		}
	}

	logLine := logOutput.String()
	if !strings.Contains(logLine, "http_status=403") || !strings.Contains(logLine, "duration_ms=") {
		t.Errorf("log line is missing http_status or duration_ms\nfull line: %s", logLine)
	}
}

func TestNoResponseHasStatusZeroAndNetworkAdvice(t *testing.T) {
	config := vaultapi.DefaultConfig()
	config.Address = "http://127.0.0.1:1" // nothing listens on port 1
	config.MaxRetries = 0
	apiClient, err := vaultapi.NewClient(config)
	if err != nil {
		t.Fatalf("creating the official client failed: %v", err)
	}
	apiClient.SetToken("test-token")

	logger, _ := logging.New(logging.Options{Output: io.Discard, Format: logging.FormatText, Level: logging.LevelInfo})
	client := NewFromAPIClient(apiClient, logger)

	_, err = client.Read(context.Background(), "read_health", "", "sys/health")
	requestError, found := AsRequestError(err)
	if !found {
		t.Fatalf("expected a RequestError, got %v", err)
	}
	if requestError.StatusCode != 0 {
		t.Errorf("expected status 0 when nothing answered, got %d", requestError.StatusCode)
	}
	if !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Errorf("expected advice about VAULT_ADDR, got %q", err.Error())
	}
}

func TestInvalidJSONFailsLoudly(t *testing.T) {
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, `not json`)
	})

	_, err := client.Read(context.Background(), "list_mounts", "", "sys/mounts")
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("expected a not-valid-JSON error, got %v", err)
	}
}

func TestNewWithoutTokenFails(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	t.Setenv("HOME", t.TempDir()) // so a ~/.vault-token file on the test machine is not used

	logger, _ := logging.New(logging.Options{Output: io.Discard, Format: logging.FormatText, Level: logging.LevelInfo})
	_, err := New(logger)
	if err == nil || !strings.Contains(err.Error(), "VAULT_TOKEN") {
		t.Errorf("expected an error naming VAULT_TOKEN, got %v", err)
	}
}

func TestEmptyListIsNotAnError(t *testing.T) {
	client, logOutput := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		io.WriteString(writer, `{"errors":[]}`)
	})

	response, err := client.List(context.Background(), "list_namespaces", "", "sys/namespaces")
	if err != nil {
		t.Fatalf("an empty list must not be an error, got: %v", err)
	}
	if string(response.Data) != `{"keys":[]}` {
		t.Errorf("expected an empty key list, got %s", response.Data)
	}
	if strings.Contains(logOutput.String(), "level=WARN") {
		t.Errorf("an empty list must not log a warning\nlogs:\n%s", logOutput.String())
	}
}

func TestNotFoundWithMessageIsStillAnError(t *testing.T) {
	client, _ := newTestClient(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		io.WriteString(writer, `{"errors":["enterprise-only feature"]}`)
	})

	_, err := client.List(context.Background(), "list_namespaces", "", "sys/namespaces")
	if err == nil || !strings.Contains(err.Error(), "enterprise-only feature") {
		t.Errorf("expected Vault's message in the error, got %v", err)
	}
}
