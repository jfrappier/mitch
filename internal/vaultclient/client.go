// Package vaultclient is the only part of Mitch that talks to Vault.
//
// It wraps HashiCorp's official Go client (github.com/hashicorp/vault/api)
// so that every call:
//
//   - is read-only (GET, LIST, or the one PUT used to check our own permissions),
//   - is logged in the standard Mitch format with http_status and duration_ms,
//   - fails with a RequestError that says what failed and what to do next.
//
// Connection settings come from the standard Vault environment variables, the
// same ones the vault CLI uses: VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE,
// VAULT_CACERT, VAULT_CLIENT_CERT, VAULT_CLIENT_KEY, VAULT_SKIP_VERIFY, and so on.
package vaultclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/jfrappier/mitch/internal/logging"
)

// The kinds of request Mitch sends. These names appear in logs and errors.
//
// LIST is Vault's method for listing keys. Mitch sends it as GET with the
// query parameter list=true, which the Vault docs describe as equivalent and
// which needs the same "list" capability:
// https://developer.hashicorp.com/vault/api-docs#reading-writing-and-listing-secrets
//
// PUT is only used for sys/capabilities-self, which reports the caller's own
// permissions and changes nothing. (The docs show POST; Vault treats PUT and
// POST the same, and the official client sends PUT.)
const (
	methodGet  = http.MethodGet
	methodList = "LIST"
	methodPut  = http.MethodPut
)

// Client sends read-only requests to one Vault cluster.
type Client struct {
	api    *vaultapi.Client
	logger *slog.Logger
}

// Response is the decoded body of a successful Vault call.
type Response struct {
	// StatusCode is the HTTP status Vault returned, for example 200.
	StatusCode int

	// Data is the "data" object from the response body, left as raw JSON so
	// each caller can decode it into the exact shape it expects.
	// It is empty when the response had no "data" field.
	Data json.RawMessage

	// Body is the whole response body, for the few endpoints (like
	// sys/health) that do not wrap their result in "data".
	Body json.RawMessage
}

// New creates a client from the standard Vault environment variables.
//
// It fails, instead of continuing, when the environment is invalid or no
// token is set, because every later call would fail with a less clear error.
func New(logger *slog.Logger) (*Client, error) {
	config := vaultapi.DefaultConfig()
	if config.Error != nil {
		return nil, fmt.Errorf("vault client: reading Vault settings from the environment failed: %w", config.Error)
	}

	apiClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("vault client: creating the Vault client failed: %w", err)
	}

	if apiClient.Token() == "" {
		return nil, errors.New("vault client: no Vault token found: set VAULT_TOKEN to a token that has the Mitch policy attached")
	}

	client := &Client{
		api:    apiClient,
		logger: logging.ForComponent(logger, "vault"),
	}
	return client, nil
}

// NewFromAPIClient wraps an existing official client. Tests use this to point
// Mitch at a fake Vault server.
func NewFromAPIClient(apiClient *vaultapi.Client, logger *slog.Logger) *Client {
	client := &Client{
		api:    apiClient,
		logger: logging.ForComponent(logger, "vault"),
	}
	return client
}

// Address returns the Vault address this client talks to.
func (c *Client) Address() string {
	return c.api.Address()
}

// Read sends GET /v1/<path>.
//
// operation is a short name for what Mitch is doing, such as "list_mounts".
// It appears in logs and errors. namespace is the Vault Enterprise namespace
// to send the request to; use "" for the root namespace.
func (c *Client) Read(ctx context.Context, operation string, namespace string, path string) (*Response, error) {
	return c.send(ctx, operation, namespace, methodGet, path, nil, nil)
}

// ReadWithQuery sends GET /v1/<path>?<query>, for endpoints that take query
// parameters, such as sys/health?standbyok=true.
func (c *Client) ReadWithQuery(ctx context.Context, operation string, namespace string, path string, query url.Values) (*Response, error) {
	return c.send(ctx, operation, namespace, methodGet, path, query, nil)
}

// List lists the keys under a path (Vault's LIST operation).
//
// Vault answers an empty list with HTTP 404 and an empty "errors" array, as
// described in https://developer.hashicorp.com/vault/api-docs#reading-writing-and-listing-secrets.
// List turns exactly that answer into a normal response with no keys (see
// send), so callers don't mistake "nothing here" for "not found".
func (c *Client) List(ctx context.Context, operation string, namespace string, path string) (*Response, error) {
	return c.send(ctx, operation, namespace, methodList, path, nil, nil)
}

// CheckOwnCapabilities sends PUT /v1/sys/capabilities-self, which returns
// the capabilities the current token has on each of the given paths.
// It changes nothing in Vault.
//
// Docs: https://developer.hashicorp.com/vault/api-docs/system/capabilities-self
func (c *Client) CheckOwnCapabilities(ctx context.Context, namespace string, paths []string) (*Response, error) {
	body := map[string]any{"paths": paths}
	return c.send(ctx, "check_own_capabilities", namespace, methodPut, "sys/capabilities-self", nil, body)
}

// send does the actual HTTP call, logs it, and turns failures into a RequestError.
// query and body are optional; pass nil when not needed.
func (c *Client) send(ctx context.Context, operation string, namespace string, method string, path string, query url.Values, body any) (*Response, error) {
	cleanPath := strings.TrimPrefix(path, "/")

	// Always choose the namespace explicitly, so a VAULT_NAMESPACE environment
	// variable can never silently send a request somewhere else.
	// WithNamespace returns a copy of the client; an empty namespace means root.
	// (Setting the header on a single request does not work: the official
	// client overwrites it with the client's own namespace.)
	namespacedClient := c.api.WithNamespace(namespace)
	logical := namespacedClient.Logical()

	startTime := time.Now()

	var rawResponse *vaultapi.Response
	var requestErr error

	switch method {
	case methodGet:
		rawResponse, requestErr = logical.ReadRawWithDataWithContext(ctx, cleanPath, query)

	case methodList:
		listQuery := url.Values{}
		for key, values := range query {
			listQuery[key] = values
		}
		listQuery.Set("list", "true")
		rawResponse, requestErr = logical.ReadRawWithDataWithContext(ctx, cleanPath, listQuery)

	case methodPut:
		encodedBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vault client: encoding the request body for %s failed: %w", operation, err)
		}
		rawResponse, requestErr = logical.WriteRawWithContext(ctx, cleanPath, encodedBody)

	default:
		return nil, fmt.Errorf("vault client: method %q is not allowed; Mitch only reads", method)
	}

	durationMS := time.Since(startTime).Milliseconds()

	statusCode := 0
	if rawResponse != nil {
		statusCode = rawResponse.StatusCode
		defer closeBody(rawResponse)
	}

	if requestErr != nil {
		failure := newRequestError(operation, method, cleanPath, namespace, statusCode, requestErr)

		// An empty LIST comes back as HTTP 404 with no error messages.
		// That is a normal "no keys" answer, not a failure.
		isEmptyList := method == methodList && failure.StatusCode == http.StatusNotFound && len(failure.VaultErrors) == 0
		if isEmptyList {
			c.logger.Debug("vault returned an empty list",
				logging.FieldOperation, operation,
				"method", method,
				"path", cleanPath,
				"namespace", namespaceForLog(namespace),
				logging.FieldHTTPStatus, failure.StatusCode,
				logging.FieldDurationMS, durationMS,
			)
			emptyList := &Response{
				StatusCode: failure.StatusCode,
				Data:       json.RawMessage(`{"keys":[]}`),
			}
			return emptyList, nil
		}

		c.logger.Warn("vault request failed",
			logging.FieldOperation, operation,
			"method", method,
			"path", cleanPath,
			"namespace", namespaceForLog(namespace),
			logging.FieldHTTPStatus, failure.StatusCode,
			logging.FieldDurationMS, durationMS,
			logging.FieldError, failure.Error(),
		)
		return nil, failure
	}

	c.logger.Debug("vault request succeeded",
		logging.FieldOperation, operation,
		"method", method,
		"path", cleanPath,
		"namespace", namespaceForLog(namespace),
		logging.FieldHTTPStatus, statusCode,
		logging.FieldDurationMS, durationMS,
	)

	// Some endpoints return 204 No Content. That is a success with no data.
	if statusCode == http.StatusNoContent {
		return &Response{StatusCode: statusCode}, nil
	}

	// Keep the whole body, then pull out the "data" field. Most endpoints put
	// their result in "data"; a few, such as sys/health, put it at the top level.
	var wholeBody json.RawMessage
	err := rawResponse.DecodeJSON(&wholeBody)
	if err != nil {
		return nil, fmt.Errorf("vault client: %s: Vault returned HTTP %d for %s %s but the body was not valid JSON: %w",
			operation, statusCode, method, cleanPath, err)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	err = json.Unmarshal(wholeBody, &envelope)
	if err != nil {
		return nil, fmt.Errorf("vault client: %s: Vault returned HTTP %d for %s %s but the body was not a JSON object: %w",
			operation, statusCode, method, cleanPath, err)
	}

	response := &Response{
		StatusCode: statusCode,
		Body:       wholeBody,
		Data:       envelope.Data,
	}
	return response, nil
}

// closeBody closes a response body. A failure to close only leaks a
// connection, never data, so it is ignored on purpose.
func closeBody(response *vaultapi.Response) {
	_ = response.Body.Close()
}

// namespaceForLog shows the root namespace as "root" instead of an empty value,
// so log lines are easier to read.
func namespaceForLog(namespace string) string {
	if namespace == "" {
		return "root"
	}
	return namespace
}
