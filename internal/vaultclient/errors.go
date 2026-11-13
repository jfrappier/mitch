package vaultclient

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// RequestError describes one failed Vault call in enough detail to fix it.
type RequestError struct {
	// Operation is what Mitch was doing, for example "list_mounts".
	Operation string

	// Method and Path are the HTTP method and Vault path, for example LIST sys/policies/acl.
	Method string
	Path   string

	// Namespace is the Vault Enterprise namespace, or "" for root.
	Namespace string

	// StatusCode is the HTTP status from Vault. It is 0 when no response
	// arrived at all, for example when the address is wrong or TLS failed.
	StatusCode int

	// VaultErrors are the error messages Vault sent back, if any.
	VaultErrors []string

	// NextStep tells the user what to do about it.
	NextStep string

	// Cause is the underlying error from the HTTP client.
	Cause error
}

// Error builds a one-line message: what failed, where, the status, Vault's
// own message, and the next step.
func (e *RequestError) Error() string {
	var message strings.Builder

	fmt.Fprintf(&message, "%s failed: %s %s", e.Operation, e.Method, e.Path)
	if e.Namespace != "" {
		fmt.Fprintf(&message, " in namespace %q", e.Namespace)
	}

	if e.StatusCode == 0 {
		message.WriteString(": no response from Vault")
	} else {
		fmt.Fprintf(&message, ": HTTP %d", e.StatusCode)
	}

	// Prefer Vault's own words. When Vault answered but sent no message, the
	// status code says it all. Only show the raw cause when Vault never
	// answered, for example a DNS or TLS failure.
	if len(e.VaultErrors) > 0 {
		fmt.Fprintf(&message, ": Vault said %q", strings.Join(e.VaultErrors, "; "))
	} else if e.StatusCode == 0 && e.Cause != nil {
		fmt.Fprintf(&message, ": %v", e.Cause)
	}

	if e.NextStep != "" {
		fmt.Fprintf(&message, ". Next step: %s", e.NextStep)
	}

	return message.String()
}

// Summary is a shorter message without the next step, for places that show
// the next step separately: "GET sys/audit returned HTTP 403: permission denied".
func (e *RequestError) Summary() string {
	if e.StatusCode == 0 {
		return fmt.Sprintf("%s %s got no response from Vault", e.Method, e.Path)
	}
	if len(e.VaultErrors) > 0 {
		return fmt.Sprintf("%s %s returned HTTP %d: %s", e.Method, e.Path, e.StatusCode, strings.Join(e.VaultErrors, "; "))
	}
	return fmt.Sprintf("%s %s returned HTTP %d", e.Method, e.Path, e.StatusCode)
}

// Unwrap lets errors.Is and errors.As see the underlying error.
func (e *RequestError) Unwrap() error {
	return e.Cause
}

// IsPermissionDenied reports whether Vault refused the call with HTTP 403.
func (e *RequestError) IsPermissionDenied() bool {
	return e.StatusCode == http.StatusForbidden
}

// AsRequestError returns the RequestError inside err, if there is one.
func AsRequestError(err error) (*RequestError, bool) {
	var requestError *RequestError
	found := errors.As(err, &requestError)
	return requestError, found
}

// newRequestError builds a RequestError and picks the next step from the status code.
func newRequestError(operation string, method string, path string, namespace string, statusCode int, cause error) *RequestError {
	requestError := &RequestError{
		Operation:  operation,
		Method:     method,
		Path:       path,
		Namespace:  namespace,
		StatusCode: statusCode,
		Cause:      cause,
	}

	// The official client returns a ResponseError that carries Vault's own messages.
	var responseError *vaultapi.ResponseError
	if errors.As(cause, &responseError) {
		for _, vaultMessage := range responseError.Errors {
			requestError.VaultErrors = append(requestError.VaultErrors, cleanVaultMessage(vaultMessage))
		}
		if requestError.StatusCode == 0 {
			requestError.StatusCode = responseError.StatusCode
		}
	}

	requestError.NextStep = nextStepFor(requestError.StatusCode, path)
	return requestError
}

// cleanVaultMessage turns Vault's multi-line error text into one line.
// Vault often sends "1 error occurred:\n\t* permission denied\n\n"; this
// returns "permission denied".
func cleanVaultMessage(message string) string {
	var parts []string
	for _, line := range strings.Split(message, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.TrimPrefix(trimmed, "* ")
		if trimmed == "" || strings.HasSuffix(trimmed, "error occurred:") || strings.HasSuffix(trimmed, "errors occurred:") {
			continue
		}
		parts = append(parts, trimmed)
	}
	if len(parts) == 0 {
		return strings.TrimSpace(message)
	}
	return strings.Join(parts, "; ")
}

// nextStepFor turns an HTTP status into advice the user can act on.
func nextStepFor(statusCode int, path string) string {
	switch statusCode {
	case 0:
		return "check VAULT_ADDR, network access to Vault, and TLS settings (VAULT_CACERT)"
	case http.StatusBadRequest:
		return "this is likely a Mitch bug or an unsupported Vault version; please report it with this log line"
	case http.StatusForbidden:
		return fmt.Sprintf("the token is missing a capability on %q; run \"mitch policy\" to see the policy Mitch needs, or check that VAULT_TOKEN is valid", path)
	case http.StatusNotFound:
		return "the path does not exist on this Vault, or the feature needs a newer Vault version or Vault Enterprise"
	case http.StatusTooManyRequests:
		return "Vault rate-limited the request; try again later or ask the Vault admin about rate limit quotas"
	case http.StatusServiceUnavailable:
		return "Vault is sealed or in maintenance; unseal it or point VAULT_ADDR at an active node"
	default:
		if statusCode >= http.StatusInternalServerError {
			return "Vault had an internal error; check the Vault server logs"
		}
		return ""
	}
}
