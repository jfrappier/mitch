package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"time"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/vaultclient"
)

// maxNamespaceDepth stops runaway recursion if Vault ever reports a cycle.
const maxNamespaceDepth = 32

// Options controls what a scan does.
type Options struct {
	// Sudo turns on the checks that need the sudo capability.
	Sudo bool

	// CountKV turns on counting secrets in KV mounts.
	CountKV bool

	// MitchVersion is recorded in the inventory.
	MitchVersion string
}

// Scanner runs one scan. Create it with New and call Run once.
type Scanner struct {
	client    *vaultclient.Client
	logger    *slog.Logger
	options   Options
	inventory *Inventory

	// allowed records the preflight result for each namespace and check.
	// A missing entry means preflight could not run, so the check is tried anyway.
	allowed map[string]bool
}

// New creates a scanner that uses the given Vault client.
func New(client *vaultclient.Client, logger *slog.Logger, options Options) *Scanner {
	scanner := &Scanner{
		client:  client,
		logger:  logging.ForComponent(logger, "scan"),
		options: options,
		allowed: make(map[string]bool),
	}
	return scanner
}

// Run scans Vault and returns the inventory.
//
// Permission problems (HTTP 403) and missing endpoints (HTTP 404) do not stop
// the scan: they are recorded in Inventory.Skipped. Anything else, such as
// Vault being unreachable, sealed, or returning HTTP 500, stops the scan with
// an error, because the results would be misleading.
func (s *Scanner) Run(ctx context.Context) (*Inventory, error) {
	s.inventory = &Inventory{
		MitchVersion:   s.options.MitchVersion,
		StartedAt:      time.Now().UTC(),
		VaultAddress:   s.client.Address(),
		SudoRequested:  s.options.Sudo,
		Preflight:      []PreflightResult{},
		VersionHistory: []VersionHistoryEntry{},
		Plugins:        []Plugin{},
		Namespaces:     []NamespaceInventory{},
		Skipped:        []SkippedCheck{},
		NotRequested:   []NotRequestedCheck{},
	}

	s.logger.Info("scan started", logging.FieldOperation, "scan", "vault_address", s.client.Address(), "sudo", s.options.Sudo, "count_kv", s.options.CountKV)

	// Step 1: health. This tells us the version and edition, and stops the
	// scan early if Vault is sealed.
	err := s.readHealth(ctx)
	if err != nil {
		return nil, err
	}

	s.recordNotRequested()

	// Step 2: preflight and cluster-wide checks in the root namespace.
	err = s.preflight(ctx, "")
	if err != nil {
		return nil, err
	}

	err = s.scanRootOnlyChecks(ctx)
	if err != nil {
		return nil, err
	}

	// Step 3: find every namespace (Enterprise only). Root is always first.
	namespacePaths := []string{""}
	if s.inventory.Health.Enterprise {
		childPaths, err := s.listNamespacesRecursively(ctx, "", 0)
		if err != nil {
			return nil, err
		}
		namespacePaths = append(namespacePaths, childPaths...)
	}

	// Step 4: per-namespace checks.
	for _, namespacePath := range namespacePaths {
		if namespacePath != "" {
			err = s.preflight(ctx, namespacePath)
			if err != nil {
				return nil, err
			}
		}

		namespaceInventory, err := s.scanNamespace(ctx, namespacePath)
		if err != nil {
			return nil, err
		}
		s.inventory.Namespaces = append(s.inventory.Namespaces, namespaceInventory)
	}

	s.inventory.FinishedAt = time.Now().UTC()

	s.logger.Info("scan finished",
		logging.FieldOperation, "scan",
		"namespaces", len(s.inventory.Namespaces),
		"skipped_checks", len(s.inventory.Skipped),
		logging.FieldDurationMS, s.inventory.FinishedAt.Sub(s.inventory.StartedAt).Milliseconds(),
	)

	return s.inventory, nil
}

// readHealth calls GET sys/health. standbyok and perfstandbyok make standby
// nodes answer 200 instead of an error code, since they can still be scanned.
func (s *Scanner) readHealth(ctx context.Context) error {
	query := url.Values{}
	query.Set("standbyok", "true")
	query.Set("perfstandbyok", "true")

	response, err := s.client.ReadWithQuery(ctx, "read_health", "", "sys/health", query)
	if err != nil {
		return fmt.Errorf("cannot start the scan: %w", err)
	}

	err = json.Unmarshal(response.Body, &s.inventory.Health)
	if err != nil {
		return fmt.Errorf("cannot start the scan: sys/health returned unexpected JSON: %w", err)
	}

	if !s.inventory.Health.Initialized {
		return fmt.Errorf("cannot start the scan: Vault at %s is not initialized", s.client.Address())
	}
	if s.inventory.Health.Sealed {
		return fmt.Errorf("cannot start the scan: Vault at %s is sealed; unseal it and run the scan again", s.client.Address())
	}

	s.logger.Info("connected to Vault",
		logging.FieldOperation, "read_health",
		"vault_version", s.inventory.Health.Version,
		"enterprise", s.inventory.Health.Enterprise,
	)
	return nil
}

// recordNotRequested lists the checks that will not run on purpose.
func (s *Scanner) recordNotRequested() {
	if !s.options.CountKV {
		s.inventory.NotRequested = append(s.inventory.NotRequested, NotRequestedCheck{
			Check:  checks.CheckKVCount,
			Reason: "counting secrets in KV mounts was turned off",
		})
	}

	for _, check := range checks.All() {
		if check.NeedsSudo && !s.options.Sudo {
			s.inventory.NotRequested = append(s.inventory.NotRequested, NotRequestedCheck{
				Check:  check.Name,
				Reason: "needs the sudo capability; run with --sudo and attach the " + checks.SudoPolicyName + " policy to include it",
			})
		}
		if check.EnterpriseOnly && !s.inventory.Health.Enterprise {
			s.inventory.NotRequested = append(s.inventory.NotRequested, NotRequestedCheck{
				Check:  check.Name,
				Reason: "only available on Vault Enterprise",
			})
		}
	}
}

// shouldRun reports whether a check applies to this cluster, namespace and run.
func (s *Scanner) shouldRun(check checks.Check, namespace string) bool {
	if check.NeedsSudo && !s.options.Sudo {
		return false
	}
	if check.EnterpriseOnly && !s.inventory.Health.Enterprise {
		return false
	}
	if check.RootNamespaceOnly && namespace != "" {
		return false
	}
	return true
}

// preflight asks Vault which of the needed grants the token has in one
// namespace, using POST sys/capabilities-self.
//
// If the token cannot call sys/capabilities-self, preflight is skipped and
// every check is attempted; failures are then recorded per check.
func (s *Scanner) preflight(ctx context.Context, namespace string) error {
	var applicable []checks.Check
	var probePaths []string
	for _, check := range checks.All() {
		if s.shouldRun(check, namespace) {
			applicable = append(applicable, check)
			probePaths = append(probePaths, check.ProbePath)
		}
	}

	response, err := s.client.CheckOwnCapabilities(ctx, namespace, probePaths)
	if err != nil {
		requestError, isRequestError := vaultclient.AsRequestError(err)
		if isRequestError && requestError.IsPermissionDenied() {
			s.logger.Warn("preflight unavailable: token cannot call sys/capabilities-self; every check will be attempted",
				logging.FieldOperation, "preflight",
				"namespace", namespaceLabel(namespace),
				"next_step", `attach the policy from "mitch policy", which grants update on sys/capabilities-self`,
			)
			return nil
		}
		return fmt.Errorf("preflight failed: %w", err)
	}

	var grantedByPath map[string][]string
	err = json.Unmarshal(response.Data, &grantedByPath)
	if err != nil {
		return fmt.Errorf("preflight failed: sys/capabilities-self returned unexpected JSON: %w", err)
	}

	for _, check := range applicable {
		granted := grantedByPath[check.ProbePath]
		if granted == nil {
			granted = []string{}
		}
		isAllowed := checks.HasCapabilities(granted, check.Capabilities)

		s.allowed[allowedKey(namespace, check.Name)] = isAllowed
		s.inventory.Preflight = append(s.inventory.Preflight, PreflightResult{
			Check:     check.Name,
			Namespace: namespace,
			Path:      check.PolicyPath,
			Required:  check.Capabilities,
			Granted:   granted,
			Allowed:   isAllowed,
		})

		if !isAllowed {
			s.logger.Warn("token is missing a grant; this check will be skipped",
				logging.FieldOperation, "preflight",
				"check", check.Name,
				"namespace", namespaceLabel(namespace),
				"policy_path", check.PolicyPath,
				"required", check.Capabilities,
				"granted", granted,
				"next_step", `run "mitch policy" to see the policy Mitch needs`,
			)
		}
	}

	return nil
}

// isAllowed returns false only when preflight ran and showed the grant is missing.
func (s *Scanner) isAllowed(namespace string, checkName string) bool {
	allowed, preflightRan := s.allowed[allowedKey(namespace, checkName)]
	if !preflightRan {
		return true
	}
	return allowed
}

// beginCheck decides whether a check should run now. When preflight showed
// the grant is missing, it records the check as skipped and returns false.
func (s *Scanner) beginCheck(checkName string, namespace string) bool {
	check, found := checks.Find(checkName)
	if !found {
		// A programming error: every check name must be listed in package checks.
		panic("unknown check name: " + checkName)
	}

	if !s.shouldRun(check, namespace) {
		return false
	}

	if !s.isAllowed(namespace, checkName) {
		s.inventory.Skipped = append(s.inventory.Skipped, SkippedCheck{
			Check:      check.Name,
			Namespace:  namespace,
			Path:       check.PolicyPath,
			HTTPStatus: 0,
			Reason:     fmt.Sprintf("preflight: token lacks %v on %q", check.Capabilities, check.PolicyPath),
			NextStep:   `run "mitch policy" to see the policy Mitch needs`,
		})
		return false
	}

	return true
}

// handleFailure decides what a failed Vault call means for the scan.
//
// HTTP 4xx answers (permission denied, not found, and so on) are recorded as
// skipped checks and the scan continues. Anything else is returned as an error
// and stops the scan.
func (s *Scanner) handleFailure(checkName string, namespace string, err error) error {
	requestError, isRequestError := vaultclient.AsRequestError(err)
	isClientError := isRequestError && requestError.StatusCode >= 400 && requestError.StatusCode < 500

	if !isClientError {
		return fmt.Errorf("scan stopped during check %q: %w", checkName, err)
	}

	s.inventory.Skipped = append(s.inventory.Skipped, SkippedCheck{
		Check:      checkName,
		Namespace:  namespace,
		Path:       requestError.Path,
		HTTPStatus: requestError.StatusCode,
		Reason:     requestError.Summary(),
		NextStep:   requestError.NextStep,
	})
	return nil
}

// wasSkipped reports whether a check was recorded as skipped in a namespace.
func (s *Scanner) wasSkipped(checkName string, namespace string) bool {
	for _, skipped := range s.inventory.Skipped {
		if skipped.Check == checkName && skipped.Namespace == namespace {
			return true
		}
	}
	return false
}

// allowedKey builds the map key for one namespace and check.
func allowedKey(namespace string, checkName string) string {
	return namespace + "|" + checkName
}

// namespaceLabel shows the root namespace as "root" in logs.
func namespaceLabel(namespace string) string {
	if namespace == "" {
		return "root"
	}
	return namespace
}

// sortedKeys returns the keys of a map in alphabetical order, so output is
// the same on every run.
func sortedKeys[Value any](input map[string]Value) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
