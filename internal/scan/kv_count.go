package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/logging"
	"github.com/jfrappier/mitch/internal/vaultclient"
)

// maxKVFolderDepth stops the walk if folders are nested deeper than this.
// Real KV trees are far shallower; this only guards against a runaway walk.
const maxKVFolderDepth = 64

// redactedFolder replaces folder names in logs, errors and the inventory.
const redactedFolder = "<redacted>"

// countKVSecrets counts secrets and folders in every KV mount of one namespace.
//
// It lists key names folder by folder, one request at a time, so the load
// on Vault stays low. It never reads secret values.
//
// Docs:
//
//	KV v1: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v1#list-secrets
//	KV v2: https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#list-secrets
func (s *Scanner) countKVSecrets(ctx context.Context, namespace string, secretsEngines []Mount) ([]KVCount, error) {
	counts := []KVCount{}

	kvMounts := s.findKVMounts(namespace, secretsEngines)
	if len(kvMounts) == 0 {
		return counts, nil
	}

	allowedByMount, err := s.preflightKV(ctx, namespace, kvMounts)
	if err != nil {
		return nil, err
	}

	for _, mount := range kvMounts {
		allowed, preflightRan := allowedByMount[mount.Path]
		if preflightRan && !allowed {
			s.inventory.Skipped = append(s.inventory.Skipped, SkippedCheck{
				Check:      checks.CheckKVCount,
				Namespace:  namespace,
				Path:       checks.KVPolicyPath(mount),
				HTTPStatus: 0,
				Reason:     fmt.Sprintf("preflight: token lacks [list] on %q", checks.KVPolicyPath(mount)),
				NextStep:   kvNextStep(mount),
			})
			counts = append(counts, KVCount{Mount: mount.Path, KVVersion: mount.Version, Complete: false})
			continue
		}

		count, err := s.walkKVMount(ctx, namespace, mount)
		if err != nil {
			return nil, err
		}
		counts = append(counts, count)
	}

	return counts, nil
}

// findKVMounts picks the KV mounts out of the secrets engine list.
//
// sys/mounts shows the KV version in options.version: "2" for KV v2, and
// "1" or nothing for KV v1.
// Docs: https://developer.hashicorp.com/vault/api-docs/system/mounts
func (s *Scanner) findKVMounts(namespace string, secretsEngines []Mount) []checks.KVMount {
	kvMounts := []checks.KVMount{}

	for _, engine := range secretsEngines {
		if engine.Type != "kv" {
			continue
		}

		versionText := engine.Options["version"]
		switch versionText {
		case "2":
			kvMounts = append(kvMounts, checks.KVMount{Path: engine.Path, Version: 2})
		case "1", "":
			kvMounts = append(kvMounts, checks.KVMount{Path: engine.Path, Version: 1})
		default:
			s.inventory.Skipped = append(s.inventory.Skipped, SkippedCheck{
				Check:      checks.CheckKVCount,
				Namespace:  namespace,
				Path:       engine.Path,
				HTTPStatus: 0,
				Reason:     fmt.Sprintf("KV mount reports options.version %q; Mitch only knows versions 1 and 2", versionText),
				NextStep:   "please report this with your Vault version",
			})
		}
	}

	return kvMounts
}

// preflightKV asks sys/capabilities-self whether the token can list each KV
// mount. It returns mount path -> allowed.
//
// If the token cannot call sys/capabilities-self, it returns an empty map and
// every mount is tried; failures are then recorded per mount.
func (s *Scanner) preflightKV(ctx context.Context, namespace string, kvMounts []checks.KVMount) (map[string]bool, error) {
	allowedByMount := make(map[string]bool)

	probePaths := []string{}
	for _, mount := range kvMounts {
		probePaths = append(probePaths, checks.KVListPath(mount, ""))
	}

	response, err := s.client.CheckOwnCapabilities(ctx, namespace, probePaths)
	if err != nil {
		requestError, isRequestError := vaultclient.AsRequestError(err)
		if isRequestError && requestError.IsPermissionDenied() {
			// The main preflight already logged this once for the namespace.
			return allowedByMount, nil
		}
		return nil, fmt.Errorf("preflight for KV mounts failed: %w", err)
	}

	var grantedByPath map[string][]string
	err = json.Unmarshal(response.Data, &grantedByPath)
	if err != nil {
		return nil, fmt.Errorf("preflight for KV mounts failed: sys/capabilities-self returned unexpected JSON: %w", err)
	}

	required := []string{"list"}
	for _, mount := range kvMounts {
		probePath := checks.KVListPath(mount, "")
		granted := grantedByPath[probePath]
		if granted == nil {
			granted = []string{}
		}
		isAllowed := checks.HasCapabilities(granted, required)
		allowedByMount[mount.Path] = isAllowed

		s.inventory.Preflight = append(s.inventory.Preflight, PreflightResult{
			Check:     checks.CheckKVCount,
			Namespace: namespace,
			Path:      checks.KVPolicyPath(mount),
			Required:  required,
			Granted:   granted,
			Allowed:   isAllowed,
		})

		if !isAllowed {
			s.logger.Warn("token cannot list this KV mount; its secrets will not be counted",
				logging.FieldOperation, "preflight",
				"check", checks.CheckKVCount,
				"namespace", namespaceLabel(namespace),
				"policy_path", checks.KVPolicyPath(mount),
				"required", required,
				"granted", granted,
				"next_step", kvNextStep(mount),
			)
		}
	}

	return allowedByMount, nil
}

// walkKVMount lists every folder in one KV mount and counts what it finds.
//
// A folder that cannot be listed (any HTTP 4xx) is counted as a failure and
// the walk carries on with the rest of the mount. Anything else, such as
// Vault going away or HTTP 500, stops the scan.
func (s *Scanner) walkKVMount(ctx context.Context, namespace string, mount checks.KVMount) (KVCount, error) {
	count := KVCount{Mount: mount.Path, KVVersion: mount.Version, Complete: true}

	startTime := time.Now()
	listRequests := 0
	failedFolders := 0
	var firstFailure *vaultclient.RequestError

	// foldersToList holds folders not listed yet, relative to the mount.
	// "" is the top of the mount.
	foldersToList := []string{""}

	for len(foldersToList) > 0 {
		lastIndex := len(foldersToList) - 1
		folder := foldersToList[lastIndex]
		foldersToList = foldersToList[:lastIndex]

		if strings.Count(folder, "/") > maxKVFolderDepth {
			return count, fmt.Errorf("KV mount %s in namespace %s has folders nested deeper than %d levels; stopping to avoid a runaway walk",
				mount.Path, namespaceLabel(namespace), maxKVFolderDepth)
		}

		keys, err := s.listKVFolder(ctx, namespace, mount, folder)
		listRequests++
		if err != nil {
			requestError, isRequestError := vaultclient.AsRequestError(err)
			isClientError := isRequestError && requestError.StatusCode >= 400 && requestError.StatusCode < 500
			if !isClientError {
				return count, fmt.Errorf("scan stopped while counting secrets in KV mount %s: %w", mount.Path, err)
			}

			failedFolders++
			if firstFailure == nil {
				firstFailure = requestError
			}
			continue
		}

		for _, key := range keys {
			isFolder := strings.HasSuffix(key, "/")
			if isFolder {
				count.Folders++
				foldersToList = append(foldersToList, folder+key)
			} else {
				count.Secrets++
			}
		}
	}

	if failedFolders > 0 {
		count.Complete = false
		s.recordKVFailure(namespace, mount, failedFolders, listRequests, firstFailure)
	}

	s.logger.Info("counted secrets in KV mount",
		logging.FieldOperation, "count_kv_secrets",
		"namespace", namespaceLabel(namespace),
		"mount", mount.Path,
		"kv_version", mount.Version,
		"secrets", count.Secrets,
		"folders", count.Folders,
		"list_requests", listRequests,
		"failed_folders", failedFolders,
		"complete", count.Complete,
		logging.FieldDurationMS, time.Since(startTime).Milliseconds(),
	)

	return count, nil
}

// listKVFolder lists the keys in one folder. Folder keys end in "/".
//
// The top of the mount is listed with its real path, because mount paths are
// already in the inventory. Folders below it are listed with ListRedacted, so
// their names never reach logs or errors.
func (s *Scanner) listKVFolder(ctx context.Context, namespace string, mount checks.KVMount, folder string) ([]string, error) {
	listPath := checks.KVListPath(mount, folder)

	var response *vaultclient.Response
	var err error
	if folder == "" {
		response, err = s.client.List(ctx, "list_kv_keys", namespace, listPath)
	} else {
		displayPath := checks.KVListPath(mount, "") + redactedFolder
		response, err = s.client.ListRedacted(ctx, "list_kv_keys", namespace, listPath, displayPath)
	}
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Keys []string `json:"keys"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return nil, fmt.Errorf("listing KV mount %s returned unexpected JSON: %w", mount.Path, err)
	}
	return parsed.Keys, nil
}

// recordKVFailure adds one skipped entry for a mount where some folders could
// not be listed. One entry per mount keeps the list short on big trees.
func (s *Scanner) recordKVFailure(namespace string, mount checks.KVMount, failedFolders int, listRequests int, firstFailure *vaultclient.RequestError) {
	nextStep := firstFailure.NextStep
	if firstFailure.StatusCode == http.StatusForbidden {
		nextStep = kvNextStep(mount)
	}

	s.inventory.Skipped = append(s.inventory.Skipped, SkippedCheck{
		Check:      checks.CheckKVCount,
		Namespace:  namespace,
		Path:       checks.KVPolicyPath(mount),
		HTTPStatus: firstFailure.StatusCode,
		Reason: fmt.Sprintf("%d of %d folders could not be listed, so the counts are incomplete; first failure: %s",
			failedFolders, listRequests, firstFailure.Summary()),
		NextStep: nextStep,
	})
}

// kvNextStep tells the user how to grant list on one KV mount.
func kvNextStep(mount checks.KVMount) string {
	return fmt.Sprintf(`run "mitch policy --kv%d-mount %s" and attach the printed %s policy to the token`,
		mount.Version, mount.Path, checks.KVPolicyName)
}
