package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/jfrappier/mitch/internal/checks"
	"github.com/jfrappier/mitch/internal/vaultclient"
)

// listNamespacesRecursively returns the full path of every namespace under
// parent, depth first. It is only called on Vault Enterprise.
//
// LIST sys/namespaces returns the direct children of the namespace the
// request is sent to, so Mitch asks each child for its own children.
func (s *Scanner) listNamespacesRecursively(ctx context.Context, parent string, depth int) ([]string, error) {
	if depth > maxNamespaceDepth {
		return nil, fmt.Errorf("namespace nesting under %q is deeper than %d levels; stopping to avoid a loop", parent, maxNamespaceDepth)
	}

	if !s.beginCheck(checks.CheckNamespaces, "") {
		return []string{}, nil
	}

	response, err := s.client.List(ctx, "list_namespaces", parent, "sys/namespaces")
	if err != nil {
		// Vault answers LIST with 404 when there is nothing to list.
		requestError, isRequestError := vaultclient.AsRequestError(err)
		if isRequestError && requestError.StatusCode == 404 {
			return []string{}, nil
		}
		return []string{}, s.handleFailure(checks.CheckNamespaces, parent, err)
	}

	var parsed struct {
		Keys []string `json:"keys"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return nil, fmt.Errorf("sys/namespaces returned unexpected JSON: %w", err)
	}

	allPaths := []string{}
	for _, childKey := range parsed.Keys {
		childPath := parent + childKey
		allPaths = append(allPaths, childPath)

		grandchildren, err := s.listNamespacesRecursively(ctx, childPath, depth+1)
		if err != nil {
			return nil, err
		}
		allPaths = append(allPaths, grandchildren...)
	}

	return allPaths, nil
}

// scanNamespace reads secrets engines, auth methods and ACL policies in one namespace.
func (s *Scanner) scanNamespace(ctx context.Context, namespace string) (NamespaceInventory, error) {
	result := NamespaceInventory{
		Path:           namespace,
		SecretsEngines: []Mount{},
		AuthMethods:    []Mount{},
		ACLPolicies:    []Policy{},
	}

	secretsEngines, err := s.readMounts(ctx, namespace, checks.CheckMounts, "list_secrets_engines", "sys/mounts")
	if err != nil {
		return result, err
	}
	result.SecretsEngines = secretsEngines

	authMethods, err := s.readMounts(ctx, namespace, checks.CheckAuthMethods, "list_auth_methods", "sys/auth")
	if err != nil {
		return result, err
	}
	result.AuthMethods = authMethods

	policies, err := s.readPolicies(ctx, namespace)
	if err != nil {
		return result, err
	}
	result.ACLPolicies = policies

	return result, nil
}

// readMounts calls GET sys/mounts or GET sys/auth. Both return a map from
// mount path to mount details.
func (s *Scanner) readMounts(ctx context.Context, namespace string, checkName string, operation string, path string) ([]Mount, error) {
	mounts := []Mount{}

	if !s.beginCheck(checkName, namespace) {
		return mounts, nil
	}

	response, err := s.client.Read(ctx, operation, namespace, path)
	if err != nil {
		return mounts, s.handleFailure(checkName, namespace, err)
	}

	var mountsByPath map[string]Mount
	err = json.Unmarshal(response.Data, &mountsByPath)
	if err != nil {
		return mounts, fmt.Errorf("%s returned unexpected JSON: %w", path, err)
	}

	for _, mountPath := range sortedKeys(mountsByPath) {
		mount := mountsByPath[mountPath]
		mount.Path = mountPath
		mounts = append(mounts, mount)
	}
	return mounts, nil
}

// readPolicies calls LIST sys/policies/acl, then GET sys/policies/acl/:name
// for each policy.
func (s *Scanner) readPolicies(ctx context.Context, namespace string) ([]Policy, error) {
	policies := []Policy{}

	if !s.beginCheck(checks.CheckPolicyList, namespace) {
		return policies, nil
	}

	response, err := s.client.List(ctx, "list_acl_policies", namespace, "sys/policies/acl")
	if err != nil {
		return policies, s.handleFailure(checks.CheckPolicyList, namespace, err)
	}

	var parsed struct {
		Keys []string `json:"keys"`
	}
	err = json.Unmarshal(response.Data, &parsed)
	if err != nil {
		return policies, fmt.Errorf("sys/policies/acl returned unexpected JSON: %w", err)
	}

	if !s.beginCheck(checks.CheckPolicyRead, namespace) {
		// We know the names but cannot read the text.
		for _, policyName := range parsed.Keys {
			policies = append(policies, Policy{Name: policyName})
		}
		return policies, nil
	}

	for _, policyName := range parsed.Keys {
		policyPath := "sys/policies/acl/" + url.PathEscape(policyName)

		policyResponse, err := s.client.Read(ctx, "read_acl_policy", namespace, policyPath)
		if err != nil {
			handled := s.handleFailure(checks.CheckPolicyRead, namespace, err)
			if handled != nil {
				return policies, handled
			}
			policies = append(policies, Policy{Name: policyName})
			continue
		}

		var policy Policy
		err = json.Unmarshal(policyResponse.Data, &policy)
		if err != nil {
			return policies, fmt.Errorf("%s returned unexpected JSON: %w", policyPath, err)
		}
		policies = append(policies, policy)
	}

	return policies, nil
}
