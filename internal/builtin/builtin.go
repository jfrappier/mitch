// Package builtin lists the mounts and policies that Vault creates itself.
//
// Nobody can enable, disable, move or delete them, so Mitch never writes
// Terraform for them and never reports them as missing from git.
package builtin

// secretsEngines are Vault's own "protectedMounts" (vault/mount.go). Vault
// 2.x adds agent-registry/, which every Vault 2.x server has.
// Source: https://github.com/hashicorp/vault/blob/main/vault/mount.go
// Docs: https://developer.hashicorp.com/vault/docs/secrets/cubbyhole and
// https://developer.hashicorp.com/vault/docs/secrets/identity
var secretsEngines = map[string]bool{"sys/": true, "identity/": true, "cubbyhole/": true, "agent-registry/": true}

// authMethods are auth methods Vault creates itself.
// Docs: https://developer.hashicorp.com/vault/docs/auth/token
var authMethods = map[string]bool{"token/": true}

// RootPolicy is the built-in policy that cannot be read or changed.
// Docs: https://developer.hashicorp.com/vault/docs/concepts/policies#root-policy
const RootPolicy = "root"

// DefaultPolicy is the built-in policy every namespace has. It can be
// changed, so Terraform may manage it, but it can never be deleted.
// Docs: https://developer.hashicorp.com/vault/docs/concepts/policies#default-policy
const DefaultPolicy = "default"

// IsSecretsEngine reports whether a secrets engine path, such as "sys/",
// is one Vault creates itself.
func IsSecretsEngine(path string) bool {
	return secretsEngines[path]
}

// IsAuthMethod reports whether an auth method path, such as "token/", is one
// Vault creates itself.
func IsAuthMethod(path string) bool {
	return authMethods[path]
}
