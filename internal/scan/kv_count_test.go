package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jfrappier/mitch/internal/checks"
)

// newFakeVaultWithKV returns a fake Vault with one KV v1 and one KV v2 mount:
//
//	kv1/      one, f/two                         -> 2 secrets, 1 folder
//	secret/   top, app/db, app/api, team/x/deep   -> 4 secrets, 3 folders
//
// Folder names include "team" so tests can check they never reach the logs.
// Routes have no trailing slash because the official client trims it from
// the URL; Vault answers both forms the same.
func newFakeVaultWithKV() *fakeVault {
	fake := newFakeVault()

	fake.set("GET", "", "sys/mounts", 200, `{"data":{
		"secret/":{"type":"kv","options":{"version":"2"}},
		"kv1/":{"type":"kv","options":{"version":"1"}},
		"transit/":{"type":"transit","options":null}}}`)

	fake.set("LIST", "", "kv1", 200, `{"data":{"keys":["one","f/"]}}`)
	fake.set("LIST", "", "kv1/f", 200, `{"data":{"keys":["two"]}}`)

	fake.set("LIST", "", "secret/metadata", 200, `{"data":{"keys":["top","app/","team/"]}}`)
	fake.set("LIST", "", "secret/metadata/app", 200, `{"data":{"keys":["db","api"]}}`)
	fake.set("LIST", "", "secret/metadata/team", 200, `{"data":{"keys":["x/"]}}`)
	fake.set("LIST", "", "secret/metadata/team/x", 200, `{"data":{"keys":["deep"]}}`)

	return fake
}

// kvCountFor returns the count for one mount in the root namespace.
func kvCountFor(t *testing.T, inventory *Inventory, mountPath string) KVCount {
	t.Helper()
	for _, count := range inventory.Namespaces[0].KVCounts {
		if count.Mount == mountPath {
			return count
		}
	}
	t.Fatalf("no kv_counts entry for %q; got %+v", mountPath, inventory.Namespaces[0].KVCounts)
	return KVCount{}
}

func TestKVCountsBothVersions(t *testing.T) {
	inventory, err := runFakeScan(t, newFakeVaultWithKV(), Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(inventory.Skipped) != 0 {
		t.Errorf("expected no skipped checks, got %+v", inventory.Skipped)
	}

	kvCounts := inventory.Namespaces[0].KVCounts
	if len(kvCounts) != 2 {
		t.Fatalf("expected 2 KV mounts (transit is not KV), got %+v", kvCounts)
	}

	v1 := kvCountFor(t, inventory, "kv1/")
	expectedV1 := KVCount{Mount: "kv1/", KVVersion: 1, Secrets: 2, Folders: 1, Complete: true}
	if v1 != expectedV1 {
		t.Errorf("KV v1 count: expected %+v, got %+v", expectedV1, v1)
	}

	v2 := kvCountFor(t, inventory, "secret/")
	expectedV2 := KVCount{Mount: "secret/", KVVersion: 2, Secrets: 4, Folders: 3, Complete: true}
	if v2 != expectedV2 {
		t.Errorf("KV v2 count: expected %+v, got %+v", expectedV2, v2)
	}

	// Preflight asked about both mounts, by the path Mitch lists first.
	preflightPaths := []string{}
	for _, result := range inventory.Preflight {
		if result.Check == checks.CheckKVCount {
			preflightPaths = append(preflightPaths, result.Path)
		}
	}
	if strings.Join(preflightPaths, ",") != "kv1/*,secret/metadata/*" {
		t.Errorf("expected KV preflight for kv1/* and secret/metadata/*, got %v", preflightPaths)
	}
}

func TestKVCountingNeverReadsSecretData(t *testing.T) {
	fake := newFakeVaultWithKV()
	_, err := runFakeScan(t, fake, Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, request := range fake.requests {
		isKVRequest := strings.Contains(request, " kv1/") || strings.Contains(request, " secret/")
		if isKVRequest && !strings.HasPrefix(request, "LIST ") {
			t.Errorf("KV counting must only send LIST, but sent %q", request)
		}
		if strings.Contains(request, "secret/data/") {
			t.Errorf("KV counting must never touch secret data, but sent %q", request)
		}
	}
}

func TestKVCountingOffLeavesCountsNull(t *testing.T) {
	inventory, err := runFakeScan(t, newFakeVaultWithKV(), Options{CountKV: false})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if inventory.Namespaces[0].KVCounts != nil {
		t.Errorf("expected kv_counts to be null when counting is off, got %+v", inventory.Namespaces[0].KVCounts)
	}

	foundNotRequested := false
	for _, notRequested := range inventory.NotRequested {
		if notRequested.Check == checks.CheckKVCount {
			foundNotRequested = true
		}
	}
	if !foundNotRequested {
		t.Errorf("expected %s in not_requested, got %+v", checks.CheckKVCount, inventory.NotRequested)
	}

	encoded, _ := json.Marshal(inventory.Namespaces[0])
	if !strings.Contains(string(encoded), `"kv_counts":null`) {
		t.Errorf("expected \"kv_counts\":null in JSON, got %s", encoded)
	}
}

func TestKVPreflightDenialSkipsMount(t *testing.T) {
	fake := newFakeVaultWithKV()
	fake.deniedPaths["secret/metadata/"] = true

	inventory, err := runFakeScan(t, fake, Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	denied := kvCountFor(t, inventory, "secret/")
	if denied.Complete || denied.Secrets != 0 {
		t.Errorf("a denied mount must be incomplete with no counts, got %+v", denied)
	}
	allowed := kvCountFor(t, inventory, "kv1/")
	if !allowed.Complete || allowed.Secrets != 2 {
		t.Errorf("the allowed mount must still be counted, got %+v", allowed)
	}

	if len(inventory.Skipped) != 1 {
		t.Fatalf("expected one skipped entry, got %+v", inventory.Skipped)
	}
	skipped := inventory.Skipped[0]
	if skipped.Check != checks.CheckKVCount || skipped.Path != "secret/metadata/*" || skipped.HTTPStatus != 0 {
		t.Errorf("unexpected skipped entry %+v", skipped)
	}
	if !strings.Contains(skipped.NextStep, "mitch policy --kv2-mount secret/") {
		t.Errorf("next step should name the exact policy command, got %q", skipped.NextStep)
	}

	for _, request := range fake.requests {
		if strings.HasPrefix(request, "LIST  secret/") {
			t.Errorf("a mount denied in preflight must not be listed, but sent %q", request)
		}
	}
}

func TestKVPartialDenialIsIncompleteAndRedacted(t *testing.T) {
	fake := newFakeVaultWithKV()
	fake.set("LIST", "", "secret/metadata/team", 403, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)

	var logOutput bytes.Buffer
	inventory, err := runFakeScanWithLogs(t, fake, Options{CountKV: true}, &logOutput)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	count := kvCountFor(t, inventory, "secret/")
	expected := KVCount{Mount: "secret/", KVVersion: 2, Secrets: 3, Folders: 2, Complete: false}
	if count != expected {
		t.Errorf("expected %+v, got %+v", expected, count)
	}

	if len(inventory.Skipped) != 1 {
		t.Fatalf("expected one skipped entry for the mount, got %+v", inventory.Skipped)
	}
	skipped := inventory.Skipped[0]
	if skipped.HTTPStatus != 403 || !strings.Contains(skipped.Reason, "1 of 3 folders") {
		t.Errorf("unexpected skipped entry %+v", skipped)
	}

	// Folder names must not appear anywhere: not in logs, not in the inventory.
	encoded, _ := json.Marshal(inventory)
	for _, output := range []string{logOutput.String(), string(encoded)} {
		if strings.Contains(output, "team") {
			t.Errorf("a folder name leaked into the output:\n%s", output)
		}
	}
	if !strings.Contains(logOutput.String(), "secret/metadata/<redacted>") {
		t.Errorf("expected the failed folder to be logged as secret/metadata/<redacted>\nlogs:\n%s", logOutput.String())
	}
}

func TestKVServerErrorStopsScan(t *testing.T) {
	fake := newFakeVaultWithKV()
	fake.set("LIST", "", "secret/metadata/team", 500, `{"errors":["internal error"]}`)

	_, err := runFakeScan(t, fake, Options{CountKV: true})
	if err == nil {
		t.Fatal("expected HTTP 500 during KV counting to stop the scan")
	}
	if !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "secret/") {
		t.Errorf("error should name the mount and status, got %v", err)
	}
	if strings.Contains(err.Error(), "team") {
		t.Errorf("error leaked a folder name: %v", err)
	}
}

func TestKVUnknownVersionIsSkipped(t *testing.T) {
	fake := newFakeVault()
	fake.set("GET", "", "sys/mounts", 200, `{"data":{"odd/":{"type":"kv","options":{"version":"3"}}}}`)

	inventory, err := runFakeScan(t, fake, Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(inventory.Namespaces[0].KVCounts) != 0 {
		t.Errorf("expected no counts for an unknown KV version, got %+v", inventory.Namespaces[0].KVCounts)
	}
	if len(inventory.Skipped) != 1 || !strings.Contains(inventory.Skipped[0].Reason, `"3"`) {
		t.Errorf("expected a skipped entry naming version 3, got %+v", inventory.Skipped)
	}
}

func TestKVNotCountedWhenMountsUnreadable(t *testing.T) {
	fake := newFakeVaultWithKV()
	fake.set("GET", "", "sys/mounts", 403, `{"errors":["permission denied"]}`)

	inventory, err := runFakeScan(t, fake, Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if inventory.Namespaces[0].KVCounts != nil {
		t.Errorf("expected kv_counts null when sys/mounts could not be read, got %+v", inventory.Namespaces[0].KVCounts)
	}
}

func TestKVEnterpriseNamespaceUsesNamespaceHeader(t *testing.T) {
	fake := newFakeVaultWithKV()
	fake.set("GET", "", "sys/health", 200, `{"initialized":true,"sealed":false,"version":"2.2.2+ent","enterprise":true}`)
	fake.set("LIST", "", "sys/namespaces", 200, `{"data":{"keys":["team-a/"]}}`)
	fake.set("PUT", "team-a/", "sys/capabilities-self", 200, grantAll)
	fake.set("GET", "team-a/", "sys/mounts", 200, `{"data":{"kv/":{"type":"kv","options":{"version":"2"}}}}`)
	fake.set("LIST", "team-a/", "kv/metadata", 200, `{"data":{"keys":["a","b","c"]}}`)

	inventory, err := runFakeScan(t, fake, Options{CountKV: true})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(inventory.Namespaces) != 2 {
		t.Fatalf("expected root and team-a/, got %d namespaces", len(inventory.Namespaces))
	}

	teamCounts := inventory.Namespaces[1].KVCounts
	expected := []KVCount{{Mount: "kv/", KVVersion: 2, Secrets: 3, Folders: 0, Complete: true}}
	if len(teamCounts) != 1 || teamCounts[0] != expected[0] {
		t.Errorf("expected %+v in team-a/, got %+v", expected, teamCounts)
	}
}
