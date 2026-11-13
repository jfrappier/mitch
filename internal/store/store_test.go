package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfrappier/mitch/internal/encryption"
)

const testPassphrase = "correct horse battery staple"

// fastParams keeps tests quick. Production uses encryption.NewKDFParams.
func fastParams(t *testing.T) encryption.KDFParams {
	t.Helper()
	params, err := encryption.NewKDFParams()
	if err != nil {
		t.Fatalf("NewKDFParams failed: %v", err)
	}
	params.Time = 1
	params.MemoryKiB = 1024
	params.Threads = 1
	return params
}

// newTestStore creates a database in a temporary directory.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mitch.db")
	store, err := Create(context.Background(), path, []byte(testPassphrase), fastParams(t))
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func TestCreateMakesOwnerOnlyFile(t *testing.T) {
	_, path := newTestStore(t)
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix permission bits")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected mode 0600, got %04o", info.Mode().Perm())
	}

	problem, err := PermissionProblem(path)
	if err != nil || problem != "" {
		t.Errorf("expected no permission problem, got %q (error %v)", problem, err)
	}
}

func TestPermissionProblemDetectsGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not use Unix permission bits")
	}
	_, path := newTestStore(t)
	err := os.Chmod(path, 0o640)
	if err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	problem, err := PermissionProblem(path)
	if err != nil {
		t.Fatalf("PermissionProblem failed: %v", err)
	}
	if !strings.Contains(problem, "0640") || !strings.Contains(problem, "chmod 600") {
		t.Errorf("expected the mode and the fix in the message, got %q", problem)
	}
}

func TestCreateRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "important.txt")
	err := os.WriteFile(path, []byte("do not lose me"), 0o600)
	if err != nil {
		t.Fatalf("writing the test file failed: %v", err)
	}

	_, err = Create(context.Background(), path, []byte(testPassphrase), fastParams(t))
	if err == nil || !strings.Contains(err.Error(), "will not overwrite") {
		t.Fatalf("expected a refusal to overwrite, got %v", err)
	}

	content, _ := os.ReadFile(path)
	if string(content) != "do not lose me" {
		t.Error("the existing file was changed")
	}
}

func TestCreateRejectsShortPassphraseAndLeavesNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mitch.db")
	_, err := Create(context.Background(), path, []byte("short"), fastParams(t))
	if err == nil {
		t.Fatal("expected a short passphrase to be rejected")
	}
	_, statErr := os.Stat(path)
	if !errors.Is(statErr, os.ErrNotExist) {
		t.Error("a rejected Create must not leave a file behind")
	}
}

func TestSaveListLoadRoundTrip(t *testing.T) {
	store, path := newTestStore(t)
	ctx := context.Background()

	older := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

	firstID, err := store.SaveScan(ctx, older, older.Add(time.Minute), []byte(`{"scan":"first"}`))
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	secondID, err := store.SaveScan(ctx, newer, newer.Add(time.Minute), []byte(`{"scan":"second"}`))
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	if firstID == secondID || len(firstID) != 16 {
		t.Errorf("expected two distinct 16-character ids, got %q and %q", firstID, secondID)
	}

	summaries, err := store.ListScans(ctx)
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(summaries) != 2 || summaries[0].ID != secondID || summaries[1].ID != firstID {
		t.Fatalf("expected newest first, got %+v", summaries)
	}
	if !summaries[1].StartedAt.Equal(older) {
		t.Errorf("expected started_at %v, got %v", older, summaries[1].StartedAt)
	}

	// Close and reopen with the passphrase, as a later run would.
	err = store.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	reopened, err := Open(ctx, path, []byte(testPassphrase))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer reopened.Close()

	loaded, err := reopened.LoadScan(ctx, firstID)
	if err != nil {
		t.Fatalf("LoadScan failed: %v", err)
	}
	if string(loaded) != `{"scan":"first"}` {
		t.Errorf("expected the first inventory, got %s", loaded)
	}
}

func TestInventoryIsNotStoredInTheClear(t *testing.T) {
	store, path := newTestStore(t)
	_, err := store.SaveScan(context.Background(), time.Now(), time.Now(), []byte(`{"vault_address":"https://vault.secret-corp.example"}`))
	if err != nil {
		t.Fatalf("SaveScan failed: %v", err)
	}
	err = store.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the database file failed: %v", err)
	}
	if bytes.Contains(raw, []byte("secret-corp")) {
		t.Error("the Vault address appears in the database file in the clear")
	}
}

func TestOpenWithWrongPassphraseFails(t *testing.T) {
	store, path := newTestStore(t)
	_ = store.Close()

	_, err := Open(context.Background(), path, []byte("not the right passphrase"))
	if !errors.Is(err, encryption.ErrWrongPassphrase) {
		t.Errorf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestOpenMissingFileSaysRunInit(t *testing.T) {
	_, err := Open(context.Background(), filepath.Join(t.TempDir(), "missing.db"), []byte(testPassphrase))
	if err == nil || !strings.Contains(err.Error(), "mitch init") {
		t.Errorf("expected advice to run mitch init, got %v", err)
	}
}

func TestOpenNonMitchFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "other.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE something (x TEXT)`)
	if err != nil {
		t.Fatalf("creating a table failed: %v", err)
	}
	_ = db.Close()

	_, err = Open(context.Background(), path, []byte(testPassphrase))
	if err == nil || !strings.Contains(err.Error(), "not a Mitch database") {
		t.Errorf("expected 'not a Mitch database', got %v", err)
	}
}

func TestLoadUnknownScan(t *testing.T) {
	store, _ := newTestStore(t)
	_, err := store.LoadScan(context.Background(), "0000000000000000")
	if !errors.Is(err, ErrScanNotFound) || !strings.Contains(err.Error(), "mitch history") {
		t.Errorf("expected ErrScanNotFound with advice, got %v", err)
	}
}

func TestSwappedBlobsDoNotDecrypt(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	firstID, _ := store.SaveScan(ctx, time.Now(), time.Now(), []byte(`{"scan":"first"}`))
	secondID, _ := store.SaveScan(ctx, time.Now(), time.Now(), []byte(`{"scan":"second"}`))

	// Copy the first scan's blob onto the second row, as an attacker might.
	_, err := store.db.Exec(`UPDATE scans SET inventory = (SELECT inventory FROM scans WHERE id = ?) WHERE id = ?`, firstID, secondID)
	if err != nil {
		t.Fatalf("swapping blobs failed: %v", err)
	}

	_, err = store.LoadScan(ctx, secondID)
	if !errors.Is(err, encryption.ErrWrongPassphrase) {
		t.Errorf("a moved blob must fail to decrypt, got %v", err)
	}
}
