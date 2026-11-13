// Package store saves scans in a local SQLite file, encrypted with the
// user's passphrase.
//
// Layout of the file:
//
//	settings  name/value pairs: the schema version, when the file was
//	          created, and the wrapped data key (see package encryption).
//	scans     one row per scan: an id, timestamps, and the inventory as one
//	          AES-GCM encrypted blob.
//
// Only ids and timestamps are stored in the clear. Everything Mitch learned
// from Vault, including the Vault address, is inside the encrypted blob.
//
// The SQLite driver is modernc.org/sqlite, which is pure Go (no cgo):
// https://pkg.go.dev/modernc.org/sqlite
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"time"

	// Registers the "sqlite" driver with database/sql.
	_ "modernc.org/sqlite"

	"github.com/jfrappier/mitch/internal/encryption"
)

// FileMode is the permission Mitch creates the database file with: readable
// and writable by its owner only.
const FileMode fs.FileMode = 0o600

// schemaVersion is bumped whenever the table layout changes.
const schemaVersion = "1"

// Names of rows in the settings table.
const (
	settingSchemaVersion = "schema_version"
	settingCreatedAt     = "created_at"
	settingWrappedKey    = "wrapped_data_key"
)

// ErrScanNotFound means no scan has the requested id.
var ErrScanNotFound = errors.New("no saved scan has that id")

// Store is an open, unlocked database.
type Store struct {
	path    string
	db      *sql.DB
	dataKey []byte
}

// ScanSummary is the unencrypted part of a saved scan.
type ScanSummary struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	SavedAt    time.Time `json:"saved_at"`
}

// Create makes a new database at path, protected by passphrase.
//
// It refuses to overwrite an existing file, so a typo can't destroy scan
// history. kdfParams are normally encryption.NewKDFParams(); tests pass
// cheaper settings.
func Create(ctx context.Context, path string, passphrase []byte, kdfParams encryption.KDFParams) (*Store, error) {
	err := encryption.CheckPassphrase(passphrase)
	if err != nil {
		return nil, err
	}

	// Create the file ourselves first, so it never exists with looser
	// permissions, and so an existing file is never touched.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, FileMode) //nolint:gosec // path is the user's --db flag
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("a file already exists at %s; Mitch will not overwrite it. Use --db to choose another path", path)
		}
		return nil, fmt.Errorf("creating the database file %s failed: %w", path, err)
	}
	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("creating the database file %s failed: %w", path, err)
	}

	store, err := createTables(ctx, path, passphrase, kdfParams)
	if err != nil {
		// Leave nothing half-made behind. The file is ours: we just created it.
		removeErr := os.Remove(path)
		if removeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("removing the incomplete file %s also failed: %w", path, removeErr))
		}
		return nil, err
	}
	return store, nil
}

// createTables fills a new, empty database file.
func createTables(ctx context.Context, path string, passphrase []byte, kdfParams encryption.KDFParams) (*Store, error) {
	db, err := openSQLite(path)
	if err != nil {
		return nil, err
	}

	dataKey, err := encryption.NewDataKey()
	if err != nil {
		closeQuietly(db)
		return nil, err
	}
	wrappedKey, err := encryption.WrapDataKey(passphrase, dataKey, kdfParams)
	if err != nil {
		closeQuietly(db)
		return nil, err
	}
	wrappedKeyJSON, err := json.Marshal(wrappedKey)
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("encoding the wrapped data key failed: %w", err)
	}

	statements := []string{
		`CREATE TABLE settings (
			name  TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE scans (
			id          TEXT PRIMARY KEY,
			started_at  TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			saved_at    TEXT NOT NULL,
			inventory   BLOB NOT NULL
		)`,
	}

	transaction, err := db.BeginTx(ctx, nil)
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("starting a transaction in %s failed: %w", path, err)
	}

	for _, statement := range statements {
		_, err = transaction.ExecContext(ctx, statement)
		if err != nil {
			_ = transaction.Rollback()
			closeQuietly(db)
			return nil, fmt.Errorf("creating tables in %s failed: %w", path, err)
		}
	}

	settings := map[string]string{
		settingSchemaVersion: schemaVersion,
		settingCreatedAt:     formatTime(time.Now()),
		settingWrappedKey:    string(wrappedKeyJSON),
	}
	for name, value := range settings {
		_, err = transaction.ExecContext(ctx, `INSERT INTO settings (name, value) VALUES (?, ?)`, name, value)
		if err != nil {
			_ = transaction.Rollback()
			closeQuietly(db)
			return nil, fmt.Errorf("writing setting %q to %s failed: %w", name, path, err)
		}
	}

	err = transaction.Commit()
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("saving the new database %s failed: %w", path, err)
	}

	store := &Store{path: path, db: db, dataKey: dataKey}
	return store, nil
}

// Open opens an existing database and unlocks it with the passphrase.
// It returns encryption.ErrWrongPassphrase (wrapped) when the passphrase is wrong.
func Open(ctx context.Context, path string, passphrase []byte) (*Store, error) {
	_, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no Mitch database at %s; run \"mitch init\" to create one, or pass --db with the right path", path)
		}
		return nil, fmt.Errorf("checking the database file %s failed: %w", path, err)
	}

	db, err := openSQLite(path)
	if err != nil {
		return nil, err
	}

	settings, err := readSettings(ctx, db, path)
	if err != nil {
		closeQuietly(db)
		return nil, err
	}

	if settings[settingSchemaVersion] != schemaVersion {
		closeQuietly(db)
		return nil, fmt.Errorf("%s has schema version %q, but this Mitch reads version %q; use a matching Mitch version",
			path, settings[settingSchemaVersion], schemaVersion)
	}

	var wrappedKey encryption.WrappedKey
	err = json.Unmarshal([]byte(settings[settingWrappedKey]), &wrappedKey)
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("the wrapped data key in %s is damaged: %w", path, err)
	}

	dataKey, err := encryption.UnwrapDataKey(passphrase, wrappedKey)
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("unlocking %s failed: %w", path, err)
	}

	store := &Store{path: path, db: db, dataKey: dataKey}
	return store, nil
}

// readSettings loads the settings table. A file without one is not a Mitch database.
func readSettings(ctx context.Context, db *sql.DB, path string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("%s is not a Mitch database (reading its settings failed: %w)", path, err)
	}
	defer closeRows(rows)

	settings := make(map[string]string)
	for rows.Next() {
		var name string
		var value string
		err = rows.Scan(&name, &value)
		if err != nil {
			return nil, fmt.Errorf("reading settings from %s failed: %w", path, err)
		}
		settings[name] = value
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("reading settings from %s failed: %w", path, err)
	}
	return settings, nil
}

// Path returns the database file path.
func (s *Store) Path() string {
	return s.path
}

// Close closes the database and forgets the data key.
func (s *Store) Close() error {
	for index := range s.dataKey {
		s.dataKey[index] = 0
	}
	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("closing %s failed: %w", s.path, err)
	}
	return nil
}

// SaveScan encrypts an inventory and stores it. It returns the new scan's id.
func (s *Store) SaveScan(ctx context.Context, startedAt time.Time, finishedAt time.Time, inventoryJSON []byte) (string, error) {
	id, err := newScanID()
	if err != nil {
		return "", err
	}

	encrypted, err := encryption.Encrypt(s.dataKey, inventoryJSON, associatedDataFor(id))
	if err != nil {
		return "", fmt.Errorf("encrypting scan %s failed: %w", id, err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO scans (id, started_at, finished_at, saved_at, inventory) VALUES (?, ?, ?, ?, ?)`,
		id, formatTime(startedAt), formatTime(finishedAt), formatTime(time.Now()), encrypted)
	if err != nil {
		return "", fmt.Errorf("saving scan %s to %s failed: %w", id, s.path, err)
	}
	return id, nil
}

// ListScans returns every saved scan, newest first. It decrypts nothing.
func (s *Store) ListScans(ctx context.Context) ([]ScanSummary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, started_at, finished_at, saved_at FROM scans ORDER BY started_at DESC, id`)
	if err != nil {
		return nil, fmt.Errorf("listing scans in %s failed: %w", s.path, err)
	}
	defer closeRows(rows)

	summaries := []ScanSummary{}
	for rows.Next() {
		var id string
		var startedText string
		var finishedText string
		var savedText string
		err = rows.Scan(&id, &startedText, &finishedText, &savedText)
		if err != nil {
			return nil, fmt.Errorf("reading the scan list in %s failed: %w", s.path, err)
		}

		summary := ScanSummary{ID: id}
		summary.StartedAt, err = parseTime(startedText)
		if err != nil {
			return nil, fmt.Errorf("scan %s has a damaged started_at: %w", id, err)
		}
		summary.FinishedAt, err = parseTime(finishedText)
		if err != nil {
			return nil, fmt.Errorf("scan %s has a damaged finished_at: %w", id, err)
		}
		summary.SavedAt, err = parseTime(savedText)
		if err != nil {
			return nil, fmt.Errorf("scan %s has a damaged saved_at: %w", id, err)
		}
		summaries = append(summaries, summary)
	}
	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("listing scans in %s failed: %w", s.path, err)
	}
	return summaries, nil
}

// LoadScan decrypts and returns one saved inventory as JSON.
func (s *Store) LoadScan(ctx context.Context, id string) ([]byte, error) {
	var encrypted []byte
	err := s.db.QueryRowContext(ctx, `SELECT inventory FROM scans WHERE id = ?`, id).Scan(&encrypted)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("scan %q: %w; run \"mitch history\" to see saved scans", id, ErrScanNotFound)
		}
		return nil, fmt.Errorf("reading scan %s from %s failed: %w", id, s.path, err)
	}

	inventoryJSON, err := encryption.Decrypt(s.dataKey, encrypted, associatedDataFor(id))
	if err != nil {
		return nil, fmt.Errorf("decrypting scan %s failed: %w", id, err)
	}
	return inventoryJSON, nil
}

// PermissionProblem returns a description of the problem when the database
// file can be read by users other than its owner, and "" when it is fine.
// Windows does not use Unix permission bits, so it is not checked there.
func PermissionProblem(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("checking permissions on %s failed: %w", path, err)
	}

	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return fmt.Sprintf("%s has permissions %04o; other users on this machine can read it. Run: chmod 600 %s", path, mode, path), nil
	}
	return "", nil
}

// openSQLite opens the file with one connection. Mitch is a single process
// doing one thing at a time, so a pool would only add locking surprises.
func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening the database %s failed: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	// sql.Open does not touch the file; Ping does, so failures show up here.
	err = db.Ping()
	if err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("opening the database %s failed: %w", path, err)
	}
	return db, nil
}

// newScanID returns a random 16-character hex id.
func newScanID() (string, error) {
	buffer := make([]byte, 8)
	_, err := rand.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("creating a scan id failed: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// associatedDataFor ties an encrypted inventory to its scan id, so a blob
// copied onto another row fails to decrypt instead of showing the wrong scan.
func associatedDataFor(id string) []byte {
	return []byte("mitch scan " + id)
}

// timeLayout is RFC 3339 with a fixed nine-digit fraction. Unlike
// time.RFC3339Nano it never drops trailing zeros, so stored times always
// have the same length and sort correctly as text.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// formatTime stores times in UTC using timeLayout.
func formatTime(value time.Time) string {
	return value.UTC().Format(timeLayout)
}

// parseTime reads a time written by formatTime.
func parseTime(text string) (time.Time, error) {
	return time.Parse(timeLayout, text)
}

// closeRows closes a result set. A close failure after reading every row
// cannot lose data, so it is ignored on purpose; read errors are checked
// with rows.Err().
func closeRows(rows *sql.Rows) {
	_ = rows.Close()
}

// closeQuietly closes a database while another error is already being
// returned, so that error is the one the user sees.
func closeQuietly(db *sql.DB) {
	_ = db.Close()
}
