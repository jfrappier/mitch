package encryption

import (
	"bytes"
	"errors"
	"testing"
)

// fastParams keeps tests quick. Production uses NewKDFParams.
func fastParams(t *testing.T) KDFParams {
	t.Helper()
	params, err := NewKDFParams()
	if err != nil {
		t.Fatalf("NewKDFParams failed: %v", err)
	}
	params.Time = 1
	params.MemoryKiB = 1024
	params.Threads = 1
	return params
}

func TestDefaultKDFParamsMatchRFC9106SecondOption(t *testing.T) {
	params, err := NewKDFParams()
	if err != nil {
		t.Fatalf("NewKDFParams failed: %v", err)
	}
	if params.Time != 3 || params.MemoryKiB != 64*1024 || params.Threads != 4 {
		t.Errorf("expected time=3 memory=65536 threads=4, got %+v", params)
	}
	if len(params.Salt) != saltSize {
		t.Errorf("expected a %d-byte salt, got %d", saltSize, len(params.Salt))
	}

	other, _ := NewKDFParams()
	if bytes.Equal(params.Salt, other.Salt) {
		t.Error("two databases must not share a salt")
	}
}

func TestWrapAndUnwrapDataKey(t *testing.T) {
	dataKey, err := NewDataKey()
	if err != nil {
		t.Fatalf("NewDataKey failed: %v", err)
	}
	passphrase := []byte("correct horse battery staple")

	wrapped, err := WrapDataKey(passphrase, dataKey, fastParams(t))
	if err != nil {
		t.Fatalf("WrapDataKey failed: %v", err)
	}
	if bytes.Contains(wrapped.Ciphertext, dataKey) {
		t.Fatal("the wrapped key contains the data key in the clear")
	}

	unwrapped, err := UnwrapDataKey(passphrase, wrapped)
	if err != nil {
		t.Fatalf("UnwrapDataKey failed: %v", err)
	}
	if !bytes.Equal(unwrapped, dataKey) {
		t.Error("the unwrapped key does not match the original")
	}
}

func TestWrongPassphraseIsRejected(t *testing.T) {
	dataKey, _ := NewDataKey()
	wrapped, err := WrapDataKey([]byte("correct horse battery staple"), dataKey, fastParams(t))
	if err != nil {
		t.Fatalf("WrapDataKey failed: %v", err)
	}

	_, err = UnwrapDataKey([]byte("correct horse battery stapler"), wrapped)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestIncompleteKDFParamsAreRejected(t *testing.T) {
	_, err := UnwrapDataKey([]byte("correct horse battery staple"), WrappedKey{})
	if err == nil {
		t.Fatal("expected an error for empty passphrase settings")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, _ := NewDataKey()
	plaintext := []byte(`{"vault_address":"https://vault.example.com"}`)

	sealed, err := Encrypt(key, plaintext, []byte("scan:abc"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if bytes.Contains(sealed, []byte("vault.example.com")) {
		t.Fatal("the ciphertext contains the plaintext")
	}

	opened, err := Decrypt(key, sealed, []byte("scan:abc"))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("expected %q, got %q", plaintext, opened)
	}
}

func TestEncryptUsesAFreshNonceEachTime(t *testing.T) {
	key, _ := NewDataKey()
	first, _ := Encrypt(key, []byte("same"), nil)
	second, _ := Encrypt(key, []byte("same"), nil)
	if bytes.Equal(first, second) {
		t.Error("encrypting the same plaintext twice must give different ciphertexts")
	}
}

func TestDecryptRejectsTamperingAndSwaps(t *testing.T) {
	key, _ := NewDataKey()
	sealed, _ := Encrypt(key, []byte("inventory"), []byte("scan:abc"))

	// A row moved to another id must not decrypt.
	_, err := Decrypt(key, sealed, []byte("scan:xyz"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("wrong associated data: expected ErrWrongPassphrase, got %v", err)
	}

	// One flipped bit must not decrypt.
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 0x01
	_, err = Decrypt(key, tampered, []byte("scan:abc"))
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("tampered data: expected ErrWrongPassphrase, got %v", err)
	}

	// Truncated data gets a clear error, not a panic.
	_, err = Decrypt(key, sealed[:5], []byte("scan:abc"))
	if err == nil {
		t.Error("truncated data: expected an error")
	}
}

func TestWrongKeySizeIsRejected(t *testing.T) {
	_, err := Encrypt([]byte("short"), []byte("x"), nil)
	if err == nil {
		t.Error("expected an error for a 5-byte key")
	}
	_, err = WrapDataKey([]byte("correct horse battery staple"), []byte("short"), fastParams(t))
	if err == nil {
		t.Error("expected an error for a 5-byte data key")
	}
}

func TestCheckPassphrase(t *testing.T) {
	if CheckPassphrase([]byte("short")) == nil {
		t.Error("a 5-character passphrase must be rejected")
	}
	if CheckPassphrase([]byte("ééééééééééé")) == nil {
		t.Error("11 characters must be rejected even though it is 22 bytes")
	}
	if err := CheckPassphrase([]byte("twelve chars")); err != nil {
		t.Errorf("a 12-character passphrase must be accepted, got %v", err)
	}
}
