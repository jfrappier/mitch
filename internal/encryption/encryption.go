// Package encryption protects stored scans with a passphrase.
//
// It uses envelope encryption:
//
//  1. Each database has one random 256-bit data key. Every stored scan is
//     encrypted with it using AES-256-GCM.
//  2. The data key itself is encrypted ("wrapped") with a key derived from
//     the user's passphrase using Argon2id.
//
// So the passphrase never encrypts data directly, and changing the passphrase
// only means re-wrapping the data key, not re-encrypting every scan.
//
// Docs:
//
//	Argon2id: https://pkg.go.dev/golang.org/x/crypto/argon2
//	AES-GCM:  https://pkg.go.dev/crypto/cipher#NewGCM
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KeySize is the size of the data key and the passphrase-derived key, in
// bytes. 32 bytes selects AES-256.
const KeySize = 32

// saltSize is the size of the random Argon2id salt, in bytes.
const saltSize = 16

// MinimumPassphraseLength is the shortest passphrase Mitch accepts, in characters.
const MinimumPassphraseLength = 12

// ErrWrongPassphrase means decryption failed authentication. With AES-GCM
// this happens when the key is wrong or the data was changed, and the two
// cannot be told apart.
var ErrWrongPassphrase = errors.New("decryption failed: the passphrase is wrong, or the data was changed or damaged")

// KDFParams are the Argon2id settings used to turn a passphrase into a key.
// They are stored next to the wrapped data key, so the settings can be raised
// later without breaking older databases.
type KDFParams struct {
	// Time is the number of passes over memory.
	Time uint32 `json:"time"`

	// MemoryKiB is the memory used, in KiB.
	MemoryKiB uint32 `json:"memory_kib"`

	// Threads is the degree of parallelism.
	Threads uint8 `json:"threads"`

	// Salt is random, and unique to each database.
	Salt []byte `json:"salt"`
}

// NewKDFParams returns the default Argon2id settings with a fresh random salt.
//
// The settings are RFC 9106's second recommended option (time 3, 64 MiB,
// 4 threads), meant for machines that can't spare 2 GiB, such as CI runners
// and small containers. They are quoted in the x/crypto/argon2 docs:
// https://pkg.go.dev/golang.org/x/crypto/argon2
func NewKDFParams() (KDFParams, error) {
	salt, err := randomBytes(saltSize)
	if err != nil {
		return KDFParams{}, fmt.Errorf("creating the passphrase salt failed: %w", err)
	}

	params := KDFParams{
		Time:      3,
		MemoryKiB: 64 * 1024,
		Threads:   4,
		Salt:      salt,
	}
	return params, nil
}

// WrappedKey is the data key, encrypted with the passphrase-derived key.
// It is safe to store: without the passphrase it cannot be unwrapped.
type WrappedKey struct {
	KDF        KDFParams `json:"kdf"`
	Ciphertext []byte    `json:"ciphertext"`
}

// wrappedKeyLabel is bound to the wrapped key as AES-GCM associated data, so
// a wrapped key can't be mistaken for, or swapped with, any other ciphertext.
var wrappedKeyLabel = []byte("mitch data key v1")

// CheckPassphrase rejects passphrases that are too short to resist guessing.
func CheckPassphrase(passphrase []byte) error {
	length := len([]rune(string(passphrase)))
	if length < MinimumPassphraseLength {
		return fmt.Errorf("the passphrase is %d characters; use at least %d", length, MinimumPassphraseLength)
	}
	return nil
}

// NewDataKey returns a fresh random data key.
func NewDataKey() ([]byte, error) {
	key, err := randomBytes(KeySize)
	if err != nil {
		return nil, fmt.Errorf("creating the data key failed: %w", err)
	}
	return key, nil
}

// WrapDataKey encrypts the data key with a key derived from the passphrase.
func WrapDataKey(passphrase []byte, dataKey []byte, params KDFParams) (WrappedKey, error) {
	if len(dataKey) != KeySize {
		return WrappedKey{}, fmt.Errorf("the data key is %d bytes; expected %d", len(dataKey), KeySize)
	}

	passphraseKey := deriveKey(passphrase, params)
	ciphertext, err := Encrypt(passphraseKey, dataKey, wrappedKeyLabel)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("wrapping the data key failed: %w", err)
	}

	wrapped := WrappedKey{KDF: params, Ciphertext: ciphertext}
	return wrapped, nil
}

// UnwrapDataKey decrypts the data key with the passphrase. It returns
// ErrWrongPassphrase when the passphrase does not match.
func UnwrapDataKey(passphrase []byte, wrapped WrappedKey) ([]byte, error) {
	if wrapped.KDF.Time == 0 || wrapped.KDF.MemoryKiB == 0 || wrapped.KDF.Threads == 0 || len(wrapped.KDF.Salt) == 0 {
		return nil, fmt.Errorf("the stored passphrase settings are incomplete: %+v", wrapped.KDF)
	}

	passphraseKey := deriveKey(passphrase, wrapped.KDF)
	dataKey, err := Decrypt(passphraseKey, wrapped.Ciphertext, wrappedKeyLabel)
	if err != nil {
		return nil, err
	}
	if len(dataKey) != KeySize {
		return nil, fmt.Errorf("the unwrapped data key is %d bytes; expected %d", len(dataKey), KeySize)
	}
	return dataKey, nil
}

// Encrypt seals plaintext with AES-256-GCM under key.
//
// associatedData is not encrypted but is authenticated: Decrypt fails unless
// it is given exactly the same bytes. Mitch uses it to tie each ciphertext to
// the row it belongs to, so rows can't be swapped.
//
// The result is a random 12-byte nonce followed by the ciphertext and tag.
// A random nonce is safe here: the risk of a repeat stays negligible far
// beyond the number of scans one database will ever hold.
func Encrypt(key []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("creating a nonce failed: %w", err)
	}

	// Seal appends the ciphertext to its first argument, so the result is
	// nonce followed by ciphertext.
	sealed := aead.Seal(nonce, nonce, plaintext, associatedData)
	return sealed, nil
}

// Decrypt opens data sealed by Encrypt. It returns ErrWrongPassphrase when
// the key or associated data don't match, or the data was changed.
func Decrypt(key []byte, sealed []byte, associatedData []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(sealed) < nonceSize+aead.Overhead() {
		return nil, fmt.Errorf("the encrypted data is %d bytes, too short to be valid; it is damaged", len(sealed))
	}

	nonce := sealed[:nonceSize]
	ciphertext := sealed[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plaintext, nil
}

// deriveKey turns a passphrase into a 256-bit key with Argon2id.
func deriveKey(passphrase []byte, params KDFParams) []byte {
	return argon2.IDKey(passphrase, params.Salt, params.Time, params.MemoryKiB, params.Threads, KeySize)
}

// newAEAD builds an AES-256-GCM cipher from a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("the encryption key is %d bytes; expected %d", len(key), KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating the AES cipher failed: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM failed: %w", err)
	}
	return aead, nil
}

// randomBytes returns n bytes from the operating system's secure random source.
func randomBytes(n int) ([]byte, error) {
	buffer := make([]byte, n)
	_, err := rand.Read(buffer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}
