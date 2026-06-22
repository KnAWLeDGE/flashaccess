package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	keyEntropyBytes = 32 // 256-bit session keys
	argonTime       = 3
	argonMemory     = 64 * 1024 // 64 MiB
	argonThreads    = 4
	argonKeyLen     = 32
	argonSaltLen    = 16
)

// GenerateKey returns a new high-entropy session key, base64url-encoded.
// This is the ONLY moment the raw key exists server-side; it is shown once
// to the operator and never persisted.
func GenerateKey() (string, error) {
	b := make([]byte, keyEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashKey derives an Argon2id PHC-formatted hash string for storage.
func HashKey(key string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	hash := argon2.IDKey([]byte(key), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyKey checks a candidate key against a stored PHC hash in constant time.
func VerifyKey(candidate, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}

	var mem, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &threads); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	got := argon2.IDKey([]byte(candidate), salt, t, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}