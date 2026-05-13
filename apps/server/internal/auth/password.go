// Package auth gathers password hashing, JWT signing/verification, and
// HTTP middleware around them. The split mirrors apps/server/src/shared
// from the legacy backend.
package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns the bcrypt hash of plain. Cost is the bcrypt
// work factor — pass the value from config (12 is the OWASP minimum
// for 2024+).
//
// bcrypt has a hard 72-byte input limit; longer passwords get truncated
// silently by every bcrypt implementation. We reject them up-front so
// the user knows.
func HashPassword(plain string, cost int) (string, error) {
	if len(plain) > 72 {
		return "", errors.New("password longer than 72 bytes is not supported by bcrypt")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword returns true when plain matches the stored bcrypt hash.
// Constant-time comparison is handled inside bcrypt.CompareHashAndPassword.
func VerifyPassword(plain, hash string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
