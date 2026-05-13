package auth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the JWT payload Palmr issues.
//
// Field shapes match the legacy backend (apps/server/src/shared/jwt-sign.ts)
// so cookies issued by either codebase remain interchangeable during the
// migration window.
type Claims struct {
	UserID  string `json:"userId"`
	IsAdmin bool   `json:"isAdmin"`
	JTI     string `json:"jti"`
	jwt.RegisteredClaims
}

type Signer struct {
	secret []byte
	ttl    time.Duration
}

func NewSigner(secret string, ttl time.Duration) *Signer {
	return &Signer{secret: []byte(secret), ttl: ttl}
}

// Sign issues a new HS256 token for the given user.
func (s *Signer) Sign(userID string, isAdmin bool) (string, error) {
	now := time.Now()
	c := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		JTI:     uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// Verify parses and validates a token. Returns ErrJTIRevoked if the jti
// is on the revocation list.
func (s *Signer) Verify(raw string) (*Claims, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if IsRevoked(c.JTI) {
		return nil, ErrJTIRevoked
	}
	return c, nil
}

// -----------------------------------------------------------------------------
// jti revocation list — in-memory, mirrors legacy jwt-revocation.ts
// -----------------------------------------------------------------------------

var (
	ErrJTIRevoked = errors.New("jti revoked")
	revokedMu     sync.RWMutex
	revoked       = map[string]time.Time{}
)

// RevokeJTI marks a token as no longer accepted. Used on logout. The
// timestamp lets a background sweep eventually drop expired entries
// (a token past its exp can never be replayed anyway).
func RevokeJTI(jti string) {
	revokedMu.Lock()
	revoked[jti] = time.Now()
	revokedMu.Unlock()
}

func IsRevoked(jti string) bool {
	if jti == "" {
		return false
	}
	revokedMu.RLock()
	_, ok := revoked[jti]
	revokedMu.RUnlock()
	return ok
}

// SweepRevoked drops entries older than ttl. Call it from a periodic
// goroutine in main; keeps memory bounded.
func SweepRevoked(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	revokedMu.Lock()
	for k, v := range revoked {
		if v.Before(cutoff) {
			delete(revoked, k)
		}
	}
	revokedMu.Unlock()
}
