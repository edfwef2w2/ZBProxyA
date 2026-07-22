// Package authsecret provides a lightweight pre-shared key handshake
// that runs as the first bytes on a TCP stream (before PROXY protocol
// and application data). Designed for low-memory environments (e.g. 256 MiB).
package authsecret

import (
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"time"
)

// MaxLen is the maximum accepted secret length in bytes.
// Keeping this small bounds the per-connection scratch buffer and
// avoids large allocations on constrained hosts.
const MaxLen = 128

// DefaultTimeout is how long inbound auth reads may block.
// A short timeout prevents hung connections from exhausting
// goroutines and file descriptors under 256 MiB hosts.
const DefaultTimeout = 5 * time.Second

var (
	ErrEmpty       = errors.New("auth secret is empty")
	ErrTooLong     = errors.New("auth secret exceeds maximum length")
	ErrMismatch    = errors.New("auth secret mismatch")
	ErrShortRead   = errors.New("auth secret short read")
	ErrWriteFailed = errors.New("auth secret write failed")
)

// Normalize validates and returns the secret as a reusable []byte.
// Call once at inject/reload time; reuse the result per connection
// so we never convert string→[]byte on the hot path.
func Normalize(secret string) ([]byte, error) {
	if secret == "" {
		return nil, nil
	}
	if len(secret) > MaxLen {
		return nil, ErrTooLong
	}
	// Copy so callers can hold the bytes without retaining the config string header.
	out := make([]byte, len(secret))
	copy(out, secret)
	return out, nil
}

// Write sends the secret as the first payload on an established connection.
// secret must already be Normalize'd (non-nil, len ≤ MaxLen).
func Write(conn net.Conn, secret []byte) error {
	if len(secret) == 0 {
		return nil
	}
	n, err := conn.Write(secret)
	if err != nil {
		return err
	}
	if n != len(secret) {
		return ErrWriteFailed
	}
	return nil
}

// Verify reads exactly len(secret) bytes from conn and constant-time compares.
// Uses a stack-friendly fixed buffer capped at MaxLen — no heap growth per call
// beyond the tiny scratch slice allocated here (≤ MaxLen bytes).
// deadline is applied only for the auth read and is cleared afterwards.
func Verify(conn net.Conn, secret []byte, timeout time.Duration) error {
	if len(secret) == 0 {
		return ErrEmpty
	}
	if len(secret) > MaxLen {
		return ErrTooLong
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	// Fixed-size stack buffer; only use the prefix we need.
	var buf [MaxLen]byte
	n, err := io.ReadFull(conn, buf[:len(secret)])
	// Always clear deadline so the rest of the connection is not constrained.
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return ErrShortRead
		}
		return err
	}
	if n != len(secret) {
		return ErrShortRead
	}
	if subtle.ConstantTimeCompare(buf[:len(secret)], secret) != 1 {
		return ErrMismatch
	}
	return nil
}
