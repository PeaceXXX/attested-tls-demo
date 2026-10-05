// Package quote implements a mock TEE quote: signed attestation claims.
//
// A real quote (Intel SGX/TDX) is signed by the platform quoting enclave and
// carries measurements (MRENCLAVE/MRSIGNER), TCB patch level, and a
// caller-chosen REPORT_DATA field. Here HMAC-SHA256 stands in for the
// quoting-enclave signature: the point of this demo is what the *verifier*
// does with the claims (policy appraisal + channel binding), not the
// signature primitive itself.
package quote

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Claims is the attested statement about the workload.
type Claims struct {
	Issuer     string `json:"issuer"`      // e.g. "mock-qe/v1"
	MRenclave  string `json:"mrenclave"`   // hex measurement of the workload
	MRSIGNER   string `json:"mrsigner"`    // hex signer identity
	TCBLevel   int    `json:"tcb_level"`   // platform patch level (higher = newer)
	ReportData string `json:"report_data"` // hex; bound to the TLS session (see pkg/binding)
	Nonce      string `json:"nonce"`       // freshness, hex
	IssuedAt   int64  `json:"issued_at"`   // unix seconds
}

// Quote is signed claims.
type Quote struct {
	Claims    Claims `json:"claims"`
	Signature string `json:"signature"` // hex HMAC-SHA256 over canonical claims
}

func canonical(c Claims) []byte {
	// encoding/json marshals struct fields in declaration order, so this is
	// deterministic for a fixed Claims definition.
	b, err := json.Marshal(c)
	if err != nil {
		panic("quote: claims must always marshal: " + err.Error())
	}
	return b
}

// Sign produces a quote over claims.
func Sign(key []byte, c Claims) Quote {
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical(c))
	return Quote{Claims: c, Signature: hex.EncodeToString(mac.Sum(nil))}
}

var (
	ErrBadSignature = errors.New("quote: signature verification failed")
	ErrMalformed    = errors.New("quote: malformed quote")
)

// Verify checks the quote's signature and basic well-formedness.
func (q Quote) Verify(key []byte) error {
	if q.Claims.Issuer == "" || q.Claims.MRenclave == "" || q.Signature == "" {
		return ErrMalformed
	}
	sig, err := hex.DecodeString(q.Signature)
	if err != nil || len(sig) != sha256.Size {
		return ErrMalformed
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical(q.Claims))
	if subtle.ConstantTimeCompare(mac.Sum(nil), sig) != 1 {
		return ErrBadSignature
	}
	return nil
}

// Age returns how long ago the quote was issued.
func (q Quote) Age() time.Duration {
	return time.Since(time.Unix(q.Claims.IssuedAt, 0))
}
