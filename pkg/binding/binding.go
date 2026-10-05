// Package binding derives and checks the value sealed into
// Quote.ReportData, binding attestation evidence to the live TLS session.
//
// The classic attestation-composition flaw: a verifier checks a genuine quote
// but never ties it to *its own* connection, so a man-in-the-middle can relay
// someone else's good evidence. The fix used by attested-TLS designs is to
// seal a channel binding (RFC 5929 "tls-unique") into the quote's REPORT_DATA
// and have the verifier recompute it from its own session.
package binding

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
)

// Context labels keep derived values domain-separated.
var (
	// AttestContext labels the ReportData sealed into quotes served over a session.
	AttestContext = []byte("attested-tls-demo/attest/v1")
	// SecretProofLabel labels the client-to-server proof for secret release.
	SecretProofLabel = []byte("attested-tls-demo/secret-proof/v1")
)

// FromConnState extracts the RFC 5929 "tls-unique" channel binding from a
// live TLS connection. It is identical on both endpoints of the session.
func FromConnState(cs tls.ConnectionState) ([]byte, error) {
	if len(cs.TLSUnique) == 0 {
		return nil, errors.New("binding: tls-unique channel binding unavailable on this connection")
	}
	out := make([]byte, len(cs.TLSUnique))
	copy(out, cs.TLSUnique)
	return out, nil
}

// ReportData derives the 32-byte value the attester seals into the quote for
// the given session. Verifiers recompute it from their own channel binding.
func ReportData(channelBinding, context []byte) []byte {
	return hkdfSHA256(channelBinding, nil, context, 32)
}

// Check reports whether want equals the expected ReportData for this session
// (constant-time).
func Check(channelBinding, context, want []byte) bool {
	return subtle.ConstantTimeCompare(ReportData(channelBinding, context), want) == 1
}

// Proof derives a client-to-server proof that the client observed the same
// session the server sees. The server recomputes it from its own view of the
// channel binding before releasing secrets.
func Proof(channelBinding, label []byte) []byte {
	return hkdfSHA256(channelBinding, nil, label, 32)
}

// hkdfSHA256 is RFC 5869 HKDF with SHA-256, implemented on stdlib only.
func hkdfSHA256(ikm, salt, info []byte, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{i})
		prev = mac.Sum(nil)
		out = append(out, prev...)
		if i == 255 {
			break
		}
	}
	return out[:n]
}
