// Package policy appraises attestation evidence against a trust policy:
// is this the expected workload, on a new enough platform, with evidence
// bound to *my* session? The last question is what stops relay attacks.
package policy

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/pkg/quote"
)

// Policy is the verifier's trust policy.
type Policy struct {
	AllowedMRenclave []string
	AllowedMRSIGNER  []string
	MinTCBLevel      int
	MaxQuoteAge      time.Duration
	// ExpectedReportData, when non-nil, requires the quote's REPORT_DATA to
	// match the value derived from the verifier's own TLS session. Leave nil
	// only if you enjoy being relayed (see the --naive client mode).
	ExpectedReportData []byte
}

var (
	ErrMeasurement = errors.New("policy: workload measurement not allow-listed")
	ErrSigner      = errors.New("policy: signer identity not allow-listed")
	ErrTCB         = errors.New("policy: platform TCB level below minimum")
	ErrStale       = errors.New("policy: quote too old or from the future")
	ErrBinding     = errors.New("policy: REPORT_DATA not bound to this session (possible relay)")
)

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Appraise verifies the quote signature and evaluates every policy rule.
func (p Policy) Appraise(q quote.Quote, qeKey []byte) error {
	if err := q.Verify(qeKey); err != nil {
		return err
	}
	if len(p.AllowedMRenclave) > 0 && !contains(p.AllowedMRenclave, q.Claims.MRenclave) {
		return ErrMeasurement
	}
	if len(p.AllowedMRSIGNER) > 0 && !contains(p.AllowedMRSIGNER, q.Claims.MRSIGNER) {
		return ErrSigner
	}
	if q.Claims.TCBLevel < p.MinTCBLevel {
		return ErrTCB
	}
	age := q.Age()
	if age > p.MaxQuoteAge || age < -5*time.Minute {
		return ErrStale
	}
	if p.ExpectedReportData != nil {
		got, err := hex.DecodeString(q.Claims.ReportData)
		if err != nil || !equalConst(got, p.ExpectedReportData) {
			return ErrBinding
		}
	}
	return nil
}

func equalConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
