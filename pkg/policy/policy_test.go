package policy

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/pkg/quote"
)

var qeKey = []byte("test-only-quoting-key-32bytes!!!!")

func goodQuote() quote.Quote {
	return quote.Sign(qeKey, quote.Claims{
		Issuer:     "mock-qe/v1",
		MRenclave:  strings.Repeat("ab", 32),
		MRSIGNER:   strings.Repeat("cd", 32),
		TCBLevel:   7,
		ReportData: strings.Repeat("ef", 32),
		Nonce:      "0011223344556677",
		IssuedAt:   time.Now().Unix(),
	})
}

func testPolicy() Policy {
	rd, _ := hex.DecodeString(strings.Repeat("ef", 32))
	return Policy{
		AllowedMRenclave:   []string{strings.Repeat("ab", 32)},
		AllowedMRSIGNER:    []string{strings.Repeat("cd", 32)},
		MinTCBLevel:        5,
		MaxQuoteAge:        5 * time.Minute,
		ExpectedReportData: rd,
	}
}

func TestAppraiseAcceptsGoodQuote(t *testing.T) {
	if err := testPolicy().Appraise(goodQuote(), qeKey); err != nil {
		t.Fatalf("good quote rejected: %v", err)
	}
}

func TestAppraiseRejectsUnknownMeasurement(t *testing.T) {
	q := goodQuote()
	q.Claims.MRenclave = strings.Repeat("00", 32)
	// re-sign so the failure is the policy, not the signature
	q = quote.Sign(qeKey, q.Claims)
	if err := testPolicy().Appraise(q, qeKey); err != ErrMeasurement {
		t.Fatalf("expected ErrMeasurement, got %v", err)
	}
}

func TestAppraiseRejectsLowTCB(t *testing.T) {
	c := goodQuote().Claims
	c.TCBLevel = 3
	q := quote.Sign(qeKey, c)
	if err := testPolicy().Appraise(q, qeKey); err != ErrTCB {
		t.Fatalf("expected ErrTCB, got %v", err)
	}
}

func TestAppraiseRejectsStaleQuote(t *testing.T) {
	c := goodQuote().Claims
	c.IssuedAt = time.Now().Add(-time.Hour).Unix()
	q := quote.Sign(qeKey, c)
	if err := testPolicy().Appraise(q, qeKey); err != ErrStale {
		t.Fatalf("expected ErrStale, got %v", err)
	}
}

func TestAppraiseRejectsUnboundReportData(t *testing.T) {
	// Genuine quote, valid signature, but REPORT_DATA belongs to another
	// session: this is exactly what a relay attacker replays.
	c := goodQuote().Claims
	c.ReportData = strings.Repeat("00", 32)
	q := quote.Sign(qeKey, c)
	if err := testPolicy().Appraise(q, qeKey); err != ErrBinding {
		t.Fatalf("expected ErrBinding, got %v", err)
	}
}

func TestAppraiseNaivePolicySkipsBinding(t *testing.T) {
	// A policy without ExpectedReportData cannot see the relay. This is the
	// vulnerable configuration the --naive client demonstrates.
	p := testPolicy()
	p.ExpectedReportData = nil
	c := goodQuote().Claims
	c.ReportData = strings.Repeat("00", 32)
	q := quote.Sign(qeKey, c)
	if err := p.Appraise(q, qeKey); err != nil {
		t.Fatalf("naive policy should accept (that is the bug): %v", err)
	}
}
