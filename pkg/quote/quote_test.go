package quote

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("test-only-quoting-key-32bytes!!!!")

func testClaims() Claims {
	return Claims{
		Issuer:     "mock-qe/v1",
		MRenclave:  strings.Repeat("ab", 32),
		MRSIGNER:   strings.Repeat("cd", 32),
		TCBLevel:   7,
		ReportData: strings.Repeat("ef", 32),
		Nonce:      "0011223344556677",
		IssuedAt:   time.Now().Unix(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	q := Sign(testKey, testClaims())
	if err := q.Verify(testKey); err != nil {
		t.Fatalf("valid quote rejected: %v", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	q := Sign(testKey, testClaims())
	if err := q.Verify([]byte("wrong-key-00000000000000000000000")); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyRejectsTamperedClaims(t *testing.T) {
	q := Sign(testKey, testClaims())
	q.Claims.TCBLevel = 999 // attacker inflates patch level
	if err := q.Verify(testKey); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature for tampered claims, got %v", err)
	}
}

func TestVerifyRejectsSwappedReportData(t *testing.T) {
	// The relay-attack primitive: attacker replays a *genuine* quote but the
	// ReportData belongs to a different session. Signature still verifies;
	// it is the binding check (pkg/policy) that must catch this.
	q1 := Sign(testKey, testClaims())
	c2 := testClaims()
	c2.ReportData = strings.Repeat("00", 32)
	q2 := Sign(testKey, c2)
	if err := q1.Verify(testKey); err != nil {
		t.Fatalf("q1 should verify: %v", err)
	}
	if err := q2.Verify(testKey); err != nil {
		t.Fatalf("q2 should verify: %v", err)
	}
	if q1.Signature == q2.Signature {
		t.Fatal("different ReportData must produce different signatures")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	var q Quote
	if err := q.Verify(testKey); err != ErrMalformed {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
	q = Sign(testKey, testClaims())
	q.Signature = "zzzz"
	if err := q.Verify(testKey); err != ErrMalformed {
		t.Fatalf("expected ErrMalformed for bad hex, got %v", err)
	}
}
