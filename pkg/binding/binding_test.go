package binding

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 5869 Appendix A, Test Case 1 (SHA-256). Public standard test vector.
func TestHKDFRFC5869Vector(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got := hkdfSHA256(ikm, salt, info, 42)
	if !bytes.Equal(got, want) {
		t.Fatalf("HKDF mismatch:\n got %x\nwant %x", got, want)
	}
}

func TestReportDataDeterministicAndSessionScoped(t *testing.T) {
	cbA := []byte("session-A-channel-binding-32bytes!")
	cbB := []byte("session-B-channel-binding-32bytes!")
	if !bytes.Equal(ReportData(cbA, AttestContext), ReportData(cbA, AttestContext)) {
		t.Fatal("ReportData must be deterministic per session")
	}
	if bytes.Equal(ReportData(cbA, AttestContext), ReportData(cbB, AttestContext)) {
		t.Fatal("different sessions must derive different ReportData")
	}
	if bytes.Equal(ReportData(cbA, AttestContext), ReportData(cbA, SecretProofLabel)) {
		t.Fatal("different contexts must be domain-separated")
	}
}

func TestCheck(t *testing.T) {
	cb := []byte("session-A-channel-binding-32bytes!")
	want := ReportData(cb, AttestContext)
	if !Check(cb, AttestContext, want) {
		t.Fatal("Check must accept the correct ReportData")
	}
	other := ReportData([]byte("session-B-channel-binding-32bytes!"), AttestContext)
	if Check(cb, AttestContext, other) {
		t.Fatal("Check must reject ReportData bound to another session (relay)")
	}
}

func TestProofDiffersPerSession(t *testing.T) {
	a := Proof([]byte("session-A-channel-binding-32bytes!"), SecretProofLabel)
	b := Proof([]byte("session-B-channel-binding-32bytes!"), SecretProofLabel)
	if bytes.Equal(a, b) {
		t.Fatal("proofs must differ across sessions")
	}
}
