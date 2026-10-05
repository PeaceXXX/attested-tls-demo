// Package demo holds demo-only constants. Nothing here is a real secret and
// nothing here models real key management: the QE key is compiled into both
// the attester and the verifier purely so the demo runs without a PKI.
package demo

// QEKey stands in for the quoting-enclave signing key. DEMO ONLY.
var QEKey = []byte("attested-tls-demo-qe-key-0000000") // 32 bytes
