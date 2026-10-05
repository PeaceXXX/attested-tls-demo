// Package server is the attested workload: an HTTPS server that serves a
// mock TEE quote whose REPORT_DATA is bound to the caller's TLS session,
// and that releases a secret only to clients proving they observed the
// same session.
package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/internal/certs"
	"github.com/PeaceXXX/attested-tls-demo/internal/demo"
	"github.com/PeaceXXX/attested-tls-demo/pkg/binding"
	"github.com/PeaceXXX/attested-tls-demo/pkg/quote"
)

// Options configures the attested workload's identity.
type Options struct {
	MRenclave string
	MRSIGNER  string
	TCBLevel  int
	Secret    string
}

// Server is a running attested workload.
type Server struct {
	opts     Options
	caPEM    []byte
	mux      *http.Server
	mu       sync.Mutex
	received []string // payloads POSTed to /data (demo visibility)
	logf     func(string, ...any)
}

// New creates the server (PKI generated in-memory).
func New(opts Options, logf func(string, ...any)) (*Server, error) {
	if logf == nil {
		logf = log.Printf
	}
	caPEM, caCert, caKey, err := certs.GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	certPEM, keyPEM, err := certs.ServerCert(caCert, caKey, []string{"127.0.0.1", "localhost"})
	if err != nil {
		return nil, fmt.Errorf("generate server cert: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	s := &Server{opts: opts, caPEM: caPEM, logf: logf}
	mux := http.NewServeMux()
	mux.HandleFunc("/attest", s.handleAttest)
	mux.HandleFunc("/secret", s.handleSecret)
	mux.HandleFunc("/data", s.handleData)
	mux.HandleFunc("/received", s.handleReceived)
	s.mux = &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12, // tls-unique semantics are cleanest on 1.2
		},
	}
	return s, nil
}

// CAPEM returns the CA clients must trust.
func (s *Server) CAPEM() []byte { return s.caPEM }

// Start listens on addr ("127.0.0.1:0" for ephemeral) and returns the actual address.
func (s *Server) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	tlsLn := tls.NewListener(ln, s.mux.TLSConfig)
	go func() {
		if err := s.mux.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			s.logf("server: %v", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Close shuts the server down.
func (s *Server) Close() { _ = s.mux.Close() }

// Received returns payloads delivered to /data.
func (s *Server) Received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

func channelBinding(r *http.Request) ([]byte, error) {
	if r.TLS == nil {
		return nil, fmt.Errorf("not a TLS request")
	}
	return binding.FromConnState(*r.TLS)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleAttest serves a fresh quote bound to the caller's TLS session.
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	cb, err := channelBinding(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	q := quote.Sign(demo.QEKey, quote.Claims{
		Issuer:     "mock-qe/v1",
		MRenclave:  s.opts.MRenclave,
		MRSIGNER:   s.opts.MRSIGNER,
		TCBLevel:   s.opts.TCBLevel,
		ReportData: hex.EncodeToString(binding.ReportData(cb, binding.AttestContext)),
		Nonce:      hex.EncodeToString(nonce),
		IssuedAt:   time.Now().Unix(),
	})
	s.logf("server: issued quote bound to session %x…", cb[:8])
	writeJSON(w, q)
}

// handleSecret releases the secret only to a client proving it observed the
// same TLS session (proof derived from the channel binding).
func (s *Server) handleSecret(w http.ResponseWriter, r *http.Request) {
	cb, err := channelBinding(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	want := binding.Proof(cb, binding.SecretProofLabel)
	got, err := hex.DecodeString(r.Header.Get("X-Binding-Proof"))
	if err != nil || !binding.Check(cb, binding.SecretProofLabel, got) || len(got) != len(want) {
		s.logf("server: rejected secret request (bad binding proof)")
		http.Error(w, "binding proof required", http.StatusForbidden)
		return
	}
	s.logf("server: released secret to bound session %x…", cb[:8])
	writeJSON(w, map[string]string{"secret": s.opts.Secret})
}

// handleData accepts a post-attestation payload (the "sensitive" data).
func (s *Server) handleData(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.received = append(s.received, body.Payload)
	s.mu.Unlock()
	s.logf("server: received payload %q", body.Payload)
	writeJSON(w, map[string]string{"status": "stored"})
}

func (s *Server) handleReceived(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string][]string{"received": s.Received()})
}
