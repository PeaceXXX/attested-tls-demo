// Package relay is the adversary for the demo: a man-in-the-middle that
// terminates TLS with its own CA, forwards traffic to the real server, and
// replays the server's genuine attestation evidence to the victim.
//
// The victim's naive client verifies the quote's signature and policy — both
// pass, because the evidence is real — and concludes the channel is trusted.
// Only the channel-binding check exposes the relay.
package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/internal/certs"
	"github.com/PeaceXXX/attested-tls-demo/internal/client"
	"github.com/PeaceXXX/attested-tls-demo/internal/demo"
	"github.com/PeaceXXX/attested-tls-demo/pkg/binding"
	"github.com/PeaceXXX/attested-tls-demo/pkg/policy"
)

// Relay is a running MITM proxy.
type Relay struct {
	upstream    string
	client      *http.Client
	caPEM       []byte
	srv         *http.Server
	mu          sync.Mutex
	intercepted []string
	secret      string // obtained via the relay's own legitimate attested session
	logf        func(string, ...any)
}

// New creates a relay that forwards to upstream (e.g. https://127.0.0.1:8443),
// trusting upstreamCAPEM.
func New(upstream string, upstreamCAPEM []byte, logf func(string, ...any)) (*Relay, error) {
	if logf == nil {
		logf = log.Printf
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(upstreamCAPEM) {
		return nil, fmt.Errorf("relay: bad upstream CA PEM")
	}
	caPEM, caCert, caKey, err := certs.GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("relay: generate CA: %w", err)
	}
	certPEM, keyPEM, err := certs.ServerCert(caCert, caKey, []string{"127.0.0.1", "localhost"})
	if err != nil {
		return nil, fmt.Errorf("relay: generate cert: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	r := &Relay{
		upstream: upstream,
		client:   &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}},
		caPEM:    caPEM,
		logf:     logf,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.handle)
	r.srv = &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}
	// The relay completes its *own* legitimate attested session with the
	// upstream server and caches the released secret — exactly what a real
	// MITM proxy does: it is a valid client of the server, and a fake
	// server to the victim.
	res, err := client.Run(client.Config{
		ServerURL: upstream,
		CAPEM:     upstreamCAPEM,
		QEKey:     demo.QEKey,
		Policy:    policy.Policy{MaxQuoteAge: 5 * time.Minute}, // permissive: attacker trusts any workload
	})
	if err != nil {
		return nil, fmt.Errorf("relay: own attested session failed: %w", err)
	}
	r.secret = res.Secret
	logf("relay: completed own attested session with upstream, cached secret")
	return r, nil
}

// CAPEM returns the relay CA the victim must (foolishly) trust.
func (r *Relay) CAPEM() []byte { return r.caPEM }

// Start listens on addr and returns the actual address.
func (r *Relay) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	tlsLn := tls.NewListener(ln, r.srv.TLSConfig)
	go func() {
		if err := r.srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			r.logf("relay: %v", err)
		}
	}()
	return ln.Addr().String(), nil
}

// Close shuts the relay down.
func (r *Relay) Close() { _ = r.srv.Close() }

// Intercepted returns sensitive payloads the relay observed in cleartext.
func (r *Relay) Intercepted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.intercepted...)
}

func (r *Relay) handle(w http.ResponseWriter, req *http.Request) {
	// /secret is served from the relay's own cached secret: the victim's
	// session with the relay is perfectly self-consistent (the relay even
	// checks the victim's binding proof against *their* session), which is
	// why the victim cannot tell it is not talking to the real server.
	if req.URL.Path == "/secret" {
		r.serveSecret(w, req)
		return
	}
	body, _ := io.ReadAll(http.MaxBytesReader(w, req.Body, 1<<20))
	if req.URL.Path == "/data" && len(body) > 0 {
		r.mu.Lock()
		r.intercepted = append(r.intercepted, string(body))
		r.mu.Unlock()
		r.logf("relay: INTERCEPTED sensitive payload: %s", truncate(string(body), 120))
	} else {
		r.logf("relay: forwarding %s %s", req.Method, req.URL.Path)
	}
	upReq, err := http.NewRequest(req.Method, r.upstream+req.URL.Path, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for k, vv := range req.Header {
		for _, v := range vv {
			upReq.Header.Add(k, v)
		}
	}
	upResp, err := r.client.Do(upReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()
	for k, vv := range upResp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(upResp.StatusCode)
	_, _ = io.Copy(w, upResp.Body)
}

// serveSecret plays the server's role toward the victim, using the secret the
// relay legitimately obtained in its own session with the real server.
func (r *Relay) serveSecret(w http.ResponseWriter, req *http.Request) {
	if req.TLS == nil {
		http.Error(w, "not a TLS request", http.StatusBadRequest)
		return
	}
	cb, err := binding.FromConnState(*req.TLS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	got, err := hex.DecodeString(req.Header.Get("X-Binding-Proof"))
	if err != nil || !binding.Check(cb, binding.SecretProofLabel, got) {
		r.logf("relay: victim's binding proof invalid for victim-relay session")
		http.Error(w, "binding proof required", http.StatusForbidden)
		return
	}
	r.logf("relay: victim verified US as the attested server; serving cached secret")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"secret": r.secret})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
