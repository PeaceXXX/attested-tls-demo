// Package client is the relying party: it fetches attestation evidence over
// TLS, verifies it, binds it to its own session, and only then trusts the
// channel. With Naive=true it skips the binding check — the vulnerable
// configuration the relay demo exploits.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/PeaceXXX/attested-tls-demo/pkg/binding"
	"github.com/PeaceXXX/attested-tls-demo/pkg/policy"
	"github.com/PeaceXXX/attested-tls-demo/pkg/quote"
)

// RelayError is returned when evidence is genuine but bound to another
// session: someone is relaying.
type RelayError struct{ msg string }

func (e *RelayError) Error() string { return e.msg }

// Config configures one attested session.
type Config struct {
	ServerURL string // e.g. https://127.0.0.1:8443
	CAPEM     []byte // CA to trust
	QEKey     []byte // mock quoting-enclave key (demo only)
	Policy    policy.Policy
	Naive     bool   // skip the channel-binding check (vulnerable mode)
	Payload   string // sensitive payload sent after attestation
}

// Result of a successful attested session.
type Result struct {
	Claims   quote.Claims
	Secret   string
	DataSent bool
}

// Run performs the full attested-TLS flow.
func Run(cfg Config) (*Result, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, fmt.Errorf("client: bad CA PEM")
	}
	var mu sync.Mutex
	var conns []*tls.Conn
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &tls.Dialer{Config: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
			}}
			c, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := c.(*tls.Conn); ok {
				mu.Lock()
				conns = append(conns, tc)
				mu.Unlock()
			}
			return c, nil
		},
	}
	hc := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()

	// 1. Fetch evidence.
	resp, err := hc.Get(cfg.ServerURL + "/attest")
	if err != nil {
		return nil, fmt.Errorf("client: /attest: %w", err)
	}
	var q quote.Quote
	if err := json.NewDecoder(resp.Body).Decode(&q); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("client: decode quote: %w", err)
	}
	resp.Body.Close()

	// 2. Our view of the session's channel binding.
	mu.Lock()
	if len(conns) == 0 {
		mu.Unlock()
		return nil, fmt.Errorf("client: no TLS connection captured")
	}
	cb, err := binding.FromConnState(conns[0].ConnectionState())
	mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("client: %w", err)
	}

	// 3. Policy appraisal. The binding expectation is what stops relays.
	pol := cfg.Policy
	if !cfg.Naive {
		pol.ExpectedReportData = binding.ReportData(cb, binding.AttestContext)
	}
	if err := pol.Appraise(q, cfg.QEKey); err != nil {
		if !cfg.Naive && strings.Contains(err.Error(), "not bound to this session") {
			return nil, &RelayError{msg: "RELAY DETECTED: genuine quote, but its REPORT_DATA is bound to a different TLS session — refusing to trust this channel"}
		}
		return nil, fmt.Errorf("client: appraisal failed: %w", err)
	}

	// 4. Prove to the server we observed the same session, get the secret.
	req, _ := http.NewRequest("POST", cfg.ServerURL+"/secret", nil)
	req.Header.Set("X-Binding-Proof", hex.EncodeToString(binding.Proof(cb, binding.SecretProofLabel)))
	resp, err = hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: /secret: %w", err)
	}
	var secretResp struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("client: decode secret: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client: server refused secret (status %d)", resp.StatusCode)
	}

	// 5. Send the sensitive payload over the now-trusted channel.
	res := &Result{Claims: q.Claims, Secret: secretResp.Secret}
	if cfg.Payload != "" {
		body, _ := json.Marshal(map[string]string{"payload": cfg.Payload})
		resp, err := hc.Post(cfg.ServerURL+"/data", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("client: /data: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("client: /data status %d", resp.StatusCode)
		}
		res.DataSent = true
	}
	return res, nil
}
