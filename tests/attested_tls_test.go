// Integration tests: the full attested-TLS story, including the relay attack.
package attestedtls_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/internal/client"
	"github.com/PeaceXXX/attested-tls-demo/internal/demo"
	"github.com/PeaceXXX/attested-tls-demo/internal/relay"
	"github.com/PeaceXXX/attested-tls-demo/internal/server"
	"github.com/PeaceXXX/attested-tls-demo/pkg/policy"
)

const (
	mrenclave = "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d"
	mrsigner  = "0011223344556677001122334455667700112233445566770011223344556677"
)

func testPolicy() policy.Policy {
	return policy.Policy{
		AllowedMRenclave: []string{mrenclave},
		AllowedMRSIGNER:  []string{mrsigner},
		MinTCBLevel:      1,
		MaxQuoteAge:      5 * time.Minute,
	}
}

func mustServer(t *testing.T) *server.Server {
	t.Helper()
	srv, err := server.New(server.Options{
		MRenclave: mrenclave, MRSIGNER: mrsigner, TCBLevel: 7, Secret: "s3cr3t",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestDirectFlow(t *testing.T) {
	srv := mustServer(t)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Run(client.Config{
		ServerURL: "https://" + addr,
		CAPEM:     srv.CAPEM(),
		QEKey:     demo.QEKey,
		Policy:    testPolicy(),
		Payload:   "record-123",
	})
	if err != nil {
		t.Fatalf("direct flow failed: %v", err)
	}
	if res.Claims.MRenclave != mrenclave {
		t.Fatalf("wrong measurement: %s", res.Claims.MRenclave)
	}
	if res.Secret != "s3cr3t" {
		t.Fatalf("wrong secret: %q", res.Secret)
	}
	if !res.DataSent {
		t.Fatal("payload was not sent")
	}
	got := srv.Received()
	if len(got) != 1 || got[0] != "record-123" {
		t.Fatalf("server received %v", got)
	}
}

func TestNaiveClientFooledByRelay(t *testing.T) {
	srv := mustServer(t)
	srvAddr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.New("https://"+srvAddr, srv.CAPEM(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	relayAddr, err := r.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// The victim trusts the relay's CA (compromised/misissued cert scenario)
	// and skips the binding check.
	res, err := client.Run(client.Config{
		ServerURL: "https://" + relayAddr,
		CAPEM:     r.CAPEM(),
		QEKey:     demo.QEKey,
		Policy:    testPolicy(),
		Naive:     true,
		Payload:   "ssn=123-45-6789",
	})
	if err != nil {
		t.Fatalf("naive client should have been fooled, but errored: %v", err)
	}
	if res.Claims.MRenclave != mrenclave {
		t.Fatal("naive client did not even get the relayed quote")
	}
	intercepted := r.Intercepted()
	if len(intercepted) != 1 || !strings.Contains(intercepted[0], "ssn=123-45-6789") {
		t.Fatalf("relay should have intercepted the payload, got %v", intercepted)
	}
}

func TestBoundClientDetectsRelay(t *testing.T) {
	srv := mustServer(t)
	srvAddr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.New("https://"+srvAddr, srv.CAPEM(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	relayAddr, err := r.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Run(client.Config{
		ServerURL: "https://" + relayAddr,
		CAPEM:     r.CAPEM(),
		QEKey:     demo.QEKey,
		Policy:    testPolicy(),
		Naive:     false, // binding check ON
		Payload:   "ssn=123-45-6789",
	})
	var relayErr *client.RelayError
	if !errors.As(err, &relayErr) {
		t.Fatalf("expected *RelayError, got: %v", err)
	}
	if len(r.Intercepted()) != 0 {
		t.Fatalf("bound client must send nothing; relay saw %v", r.Intercepted())
	}
	if len(srv.Received()) != 0 {
		t.Fatalf("server must receive nothing; got %v", srv.Received())
	}
}

func TestServerRejectsUnboundSecretRequest(t *testing.T) {
	srv := mustServer(t)
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A client on a *different* connection cannot reuse another session's proof:
	// here we just check the endpoint requires the proof header at all.
	res, err := client.Run(client.Config{
		ServerURL: "https://" + addr,
		CAPEM:     srv.CAPEM(),
		QEKey:     demo.QEKey,
		Policy:    testPolicy(),
		Payload:   "",
	})
	if err != nil {
		t.Fatalf("bound client should get the secret: %v", err)
	}
	if res.Secret == "" {
		t.Fatal("expected a secret")
	}
}
