// Command client is the relying party: it attests the server over TLS,
// verifies the evidence is bound to its own session, then sends a payload.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/PeaceXXX/attested-tls-demo/internal/client"
	"github.com/PeaceXXX/attested-tls-demo/internal/demo"
	"github.com/PeaceXXX/attested-tls-demo/pkg/policy"
)

func main() {
	serverURL := flag.String("server", "https://127.0.0.1:8443", "server base URL")
	ca := flag.String("ca", "ca.pem", "CA cert to trust")
	naive := flag.Bool("naive", false, "skip the channel-binding check (vulnerable mode)")
	payload := flag.String("payload", "patient-id=42;diagnosis=classified", "sensitive payload sent after attestation")
	mrenclave := flag.String("mrenclave", "deadbeefcafef00d"+"deadbeefcafef00d"+"deadbeefcafef00d"+"deadbeefcafef00d", "expected workload measurement")
	mrsigner := flag.String("mrsigner", "0011223344556677"+"0011223344556677"+"0011223344556677"+"0011223344556677", "expected workload signer")
	minTCB := flag.Int("min-tcb", 1, "minimum acceptable TCB level")
	flag.Parse()

	caPEM, err := os.ReadFile(*ca)
	if err != nil {
		log.Fatalf("read CA: %v", err)
	}
	res, err := client.Run(client.Config{
		ServerURL: *serverURL,
		CAPEM:     caPEM,
		QEKey:     demo.QEKey,
		Policy: policy.Policy{
			AllowedMRenclave: []string{*mrenclave},
			AllowedMRSIGNER:  []string{*mrsigner},
			MinTCBLevel:      *minTCB,
			MaxQuoteAge:      5 * time.Minute,
		},
		Naive:   *naive,
		Payload: *payload,
	})
	if err != nil {
		fmt.Printf("\n❌ attestation FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n✅ attested: mrenclave=%.16s… mrsigner=%.16s… tcb=%d\n",
		res.Claims.MRenclave, res.Claims.MRSIGNER, res.Claims.TCBLevel)
	fmt.Printf("🔑 secret received: %s\n", res.Secret)
	if res.DataSent {
		fmt.Printf("📤 payload delivered over the attested channel\n")
	}
}
