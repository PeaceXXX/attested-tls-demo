// Command relay runs the demo adversary: a MITM proxy that terminates TLS
// with its own CA and replays the real server's attestation evidence.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/PeaceXXX/attested-tls-demo/internal/relay"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "listen address")
	upstream := flag.String("upstream", "https://127.0.0.1:8443", "real server URL")
	upstreamCA := flag.String("upstream-ca", "ca.pem", "real server's CA cert")
	caOut := flag.String("ca-out", "relay-ca.pem", "where to write the relay CA (victim must trust this)")
	flag.Parse()

	upCA, err := os.ReadFile(*upstreamCA)
	if err != nil {
		log.Fatalf("read upstream CA: %v", err)
	}
	r, err := relay.New(*upstream, upCA, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, r.CAPEM(), 0644); err != nil {
		log.Fatal(err)
	}
	actual, err := r.Start(*listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("⚠️  relay listening on https://%s → %s (CA written to %s)", actual, *upstream, *caOut)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	r.Close()
}
