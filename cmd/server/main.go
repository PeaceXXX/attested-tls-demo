// Command server runs the attested workload: an HTTPS server whose /attest
// endpoint serves a mock TEE quote bound to the caller's TLS session.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"

	"github.com/PeaceXXX/attested-tls-demo/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	caOut := flag.String("ca-out", "ca.pem", "where to write the CA cert clients must trust")
	mrenclave := flag.String("mrenclave", "deadbeefcafef00d"+"deadbeefcafef00d"+"deadbeefcafef00d"+"deadbeefcafef00d", "workload measurement (hex)")
	mrsigner := flag.String("mrsigner", "0011223344556677"+"0011223344556677"+"0011223344556677"+"0011223344556677", "workload signer (hex)")
	tcb := flag.Int("tcb", 7, "platform TCB level")
	secret := flag.String("secret", "the-secret-only-attested-clients-get", "secret released to bound clients")
	flag.Parse()

	srv, err := server.New(server.Options{
		MRenclave: *mrenclave,
		MRSIGNER:  *mrsigner,
		TCBLevel:  *tcb,
		Secret:    *secret,
	}, log.Printf)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, srv.CAPEM(), 0644); err != nil {
		log.Fatal(err)
	}
	actual, err := srv.Start(*addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("attested workload listening on https://%s (CA written to %s)", actual, *caOut)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	srv.Close()
}
