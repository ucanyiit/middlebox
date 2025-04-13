package main

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
)

const LISTEN_ADDRESS = ":53"
const BASE_DOMAIN = "example.com"

func startDNSServer(handleFunc func(dns.ResponseWriter, *dns.Msg)) (err error) {
	// Attach request handler func
	dns.HandleFunc(".", handleFunc)

	// Listen on UDP
	server := &dns.Server{Addr: LISTEN_ADDRESS, Net: "udp"}
	log.Printf("Starting DNS server on %s\n", LISTEN_ADDRESS)
	err = server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %s", err.Error())
	}
	return nil
}

func main() {
	dnsRequestHandler := getCovertDNSRequestHandler(handleTypedDNSQuestion)

	if err := startDNSServer(dnsRequestHandler); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
