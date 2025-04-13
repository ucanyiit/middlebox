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

var COVERT_CHANNEL_HANDLER_MAP = map[string]func(dns.Question){
	"txt":   handleTXTDNSQuestion,
	"cname": handleCNAMEDNSQuestion,
	"typed": handleTypedDNSQuestion,
}

func main() {
	args := os.Args
	typeArg := args[1] // covert channel type
	dnsRequestHandler := getCovertDNSRequestHandler(
		COVERT_CHANNEL_HANDLER_MAP[typeArg],
	)

	if err := startDNSServer(dnsRequestHandler); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
