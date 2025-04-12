package main

import (
	"fmt"
	"log"
	"os"

	"github.com/miekg/dns"
)

const listenAddress = ":53"

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				log.Printf("Query for %s\n", q.Name)
				// Example: Always resolve to 1.2.3.4
				rr, err := dns.NewRR(fmt.Sprintf("%s A 1.2.3.4", q.Name))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Println(err)
	}
}

func startDNSServer() error {
	// Attach request handler func
	dns.HandleFunc(".", handleDNSRequest)

	// Listen on UDP
	server := &dns.Server{Addr: listenAddress, Net: "udp"}
	log.Printf("Starting DNS server on %s\n", listenAddress)
	err := server.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server: %s", err.Error())
	}
	return nil
}

func main() {
	if err := startDNSServer(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
