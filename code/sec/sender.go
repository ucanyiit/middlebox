package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func generateDNSQuery(domain string) []byte {
	// Generate a random transaction ID
	rand.Seed(time.Now().UnixNano())
	transactionID := uint16(rand.Intn(65535))

	// Create DNS question
	dnsQuestion := layers.DNSQuestion{
		Name:  []byte(domain),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}

	// Create DNS layer
	dns := layers.DNS{
		ID:      transactionID,
		RD:      true, // Recursion Desired
		QDCount: 1,    // One question
		Questions: []layers.DNSQuestion{
			dnsQuestion,
		},
	}

	// Serialize DNS layer
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}

	err := dns.SerializeTo(buffer, options)
	if err != nil {
		panic(err)
	}

	return buffer.Bytes()
}

func udpSender() {
	host := os.Getenv("INSECURENET_HOST_IP")
	port := 53 // DNS port
	domain := "google.com"

	if host == "" {
		fmt.Println("INSECURENET_HOST_IP environment variable is not set.")
		return
	}

	// Resolve the address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("Error resolving address: %s\n", err)
		return
	}

	// Create a UDP socket
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("Error dialing UDP: %s\n", err)
		return
	}
	defer conn.Close()

	for {
		// Generate DNS query
		dnsQuery := generateDNSQuery(domain)

		// Send DNS query to the server
		_, err := conn.Write(dnsQuery)
		if err != nil {
			fmt.Printf("Error sending DNS query: %s\n", err)
			return
		}
		fmt.Printf("DNS query sent to %s:%d for %s\n", host, port, domain)

		// Receive response from the server
		buffer := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Error receiving response: %s\n", err)
			return
		}
		fmt.Printf("Received %d bytes\n", n)

		// Sleep for 1 second
		time.Sleep(1 * time.Second)
	}
}

func main() {
	udpSender()
}
