package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// generateDNSTXTQuery creates a DNS query packet for a specific domain, requesting a TXT record.
func generateDNSTXTQuery(domain string) ([]byte, error) {
	// Generate a random transaction ID
	// Note: For production/better randomness, use crypto/rand or rand.New(rand.NewSource(...))
	// rand.Seed(time.Now().UnixNano()) // Deprecated pattern, but simple for example
	transactionID := uint16(rand.Intn(65535)) // Using math/rand for simplicity here

	// Create DNS question for TXT record
	dnsQuestion := layers.DNSQuestion{
		Name:  []byte(domain),
		Type:  layers.DNSTypeTXT, // Requesting TXT record
		Class: layers.DNSClassIN,
	}

	// Create DNS layer
	dns := layers.DNS{
		ID:        transactionID,
		OpCode:    layers.DNSOpCodeQuery,
		RD:        true, // Recursion Desired (optional, can be false)
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
		ComputeChecksums: true,
	}

	err := dns.SerializeTo(buffer, options)
	if err != nil {
		return nil, fmt.Errorf("error serializing DNS layer: %w", err)
	}

	return buffer.Bytes(), nil
}

// generateCovertTXTQueries generates covert DNS TXT queries
func generateCovertTXTQueries(message string) ([][]byte, error) {
	// --- Covert Channel Logic ---
	covertData := []byte(message)
	encodedData := hex.EncodeToString(covertData) // Encode message to Hex

	// Domain labels have a max length of 63 chars. Hex encoding doubles the size.
	const encodedChunkSize = 60
	sequenceNumber := 0
	dnsQueryPackets := make([][]byte, 0)

	for i := 0; i < len(encodedData); i += encodedChunkSize {
		end := i + encodedChunkSize
		if end > len(encodedData) {
			end = len(encodedData)
		}
		chunk := encodedData[i:end]

		fmt.Printf("Chunk: %s\n", chunk)

		// Construct the full domain name for the query
		// Format: [hex_chunk].[sequence_number]
		queryText := fmt.Sprintf("%s.%d", chunk, sequenceNumber)

		fmt.Printf("Query Text: %s\n", queryText)

		// Generate the DNS TXT query packet
		dnsQueryPacket, _ := generateDNSTXTQuery(queryText)

		// Send the DNS query packet
		dnsQueryPackets = append(dnsQueryPackets, dnsQueryPacket)

		sequenceNumber++
	}

	endQueryText := fmt.Sprintf("end.%d", sequenceNumber)
	endQuery, _ := generateDNSTXTQuery(endQueryText)
	dnsQueryPackets = append(dnsQueryPackets, endQuery)

	return dnsQueryPackets, nil
}
