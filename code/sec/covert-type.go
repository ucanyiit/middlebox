package main

import (
	"fmt"

	"github.com/google/gopacket/layers"
)

var DNS_TYPE_MAP = map[int]layers.DNSType{
	0: layers.DNSTypeCNAME, // Standard code: 5
	1: layers.DNSTypeA,     // Standard code: 1
	2: layers.DNSTypeAAAA,  // Standard code: 28
	3: layers.DNSTypeMX,    // Standard code: 15
	4: layers.DNSTypeMD,    // Standard code: 99 (end marker)
}

func generateCovertTypeQueries(message string) ([][]byte, error) {

	covertData := []byte(message)

	// Encode the covert data to dns types
	encodedData := []layers.DNSType{}
	for _, b := range covertData {
		for b > 0 {
			// Get the least significant 2
			lsb := b & 0x03
			// Clear the least significant 2 bits
			b &= 0xFC
			// Shift right by 2 bits
			b >>= 2
			// Append the least significant 2 bits to the encoded data
			encodedData = append(encodedData, DNS_TYPE_MAP[int(lsb)])
			// If the least significant 2 bits are 0, break
		}
	}

	fmt.Printf("Encoding message: '%s'\n", message)
	fmt.Printf("Encoded data: %v\n", encodedData)

	// sequenceNumber := 0
	dnsQueryPackets := make([][]byte, 0)

	for _, t := range encodedData {
		// Generate a DNS query packet for each encoded type
		queryPacket, err := generateDNSQuery(BASE_DOMAIN, t)
		if err != nil {
			return nil, err
		}
		dnsQueryPackets = append(dnsQueryPackets, queryPacket)
	}

	endQueryPacket, _ := generateDNSQuery(BASE_DOMAIN, layers.DNSTypeMD) // End of covert data
	dnsQueryPackets = append(dnsQueryPackets, endQueryPacket)

	return dnsQueryPackets, nil
}
