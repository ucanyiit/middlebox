package main

import (
	"fmt"

	"github.com/google/gopacket/layers"
)

var DNS_TYPE_MAP = map[int]layers.DNSType{
	0: layers.DNSTypeA,
	1: layers.DNSTypeNS,
	2: layers.DNSTypeSOA,
	3: layers.DNSTypeAAAA,
	4: layers.DNSTypeCNAME,
}

func generateCovertTypeQueries(message string) ([][]byte, error) {

	covertData := []byte(message)

	// Encode the covert data to dns types
	encodedData := []layers.DNSType{}
	for _, b := range covertData {
		for i := 0; i < 4; i++ {
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

	endQueryPacket, _ := generateDNSQuery(BASE_DOMAIN, layers.DNSTypeCNAME)
	dnsQueryPackets = append(dnsQueryPackets, endQueryPacket)

	return dnsQueryPackets, nil
}
