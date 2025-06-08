package main

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/gopacket/layers"
)

// DNSRecordType represents a DNS record type with its name and frequency weight
type DNSRecordType struct {
	Name      string
	Frequency float64
}

// DNS frequency baseline based on real-world traffic patterns
var dnsFrequencyBaseline = map[layers.DNSType]DNSRecordType{
	// Extremely High frequency
	layers.DNSTypeA: {"A", 40},
	// Very High frequency
	layers.DNSTypeAAAA: {"AAAA", 20},
	// High frequency
	layers.DNSTypeNS:    {"NS", 8},
	layers.DNSTypePTR:   {"PTR", 8},
	65:                  {"HTTPS", 8}, // HTTPS/SVCB record type
	layers.DNSTypeTXT:   {"TXT", 8},
	layers.DNSTypeMX:    {"MX", 8},
	layers.DNSTypeCNAME: {"CNAME", 8},
	layers.DNSTypeSOA:   {"SOA", 8},
	// Moderate frequency
	43:                {"DS", 5},
	48:                {"DNSKEY", 5},
	46:                {"RRSIG", 5},
	layers.DNSTypeSRV: {"SRV", 5},
	47:                {"NSEC", 5},
	50:                {"NSEC3", 5},
	// Low frequency
	257: {"CAA", 2},
	35:  {"NAPTR", 2},
	52:  {"TLSA", 2},
	// Very Low frequency
	44: {"SSHFP", 0.5},
	39: {"DNAME", 0.5},
	// Extremely Low frequency
	29:  {"LOC", 0.2},
	256: {"URI", 0.2},
	// Effectively Zero frequency
	13: {"HINFO", 0},
	17: {"RP", 0},
}

// Weighted DNS type selection based on frequency
type weightedDNSType struct {
	dnsType layers.DNSType
	weight  float64
}

var weightedDNSTypes []weightedDNSType
var totalWeight float64

func init() {
	// Initialize weighted DNS types for random selection
	for dnsType, record := range dnsFrequencyBaseline {
		if record.Frequency > 0 { // Only include types with non-zero frequency
			weightedDNSTypes = append(weightedDNSTypes, weightedDNSType{
				dnsType: dnsType,
				weight:  record.Frequency,
			})
			totalWeight += record.Frequency
		}
	}
}

// selectRandomDNSType selects a DNS type based on weighted probability
func selectRandomDNSType() layers.DNSType {
	if len(weightedDNSTypes) == 0 {
		return layers.DNSTypeA // Fallback
	}

	random := rand.Float64() * totalWeight
	var cumulative float64

	for _, wt := range weightedDNSTypes {
		cumulative += wt.weight
		if random <= cumulative {
			return wt.dnsType
		}
	}

	// Fallback to A record
	return layers.DNSTypeA
}

// generateNormalTrafficQueries generates normal DNS traffic using the normal traffic domain
func generateNormalTrafficQueries(message string) ([][]byte, error) {
	// Split message into words to create realistic looking DNS queries
	words := strings.Fields(message)
	dnsQueryPackets := make([][]byte, 0)

	// Create multiple queries for each word to simulate normal browsing behavior
	for i := range words {
		// Use different subdomains to make it look like normal traffic
		subdomains := []string{"www", "mail", "ftp", "api", "cdn", "static", "blog", "shop", "app", "m"}
		subdomain := subdomains[i%len(subdomains)]

		// Create domain like "www.normal.example.com", "mail.normal.example.com", etc.
		domain := fmt.Sprintf("%s.%s", subdomain, NORMAL_TRAFFIC_DOMAIN)

		// Generate a realistic number of queries per domain (1-5 queries)
		numQueries := rand.Intn(5) + 1

		for j := 0; j < numQueries; j++ {
			// Select DNS type based on realistic frequency distribution
			qtype := selectRandomDNSType()

			queryPacket, err := generateDNSQuery(domain, qtype)
			if err != nil {
				recordInfo, exists := dnsFrequencyBaseline[qtype]
				recordName := "UNKNOWN"
				if exists {
					recordName = recordInfo.Name
				}
				fmt.Printf("Error generating normal DNS query for %s (%s): %s\n", domain, recordName, err)
				continue
			}

			dnsQueryPackets = append(dnsQueryPackets, queryPacket)
		}
	}

	fmt.Printf("Generated %d normal DNS query packets for domain %s using realistic frequency distribution\n", len(dnsQueryPackets), NORMAL_TRAFFIC_DOMAIN)
	return dnsQueryPackets, nil
}
