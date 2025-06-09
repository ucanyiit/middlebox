package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/nats-io/nats.go"
)

// Threat level thresholds
const (
	CriticalThreatThreshold = 1000.0
	HighThreatThreshold     = 500.0
	MediumThreatThreshold   = 200.0
	LowThreatThreshold      = 50.0
	MitigationProbability   = 0.1 // 1/10th chance (10%)
	DelayDuration           = 200 // Delay in milliseconds
)

// Mitigation strategies
const (
	DropStrategy  = "drop"
	DelayStrategy = "delay"
)

// DNSRecordType holds information about DNS record types
type DNSRecordType struct {
	Name      string
	Frequency float64 // Expected frequency score (0-100, higher = more common)
}

// DNSPacketRecord holds information about a single DNS packet for rolling window analysis
type DNSPacketRecord struct {
	PacketID int
	DNSTypes []layers.DNSType // All DNS types observed in this packet (questions + answers)
}

// Global variables for DNS type frequency tracking
var (
	dnsTypeMutex    sync.RWMutex
	totalDNSPackets int
	suspicionScore  float64 // Running suspicion score
	droppedPackets  int     // Counter for dropped packets
	delayedPackets  int     // Counter for delayed packets

	// Rolling window for last 100 packets
	dnsPacketWindow []DNSPacketRecord
	maxWindowSize   = 100
	currentPacketID = 0

	// DNS record frequency baseline (based on real-world usage data)
	dnsFrequencyBaseline = map[layers.DNSType]DNSRecordType{
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

	// Global variables for file logging
	logFile   *os.File
	logWriter io.Writer
)

// Function to log to both stdout and file
func logOutput(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Print(message)
	if logWriter != nil {
		logWriter.Write([]byte(message))
	}
}

// Function to get DNS type name and info for better readability
func getDNSTypeInfo(dnsType layers.DNSType) (string, float64) {
	if info, exists := dnsFrequencyBaseline[dnsType]; exists {
		return info.Name, info.Frequency
	}
	return fmt.Sprintf("Unknown_%d", int(dnsType)), 0
}

// Function to calculate suspicion score based on DNS type frequency deviation
func calculateSuspicionScore(dnsType layers.DNSType, observedPercentage float64) float64 {
	_, expectedFreq := getDNSTypeInfo(dnsType)

	// Convert expected frequency to percentage (baseline)
	expectedPercentage := float64(expectedFreq)

	// if it's in the range of expected frequency * 0.8 and * 1.2, // we consider it not suspicious
	if observedPercentage <= expectedPercentage*1.2 && observedPercentage >= expectedPercentage*0.8 {
		return 0.0 // Not suspicious
	} else if observedPercentage < expectedPercentage*0.8 {
		return math.Pow(expectedPercentage*0.8-observedPercentage, 2) // Squared deviation for under-representation
	} else if observedPercentage > expectedPercentage*1.2 {
		return math.Pow(observedPercentage-expectedPercentage*1.2, 2) // Squared deviation for over-representation
	}

	return 0.0 // Default case, should not happen
}

// Function to analyze DNS packet and detect potential covert channel
func analyzeDNSPacket(dns *layers.DNS) {
	dnsTypeMutex.Lock()
	defer dnsTypeMutex.Unlock()

	totalDNSPackets++

	// Collect DNS types from this packet for rolling window
	var packetDNSTypes []layers.DNSType
	for _, question := range dns.Questions {
		packetDNSTypes = append(packetDNSTypes, question.Type)
	}
	for _, answer := range dns.Answers {
		packetDNSTypes = append(packetDNSTypes, answer.Type)
	}

	// Add to rolling window
	dnsPacketWindow = append(dnsPacketWindow, DNSPacketRecord{
		PacketID: currentPacketID,
		DNSTypes: packetDNSTypes,
	})
	currentPacketID++

	// Maintain window size
	if len(dnsPacketWindow) > maxWindowSize {
		dnsPacketWindow = dnsPacketWindow[1:]
	}

	evaluateThreatLevel()
}

// Function to print DNS type frequency analysis with suspicion scoring based on rolling window
func evaluateThreatLevel() {
	// Calculate frequency distribution based on rolling window
	windowTypeFrequency := make(map[layers.DNSType]int)
	totalWindowTypes := 0

	// Count DNS types in the current window
	for _, packetRecord := range dnsPacketWindow {
		for _, dnsType := range packetRecord.DNSTypes {
			windowTypeFrequency[dnsType]++
			totalWindowTypes++
		}
	}

	// Calculate new suspicion score based on current window only
	windowSuspicionScore := 0.0

	if totalWindowTypes == 0 {
		return
	}

	for dnsType, count := range windowTypeFrequency {
		percentage := float64(count) / float64(totalWindowTypes) * 100

		// name, expectedFreq := getDNSTypeInfo(dnsType)
		// logOutput("Type %s (%d): Count=%d, Percentage=%.2f%%, Expected=~%d%%\n",
		// 	name, int(dnsType), count, percentage, expectedFreq)

		windowSuspicionScore += calculateSuspicionScore(dnsType, percentage)
	}

	// Replace global suspicion score with window-based score
	suspicionScore = windowSuspicionScore

	// Evaluate overall threat level
	logThreatLevelAnalysis()
}

// Function to evaluate the overall threat level based on suspicion score
func logThreatLevelAnalysis() {
	windowSize := len(dnsPacketWindow)
	logOutput("\n=== DNS Threat Level Assessment ===\n")
	logOutput("Total DNS packets processed: %d\n", totalDNSPackets)
	logOutput("Current window size: %d packets (max %d)\n", windowSize, maxWindowSize)

	if suspicionScore >= CriticalThreatThreshold {
		logOutput("🚨 CRITICAL THREAT LEVEL (Score: %.1f)\n", suspicionScore)
	} else if suspicionScore >= HighThreatThreshold {
		logOutput("⚠️  HIGH THREAT LEVEL (Score: %.1f)\n", suspicionScore)
	} else if suspicionScore >= MediumThreatThreshold {
		logOutput("🟡 MEDIUM THREAT LEVEL (Score: %.1f)\n", suspicionScore)
	} else if suspicionScore >= LowThreatThreshold {
		logOutput("🟢 LOW THREAT LEVEL (Score: %.1f)\n", suspicionScore)
	} else {
		logOutput("✅ NORMAL ACTIVITY (Score: %.1f)\n", suspicionScore)
	}
}

// Function to mitigate packets based on strategy
func mitigatePacket(strategy string, suspicionScore float64) bool {
	// Apply mitigation based on strategy with 1/10th probability
	if rand.Float32() < MitigationProbability {
		switch strategy {
		case DropStrategy:
			dnsTypeMutex.Lock()
			droppedPackets++
			totalDropped := droppedPackets
			dnsTypeMutex.Unlock()

			logOutput("🚫 PACKET DROPPED (Strategy: %s, Suspicion Score: %.1f, Total Dropped: %d)\n",
				strategy, suspicionScore, totalDropped)
			return true // Packet was mitigated (droppe
		case DelayStrategy:
			dnsTypeMutex.Lock()
			delayedPackets++
			totalDelayed := delayedPackets
			dnsTypeMutex.Unlock()

			logOutput("⏳ PACKET DELAYED (Strategy: %s, Suspicion Score: %.1f, Delay: %dms, Total Delayed: %d)\n",
				strategy, suspicionScore, DelayDuration, totalDelayed)
			time.Sleep(DelayDuration * time.Millisecond)
			return false // Packet was mitigated but not dropped (will be forwarded after delay)

		default:
			logOutput("⚠️ Unknown mitigation strategy: %s\n", strategy)
			return false
		}
	}
	return false // No mitigation applied
}

// Function to process the ethernet packet
func processEthernetPacket(nc *nats.Conn, iface string, data []byte) {
	// Use gopacket to dissect the packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		logOutput("Error decoding some part of the packet: %s\n", packet.ErrorLayer().Error())
		return
	}
	// Check for Ethernet layer
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		// logOutput("Ethernet layer detected.\n")
		// logOutput("%s\n", gopacket.LayerDump(ethernetLayer))
	}

	// Check for IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		// logOutput("IPv4 layer detected.\n")
		// logOutput("%s\n", gopacket.LayerDump(ipLayer))
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		logOutput("IPv6 layer detected.\n")
		logOutput("%s\n", gopacket.LayerDump(ipLayer))
	}

	// Check for TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		logOutput("TCP layer detected.\n")
		logOutput("%s\n", gopacket.LayerDump(tcpLayer))
	}

	// Check for UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// logOutput("UDP layer detected.\n")
		// logOutput("%s\n", gopacket.LayerDump(udpLayer))

		// Check if this is a DNS packet (UDP port 53)
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 53 || udp.DstPort == 53 {
			// Check for DNS layer
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				// logOutput("DNS layer detected in UDP packet.\n")
				dns, _ := dnsLayer.(*layers.DNS)
				analyzeDNSPacket(dns)
			}
		}
	}
	// Publish the processed packet to the appropriate subject
	var subject string
	if iface == "inpktsec" {
		subject = "outpktinsec"
	} else {
		subject = "outpktsec"
	}

	logOutput("Suspicion Score: %.1f\n", suspicionScore)

	if suspicionScore > CriticalThreatThreshold && mitigatePacket(DropStrategy, suspicionScore) {
		return // Packet was dropped, don't publish it
	}

	err := nc.Publish(subject, data)
	if err != nil {
		logOutput("Error publishing message: %s\n", err)
	}
}

func main() {
	// Create log file with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logFileName := fmt.Sprintf("dns_analysis_%s.log", timestamp)

	var logErr error
	logFile, logErr = os.Create(logFileName)
	if logErr != nil {
		log.Fatalf("Error creating log file: %v", logErr)
	}
	defer logFile.Close()

	// Create a multi-writer to write to both stdout and file
	logWriter = io.MultiWriter(os.Stdout, logFile)

	logOutput("🔍 DNS Covert Channel Detection System Started 🔍\n")
	logOutput("📊 Using advanced frequency-based threat scoring system\n")
	logOutput("📁 Logging to file: %s\n", logFileName)

	url := os.Getenv("NATS_SURVEYOR_SERVERS")
	if url == "" {
		url = nats.DefaultURL
	}
	logOutput("NATS_SURVEYOR_SERVERS: %s\n", url)

	// Connect to a server
	nc, _ := nats.Connect(url)
	defer nc.Drain()

	// Create a multi-writer to write to both stdout and log file
	logWriter = io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(logWriter)

	// Log the start of the program
	logOutput("DNS Covert Channel Detection System Started")
	logOutput("Using advanced frequency-based threat scoring system")

	// Simple Publisher
	//nc.Publish("foo", []byte("Hello World"))

	// Simple Subscriber
	nc.Subscribe("inpktsec", func(m *nats.Msg) {
		//fmt.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Simple Subscriber
	nc.Subscribe("inpktinsec", func(m *nats.Msg) {
		//fmt.Printf("Received a message: %s\n", string(m.Data))
		// Process the incoming ethernet packet here
		processEthernetPacket(nc, m.Subject, m.Data)
	})

	// Keep the connection alive
	select {}
}
