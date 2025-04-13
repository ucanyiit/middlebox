package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func handleEndSignal(sequenceNumber int) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	endSignalReceived = true
	lastSequenceNumber = sequenceNumber
}

func handleChunk(hexChunk string, sequenceNumber int) {
	// Decode the hex chunk
	decodedChunk, err := hex.DecodeString(hexChunk)
	if err != nil {
		fmt.Printf("Invalid hex chunk '%s' in query: %d (Error: %v)\n", hexChunk, sequenceNumber, err)
		return // Ignore this malformed query part
	}

	mapMutex.Lock()
	defer mapMutex.Unlock()

	// Store the decoded chunk
	// Check if we already have this chunk (simple duplicate handling)
	if _, exists := receivedChunks[sequenceNumber]; !exists {
		receivedChunks[sequenceNumber] = decodedChunk
		fmt.Printf("Stored chunk: Seq=%d, Size=%d bytes", sequenceNumber, len(decodedChunk))
	} else {
		fmt.Printf("Duplicate chunk received: Seq=%d", sequenceNumber)
	}
}

func handleTXTDNSQuestion(q dns.Question) {
	if q.Qtype != dns.TypeTXT {
		return
	}

	// Split the q.name part by '.'
	// Example: "48656c6c6f.0" -> ["48656c6c6f", "0"]
	parts := strings.Split(q.Name, ".")

	// Expecting 2 parts: [hex_chunk] and [sequence_number]
	// Or the end signal: ["end", sequence_number]

	// Check if we have exactly 3 parts (hex_chunk, sequence_number, and empty string)
	if len(parts) != 3 {
		fmt.Printf("Ignoring query with unexpected format: %s\n", q.Name)
		return
	}

	hexChunk := parts[0]
	seqStr := parts[1]

	// Convert sequence number string to integer
	sequenceNumber, err := strconv.Atoi(seqStr)
	if err != nil {
		fmt.Printf("Invalid sequence number '%s' in query: %s\n", seqStr, q.Name)
		return // Ignore this malformed query part
	}

	// Check for the end signal
	if hexChunk == "end" {
		handleEndSignal(sequenceNumber)
	} else {
		handleChunk(hexChunk, sequenceNumber)
	}

	if endSignalReceived && allSequencesReceived(lastSequenceNumber) {
		go reassembleAndPrintMessage() // Run in goroutine to not block handler
	}
}
