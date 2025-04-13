package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// --- State for receiving covert data ---
var (
	// Map to store received data chunks: sequence number -> decoded data
	receivedChunks = make(map[int][]byte)
	// Mutex to protect access to receivedChunks map
	mapMutex = &sync.Mutex{}
	// Is end signal received?
	endSignalReceived = false
	// Last sequence number received
	lastSequenceNumber = -1
)

// reassembleAndPrintMessage sorts the collected chunks and prints the message.
func reassembleAndPrintMessage() {
	mapMutex.Lock() // Lock map for reading
	defer mapMutex.Unlock()

	if len(receivedChunks) == 0 {
		fmt.Println("Reassembly triggered, but no chunks received.")
		return
	}

	// Reconstruct the message
	var messageBuffer bytes.Buffer
	fmt.Printf("--- Reassembling Message --- %d chunks received, %d last\n", len(receivedChunks), lastSequenceNumber)
	for i := 0; i < lastSequenceNumber; i++ {
		chunkData, ok := receivedChunks[i]
		if !ok {
			// Should not happen if map access is correct, but good practice
			fmt.Printf("Warning: Missing chunk for sequence number %d during reassembly\n", i)
			continue
		}
		fmt.Printf("Appending chunk %d (%d bytes)\n", i, len(chunkData))
		messageBuffer.Write(chunkData)
	}
	fmt.Println("--- Reassembly Complete ---")

	fmt.Printf("\n>>> Received Covert Message: %s\n\n", messageBuffer.String())

	// Clear the map for the next potential message
	receivedChunks = make(map[int][]byte) // Reset map
	endSignalReceived = false             // Reset end signal
	fmt.Println("Chunk map cleared for next message.")
}

func allSequencesReceived(lastSequence int) bool {
	mapMutex.Lock()
	defer mapMutex.Unlock()
	// Check if all sequences from 0 to lastSequence are received
	for i := 0; i < lastSequence; i++ {
		if _, exists := receivedChunks[i]; !exists {
			fmt.Printf("Missing chunk for sequence number %d\n", i)
			return false // Found a missing sequence
		}
	}

	return true
}

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

// handleTXTDNSRequest processes incoming DNS queries.
func handleTXTDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Print("Received DNS request...\n")
	m := new(dns.Msg)
	m.SetReply(r)      // Prepare a basic reply structure
	m.Compress = false // Disable compression for simplicity/compatibility

	// We only care about standard queries
	if r.Opcode != dns.OpcodeQuery {
		w.WriteMsg(m) // Send empty reply for non-queries
		return
	}

	// Process each question in the query (usually just one)
	for _, q := range r.Question {
		fmt.Printf("Received query: Name=[%s], Type=[%s]\n", q.Name, dns.TypeToString[q.Qtype])

		// --- Covert Channel Logic ---
		// Check if it's a TXT query for our base domain
		if q.Qtype == dns.TypeTXT {
			// Extract the subdomain part before the base domain
			// Example: "48656c6c6f.0.covert.example.com." -> "48656c6c6f.0"
			subdomainPart := strings.TrimSuffix(q.Name, "."+BASE_DOMAIN+".")

			// Split the subdomain part by '.'
			// Example: "48656c6c6f.0" -> ["48656c6c6f", "0"]
			parts := strings.Split(subdomainPart, ".")

			// Expecting 2 parts: [hex_chunk] and [sequence_number]
			// Or the end signal: ["end", sequence_number]

			// Check if we have exactly 2 parts
			if len(parts) == 2 {
				hexChunk := parts[0]
				seqStr := parts[1]

				// Convert sequence number string to integer
				sequenceNumber, err := strconv.Atoi(seqStr)
				if err != nil {
					fmt.Printf("Invalid sequence number '%s' in query: %s\n", seqStr, q.Name)
					continue // Ignore this malformed query part
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
			} else {
				fmt.Printf("Ignoring query with unexpected format: %s\n", q.Name)
			}
		} // End covert channel check
	} // End loop through questions

	// Send a response back to the client.
	err := w.WriteMsg(m)
	if err != nil {
		// Log error if writing the response fails
		fmt.Printf("Error writing DNS response: %v\n", err)
	}
}
