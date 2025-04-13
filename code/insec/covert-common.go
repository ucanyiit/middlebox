package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
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
	// Current sequence number
	currentSequenceNumber = 0
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

func storeChunk(chunk []byte, sequenceNumber int) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	// Store the decoded chunk
	// Check if we already have this chunk (simple duplicate handling)
	if _, exists := receivedChunks[sequenceNumber]; !exists {
		receivedChunks[sequenceNumber] = chunk
		fmt.Printf("Stored chunk: Seq=%d, Size=%d bytes\n", sequenceNumber, len(chunk))
	} else {
		fmt.Printf("Duplicate chunk received: Seq=%d", sequenceNumber)
	}
}

func handleHexChunk(hexChunk string, sequenceNumber int) {
	// Decode the hex chunk
	decodedChunk, err := hex.DecodeString(hexChunk)
	if err != nil {
		fmt.Printf("Invalid hex chunk '%s' in query: %d (Error: %v)\n", hexChunk, sequenceNumber, err)
		return // Ignore this malformed query part
	}

	storeChunk(decodedChunk, sequenceNumber)
}

// bits can be 0 or 1
// bit0 and bit1 are the bits to be stored
func handleBitsChunk(bit0 int, bit1 int, sequenceNumber int) {
	// Convert bits to bytes
	decodedChunk := make([]byte, 1)
	decodedChunk[0] = byte((bit0 << 1) | bit1) // Combine bits into a byte

	storeChunk(decodedChunk, sequenceNumber)
}

func handleEndSignal(sequenceNumber int) {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	endSignalReceived = true
	lastSequenceNumber = sequenceNumber
}

func getCovertDNSRequestHandler(questionHandler func(q dns.Question)) func(w dns.ResponseWriter, r *dns.Msg) {
	return func(w dns.ResponseWriter, r *dns.Msg) {
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
			questionHandler(q) // Handle the question
		} // End loop through questions

		// Send a response back to the client.
		err := w.WriteMsg(m)
		if err != nil {
			// Log error if writing the response fails
			fmt.Printf("Error writing DNS response: %v\n", err)
		}
	}
}
