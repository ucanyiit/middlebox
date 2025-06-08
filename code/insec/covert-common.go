package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// Start Time for performance measurement (initially undefined, typed time.Time)
	startTime time.Time
	// Valid messages loaded from file
	validMessages []string
	// Flag to check if valid messages are loaded
	validMessagesLoaded = false
)

func getStatsFileName() string {
	args := os.Args
	typeArg := args[1]  // covert channel type
	filename := args[2] // covert channel data file
	waitBetween, _ := strconv.Atoi(args[3])

	return fmt.Sprintf("%s_%s_%d.txt", typeArg, filename, waitBetween)
}

func readFileToString(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func loadValidMessages() {
	if validMessagesLoaded {
		return // Already loaded
	}

	filename := os.Args[2]
	content, err := readFileToString(filename)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filename, err)
		return
	}

	// Split by newlines and filter out empty lines
	lines := strings.Split(content, "\n")
	validMessages = make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			validMessages = append(validMessages, trimmed)
		}
	}

	validMessagesLoaded = true
	fmt.Printf("Loaded %d valid messages from file\n", len(validMessages))
}

func checkCorrectnessOfMessage(message string) bool {
	loadValidMessages()

	trimmedMessage := strings.TrimSpace(message)

	for _, validMsg := range validMessages {
		if trimmedMessage == validMsg {
			fmt.Println("Correct message received!")
			return true
		}
	}

	fmt.Println("Incorrect message received!")
	return false
}

func writeStatsToFile(message string) {
	// Print the time taken for reassembly
	elapsedTime := time.Since(startTime)

	messages := []string{
		"--- Covert Channel Simulation ---",
		"Total size of message: " + fmt.Sprintf("%d bytes", len(message)),
		"Number of chunks received: " + fmt.Sprintf("%d", len(receivedChunks)),
		"Reassembly took: " + fmt.Sprintf("%dns", elapsedTime),
		"Correctness of message: " + fmt.Sprintf("%t", checkCorrectnessOfMessage(message)),
		"Message: " + message,
	}

	statsFileName := getStatsFileName()

	// Open the file for writing
	file, err := os.OpenFile(statsFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()
	// Write each message to the file
	for _, message := range messages {
		if _, err := file.WriteString(message + "\n"); err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			return
		}
	}
	fmt.Println("Statistics written to file:", statsFileName)
}

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

	writeStatsToFile(messageBuffer.String())

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

		mapMutex.Lock()
		if startTime == (time.Time{}) {
			// Initialize start time if not already set
			fmt.Printf("Start time not set, initializing...\n")
			startTime = time.Now()
		}
		mapMutex.Unlock()

		// We only care about standard queries
		if r.Opcode != dns.OpcodeQuery {
			w.WriteMsg(m) // Send empty reply for non-queries
			return
		}

		// Process each question in the query (usually just one)
		for _, q := range r.Question {
			fmt.Printf("Received query: Name=[%s], Type=[%s]\n", q.Name, dns.TypeToString[q.Qtype])

			// Check if this is normal traffic that should be ignored
			if strings.Contains(q.Name, NORMAL_TRAFFIC_DOMAIN) {
				fmt.Printf("Ignoring normal traffic query to: %s\n", q.Name)
				continue // Skip processing this query
			}

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
