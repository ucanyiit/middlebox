package main

import (
	"fmt"

	"github.com/miekg/dns"
)

// inverse map
var DNS_TYPE_MAP_INVERSE = map[any]int{
	dns.TypeA:     0,
	dns.TypeNS:    1,
	dns.TypeSOA:   2,
	dns.TypeAAAA:  3,
	dns.TypeCNAME: 4,
}

func combineReceivedChunks() {
	mapMutex.Lock()
	defer mapMutex.Unlock()

	fmt.Println("Combining received chunks...")
	// Combine the received chunks into a single byte
	newReceivedChunks := make(map[int][]byte)
	for i := 0; i < currentSequenceNumber; i += 4 {
		newByte := 0 // Initialize new byte
		for j := 3; j >= 0; j -= 1 {
			if i+j < currentSequenceNumber {
				// Get the received 2 bits from the DNS question type
				receivedByte := receivedChunks[i+j]
				// Convert the byte slice to an int
				receivedByteNumber := int(receivedByte[0])

				// Shift the bits to the left and add the new bits
				newByte = (newByte << 2) | receivedByteNumber
			} else {
				break // No more chunks to combine
			}
		}

		fmt.Printf("Combining chunks %d to %d into byte: %v\n", i, i+3, newByte)
		newReceivedChunks[i/4] = []byte{byte(newByte)}
	}
	// Clear the old received chunks
	receivedChunks = make(map[int][]byte)
	// Add the new received chunks
	for i, chunk := range newReceivedChunks {
		receivedChunks[i] = chunk
	}
	fmt.Println("Received chunks combined.")

	lastSequenceNumber = currentSequenceNumber / 4
	currentSequenceNumber = 0
}

func handleTypedDNSQuestion(q dns.Question) {
	if q.Qtype == dns.TypeCNAME {
		combineReceivedChunks()
		fmt.Println("End marker received, reassembling message...")
		go reassembleAndPrintMessage() // Run in goroutine to not block handler
	} else {
		// Get the received 2 bits from the DNS question type
		receivedByte := DNS_TYPE_MAP_INVERSE[q.Qtype]
		fmt.Printf("Received byte: %d\n", receivedByte)

		bit0 := (receivedByte >> 1) & 1
		bit1 := receivedByte & 1

		handleBitsChunk(bit0, bit1, currentSequenceNumber)
		mapMutex.Lock()
		currentSequenceNumber++
		mapMutex.Unlock()
	}
}
