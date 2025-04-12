package main

import (
	"fmt"
	"net"
	"os"
)

func startUDPListener() error {
	// Listen for incoming UDP packets on port 8888
	addr, err := net.ResolveUDPAddr("udp", ":8888")
	if err != nil {
		return fmt.Errorf("error resolving UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("error listening on UDP: %w", err)
	}
	defer conn.Close()

	fmt.Println("UDP listener started on port 8888")

	buffer := make([]byte, 4096)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			continue
		}

		fmt.Printf("Received %d bytes from %s\n", n, remoteAddr)
		fmt.Println(string(buffer[:n]))

		// Respond to the sender
		message := "Hi SecureNet!"
		sent, err := conn.WriteToUDP([]byte(message), remoteAddr)
		if err != nil {
			fmt.Println("Error sending response:", err)
			continue
		}

		fmt.Printf("Sent %d bytes back to %s\n", sent, remoteAddr)
	}
}

func main() {
	if err := startUDPListener(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}
