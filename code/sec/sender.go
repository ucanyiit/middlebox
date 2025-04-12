package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func udpSender() {
	host := os.Getenv("INSECURENET_HOST_IP")
	port := 8888
	message := "Hello, InSecureNet!"

	if host == "" {
		fmt.Println("SECURENET_HOST_IP environment variable is not set.")
		return
	}

	// Resolve the address
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("Error resolving address: %s\n", err)
		return
	}

	// Create a UDP socket
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Printf("Error dialing UDP: %s\n", err)
		return
	}
	defer conn.Close()

	for {
		// Send message to the server
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error sending message: %s\n", err)
			return
		}
		fmt.Printf("Message sent to %s:%d\n", host, port)

		// Receive response from the server
		buffer := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("Error receiving response: %s\n", err)
			return
		}
		fmt.Printf("Response from server: %s\n", string(buffer[:n]))

		// Sleep for 1 second
		time.Sleep(1 * time.Second)
	}
}

func main() {
	udpSender()
}
