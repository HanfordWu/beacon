package main

import (
	"log"
	"net"

	"github.com/trstruth/beacon"
)

func main() {
	// sourceIP := net.IP{104, 44, 227, 112}
	destIP := net.IP{207, 46, 33, 149}

	tc, err := NewTransportChannel(WithBPFFilter("icmp"))
	if err != nil {
		log.Fatalf("Failed to create new TransportChannel: %s", err)
	}

	err = Spray(destIP, *tc)
	if err != nil {
		log.Fatalf("Spray failed: %s", err)
	}
}
