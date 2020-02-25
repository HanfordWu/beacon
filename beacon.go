package main

import (
	"log"
	"net"
)

func main() {
	destIP := net.IPv4(207, 46, 33, 149)

	tc, err := NewTransportChannel(WithBPFFilter("icmp"))
	// tc, err := NewTransportChannel()
	if err != nil {
		log.Fatalf("Failed to create new TransportChannel: %s", err)
	}

	/*
		err = Traceroute(destIP, *tc)
		if err != nil {
			log.Fatalf("Traceroute failed: %s", err)
		}

		err = ReverseTraceroute(destIP, *tc)
		if err != nil {
			log.Fatalf("ReverseTraceroute failed: %s", err)
		}
	*/

	err = Spray(destIP, *tc)
	if err != nil {
		log.Fatalf("Spray failed: %s", err)
	}
}
