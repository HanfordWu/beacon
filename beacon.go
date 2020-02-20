package main

import (
	"log"
	"net"
)

const (
	ipHeaderLen   = 20
	icmpHeaderLen = 8
  
	eth0DeviceName = "eth0"

	icmpTTLExceeded = 2816
	icmpEchoRequest = 2048
	icmpEchoReply   = 0
)

func main() {
	// destIP := net.IPv4(104, 44, 227, 112)
	destIP := net.IPv4(207, 46, 33, 149)

	tc, err := NewTransportChannel()
	if err != nil {
		log.Fatalf("Failed to create new TransportChannel: %s", err)
	}

	err = Traceroute(destIP, *tc)
	if err != nil {
		log.Fatalf("Traceroute failed: %s", err)
	}

	err = ReverseTraceroute(destIP, *tc)
	if err != nil {
		log.Fatalf("ReverseTraceroute failed: %s", err)
	}
}
