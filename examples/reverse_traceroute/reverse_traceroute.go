package main

import (
	"fmt"
	"log"
	"os"
	"net"

	"github.com/trstruth/beacon"
)

func main() {
	destIP := net.ParseIP(os.Args[1])

	tc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("icmp"))
	if err != nil {
		log.Fatal(err)
	}

	err = ReverseTraceroute(destIP, *tc)
	if err != nil {
		log.Fatal(err)
	}
}

// ReverseTraceroute uses IP in IP to perform traceroute from the remote back to the caller
func ReverseTraceroute(destIP net.IP, tc beacon.TransportChannel) error {
	fmt.Printf("Doing traceroute to %s", destIP)

	pc, err := beacon.GetPathChannelFrom(destIP, tc)
	if err != nil {
		return err
	}

	for hop := range pc {
		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hostname)
		} else {
			fmt.Println(hop.String())
		}
	}

	return nil
}
