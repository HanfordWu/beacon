package main

import (
	"fmt"
	"net"

	"github.com/trstruth/beacon"
)

// Traceroute performs traditional traceroute
func Traceroute(destIP net.IP) error {
	destHostname, err := net.LookupAddr(destIP.String())
	if err != nil {
		fmt.Printf("Doing traceroute to %s\n", destIP)
	} else {
		fmt.Printf("Doing traceroute to %s (%s)\n", destHostname[0], destIP)
	}

	tc, err := beacon.NewTransportChannel(
		beacon.WithBPFFilter("icmp"),
		beacon.WithInterface(interfaceDevice),
	)
	if err != nil {
		return fmt.Errorf("Error creating transport channel: %s", err)
	}
	pc, err := tc.GetPathChannelTo(destIP)
	if err != nil {
		return err
	}

	for hop := range pc {
		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hop.String())
		} else {
			fmt.Printf("%s (%s)\n", hostname[0], hop.String())
		}
	}

	return nil
}
