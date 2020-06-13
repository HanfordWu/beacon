package main

import (
	"fmt"
	"net"

	"github.com/trstruth/beacon"
)

// Traceroute performs traditional traceroute
func Traceroute(destIP net.IP, timeout int) error {
	destHostname, err := net.LookupAddr(destIP.String())
	if err != nil {
		fmt.Printf("Doing traceroute to %s\n", destIP)
	} else {
		fmt.Printf("Doing traceroute to %s (%s)\n", destHostname[0], destIP)
	}

	if interfaceDevice == "" {
		discoveredOutboundInterface, err := beacon.GetInterfaceDeviceFromDestIP(destIP)
		if err != nil {
			return fmt.Errorf("Failed to find an interface for %s: %s, explicitly provide an interface with -i", destIP.String(), err)
		}
		interfaceDevice = discoveredOutboundInterface
	}

	tc, err := beacon.NewTransportChannel(
		beacon.WithBPFFilter("icmp"),
		beacon.WithInterface(interfaceDevice),
	)
	if err != nil {
		return fmt.Errorf("Error creating transport channel: %s", err)
	}
	pc, err := tc.GetPathChannelTo(destIP, timeout)
	if err != nil {
		return err
	}

	hopIdx := 1
	for hop := range pc {
		fmt.Printf("%d: ", hopIdx)
		hopIdx++

		if hop == nil {
			fmt.Println("*")
			continue
		}

		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hop.String())
		} else {
			fmt.Printf("%s (%s)\n", hostname[0], hop.String())
		}
	}

	return nil
}
