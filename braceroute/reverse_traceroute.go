package main

import (
	"fmt"
	"net"

	"github.com/trstruth/beacon"
)

// ReverseTraceroute uses IP in IP to perform traceroute from the remote back to the caller
func ReverseTraceroute(destIP net.IP, timeout int) error {
	destHostname, err := net.LookupAddr(destIP.String())
	if err != nil {
		fmt.Printf("Doing reverse traceroute from %s\n", destIP)
	} else {
		fmt.Printf("Doing reverse traceroute from %s (%s)\n", destHostname[0], destIP)
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
		beacon.WithHasher(beacon.V4TraceRouteHasher{}),
		beacon.WithHasher(beacon.V6TraceRouteHasher{}),
		beacon.WithInterface(interfaceDevice),
	)
	if err != nil {
		return fmt.Errorf("Error creating transport channel: %s", err)
	}
	pc, err := tc.GetPathChannelFrom(destIP, timeout)
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
