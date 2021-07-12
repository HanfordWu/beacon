package beacon

import (
	"fmt"
	"net"
)

// Traceroute between specified source and destination devices
// sourceIP needs to be provided if source device is in a different Autonomous System and source IP cannot be determined automatically
func Traceroute(destinationIP string, sourceIP string, timeout int, interfaceDevice string) ([]string, error) {

	var destIP net.IP = net.ParseIP(destinationIP)

	filter := "icmp"
	if destIP.To4() == nil {
		filter = "icmp6"
	}

	route := make([]string, 0)

	destHostname, err := net.LookupAddr(destIP.String())
	if err != nil {
		log.Printf("Doing traceroute to %s\n", destIP)
	} else {
		log.Printf("Doing traceroute to %s (%s)\n", destHostname[0], destIP)
	}

	if interfaceDevice == "" {
		discoveredOutboundInterface, err := GetInterfaceDeviceFromDestIP(destIP)
		if err != nil {
			return nil, fmt.Errorf("Failed to find an interface for %s: %s, explicitly provide an interface with -i", destIP.String(), err)
		}
		interfaceDevice = discoveredOutboundInterface
	}

	tc, err := NewTransportChannel(
		WithBPFFilter(filter),
		WithHasher(V4TraceRouteHasher{}),
		WithHasher(V6TraceRouteHasher{}),
		WithInterface(interfaceDevice),
		WithTimeout(100),
	)
	if err != nil {
		return nil, fmt.Errorf("Error creating transport channel: %s", err)
	}

	var srcIP net.IP = nil
	if len(sourceIP) > 0 {
		srcIP = net.ParseIP(sourceIP)
	} else {
		srcIP, _ = FindSourceIPForDest(destIP)
	}

	pc, err := tc.GetPathChannelTo(destIP, srcIP, timeout)
	if err != nil {
		return nil, err
	}

	hopIdx := 1
	for hop := range pc {
		log.Printf("%d: ", hopIdx)
		hopIdx++

		if hop == nil {
			log.Println("*")
			route = append(route, "*")
			continue
		}

		var hostname = "Unknown"
		hostnames, err := net.LookupAddr(hop.String())
		if err == nil && len(hostnames) > 0 {
			hostname = hostnames[0]
		}
		fmt.Printf("%s (%s)\n", hostname, hop.String())
		route = append(route, fmt.Sprintf("%s (%s)\n", hostname, hop.String()))
	}

	return route, nil
}
