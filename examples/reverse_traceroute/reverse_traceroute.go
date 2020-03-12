package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/trstruth/beacon"
)

func main() {
	destIP := net.ParseIP(os.Args[1])

	err := ReverseTraceroute(destIP)
	if err != nil {
		log.Fatal(err)
	}
}

// ReverseTraceroute uses IP in IP to perform traceroute from the remote back to the caller
func ReverseTraceroute(destIP net.IP) error {
	destHostname, err := net.LookupAddr(destIP.String())
	if err != nil {
		fmt.Printf("Doing reverse traceroute from %s\n", destIP)
	} else {
		fmt.Printf("Doing reverse traceroute from %s (%s)\n", destHostname[0], destIP)
	}

	pc, err := beacon.GetPathChannelFrom(destIP)
	if err != nil {
		return err
	}

	for hop := range pc {
		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hop.String())
		} else {
			fmt.Println(hostname[0])
		}
	}

	return nil
}
