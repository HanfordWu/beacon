package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/trstruth/beacon"
)

func main() {
	destIP := net.ParseIP(os.Args[1])
	sourceIP, err := beacon.FindLocalIP()
	if err != nil {
		log.Fatal(err)
	}
	path := []net.IP{sourceIP, destIP}

	tc, err := beacon.NewTransportChannel()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Starting spray over path %v\n", path)
	err = spray(path, tc)
	if err != nil {
		log.Fatal(err)
	}
}

func spray(path beacon.Path, tc *beacon.TransportChannel) error {
	payload := []byte("boomerang mode")
	buf := gopacket.NewSerializeBuffer()

	err := beacon.CreateRoundTripPacketForPath(path, payload, buf)
	if err != nil {
		return err
	}
	fmt.Printf("sending packet: %v to path: %v\n", buf.Bytes(), path)

	return tc.SendToPath(buf.Bytes(), path)
}
