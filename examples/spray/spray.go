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
	sourceIP, err := beacon.FindLocalIP()
	if err != nil {
		log.Fatal(err)
	}
	destIP := net.ParseIP(os.Args[1])
	path := []net.IP{sourceIP, destIP}
	fmt.Printf("Starting spray over path %v\n", path)

	tc, err := beacon.NewTransportChannel()
	if err != nil {
		log.Fatal(err)
	}

	spray(path, tc)
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
