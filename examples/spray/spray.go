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
	tc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("icmp"))
	if err != nil {
		log.Fatal(err)
	}
	path, err := beacon.GetPathTo(destIP, *tc)
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
	fmt.Println("sending packet")

	return tc.SendToPath(buf.Bytes(), path)
}
