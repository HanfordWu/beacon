package main

import (
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

	tc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("icmp"))
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

	return tc.SendToPath(buf.Bytes(), path)
}
