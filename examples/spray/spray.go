package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	done := make(chan error)

	go func() {
		for packet := range tc.Rx() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			udp, _ := udpLayer.(*layers.UDP)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if ip4.DstIP.Equal(path[0]) && ip4.SrcIP.Equal(path[1]) {
				fmt.Printf("%s -> %s: %s\n", path[0], path[1], udp.Payload)
				done <- nil
			}
		}
	}()

	fmt.Println("sending packet")
	err = tc.SendToPath(buf.Bytes(), path)
	if err != nil {
		return err
	}

	return <-done
}
