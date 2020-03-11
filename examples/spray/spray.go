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
	srcIP := net.ParseIP(os.Args[1])
	destIP := net.ParseIP(os.Args[2])
	tc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("icmp"))
	if err != nil {
		log.Fatal(err)
	}
	pathChan, err := beacon.GetPathChannelFromSourceToDest(srcIP, destIP, *tc)
	if err != nil {
		log.Fatal(err)
	}
	for hop := range pathChan {
		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hop.String())
		} else {
			fmt.Println(hostname[0])
		}
	}
	fmt.Println("DONE")

	path, err := beacon.GetPathFromSourceToDest(srcIP, destIP, *tc)
	if err != nil {
		log.Fatal(err)
	}

	vantageIP, err := beacon.FindLocalIP()
	if err != nil {
		log.Fatal(err)
	}

	path = append([]net.IP{vantageIP}, path...)

	// sprayTc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("ip proto 4"))
	if err != nil {
		log.Fatal(err)
	}

	// path = []net.IP{net.IP{10, 20, 30, 96}, net.IP{104,44,0,230}}
	fmt.Printf("Starting spray over path %v\n", path)
	for _, hop := range path {
		hostname, err := net.LookupAddr(hop.String())
		if err != nil {
			fmt.Println(hop.String())
		} else {
			fmt.Println(hostname[0])
		}
	}
	/*
	err = spray(path, sprayTc)
	if err != nil {
		log.Fatal(err)
	}
	*/
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
				fmt.Printf("%s -> %s: %s\n", path[1], path[0], udp.Payload)
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
