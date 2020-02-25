package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ReverseTraceroute performs traditional traceroute
func ReverseTraceroute(destIP net.IP, tc TransportChannel) error {
	log.Printf("Doing reverse traceroute from %s", destIP)
	done := make(chan error)
	found := make(chan uint8)

	sourceIP, err := findLocalIP()
	if err != nil {
		return err
	}

	go func() {
		for packet := range tc.Rx() {

			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(sourceIP) {
				// log.Printf("%s -> %s  %s", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
				hostname, err := net.LookupAddr(ip4.SrcIP.String())
				if err != nil {
					log.Println(ip4.SrcIP)
				} else {
					log.Printf("%s", hostname)
				}
				found <- ip4.TTL
			} else if int(icmp.TypeCode) == icmpEchoRequest && ip4.SrcIP.Equal(destIP) {
				// log.Printf("%s -> %s  %s", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
				hostname, err := net.LookupAddr(ip4.DstIP.String())
				if err != nil {
					log.Println(ip4.DstIP)
				} else {
					log.Printf("%s", hostname)
				}
				found <- ip4.TTL
				done <- nil
			}
		}
	}()

	go func() {
		for ttl := 0; ttl <= 64; ttl++ {
			payload := []byte{'H', 'e', 'l', 'l', 'o'}

			roundTripBuf := gopacket.NewSerializeBuffer()
			farendBuf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
			}

			// outer ip in ip header (layer 3) https://tools.ietf.org/html/rfc2003#section-3
			ipipLength := uint16(ipHeaderLen + ipHeaderLen + icmpHeaderLen + len(payload))
			ipipLayer := buildIPIPLayer(sourceIP, destIP, ipipLength)

			// inner ip header (layer 3) https://tools.ietf.org/html/rfc791#section-3.1
			ipLength := uint16(ipHeaderLen + icmpHeaderLen + len(payload))
			roundTripIPLayer := buildIPv4ICMPLayer(sourceIP, sourceIP, ipLength, uint8(ttl))

			farendIPLayer := buildIPv4ICMPLayer(destIP, sourceIP, ipLength, uint8(ttl+1))

			// inner icmp header (layer 4) https://tools.ietf.org/html/rfc792#page-4
			icmpLayer := &layers.ICMPv4{
				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
				Seq:      1,
			}

			err = gopacket.SerializeLayers(roundTripBuf, opts,
				ipipLayer,
				roundTripIPLayer,
				icmpLayer,
				gopacket.Payload(payload),
			)
			if err != nil {
				done <- err
			}
			roundTripPacketData := roundTripBuf.Bytes()

			err = gopacket.SerializeLayers(farendBuf, opts,
				ipipLayer,
				farendIPLayer,
				icmpLayer,
				gopacket.Payload(payload),
			)
			if err != nil {
				done <- err
			}
			farEndPacketData := farendBuf.Bytes()

			err = tc.SendTo(roundTripPacketData, destIP)
			if err != nil {
				done <- err
			}

			err = tc.SendTo(farEndPacketData, destIP)
			if err != nil {
				done <- err
			}

			<-found
		}
	}()

	err = <-done
	return err
}
