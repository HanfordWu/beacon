package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Path is a slice of IPs which represents a path through the network
type Path []net.IP

// PathChannel is the channel version of a Path
type PathChannel chan net.IP

// GetPathTo returns a Path to a destination IP from the caller
func GetPathTo(destIP net.IP, tc TransportChannel) (Path, error) {
	path := make(Path, 0)

	done := make(chan error)
	found := make(chan uint8)

	sourceIP, err := findLocalIP()
	if err != nil {
		return path, err
	}

	go func() {
		buf := gopacket.NewSerializeBuffer()

		var ttl uint8
		for ttl = 0; ttl <= 32; ttl++ {
			err = buildICMPTraceroutePacket(sourceIP, destIP, ttl, []byte("Hello"), buf)
			if err != nil {
				done <- err
			}
			tc.SendTo(buf.Bytes(), destIP)
			<-found
		}
	}()

	go func() {
		for packet := range tc.Rx() {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			// fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(sourceIP) {
				path = append(path, ip4.SrcIP)
				found <- ip4.TTL
			} else if int(icmp.TypeCode) == icmpEchoReply && ip4.SrcIP.Equal(destIP) {
				path = append(path, ip4.DstIP)
				found <- ip4.TTL
				done <- nil
			}
		}
	}()

	err = <-done
	if err != nil {
		return path, err
	}

	return path, nil
}

// GetPathFrom returns a Path from a destination IP back to the caller
func GetPathFrom(destIP net.IP, tc TransportChannel) (Path, error) {
	path := make(Path, 0)

	done := make(chan error)
	found := make(chan uint8)

	sourceIP, err := findLocalIP()
	if err != nil {
		return path, err
	}

	go func() {
		roundTripBuf := gopacket.NewSerializeBuffer()
		remoteProbeBuf := gopacket.NewSerializeBuffer()

		var ttl uint8
		for ttl = 0; ttl <= 32; ttl++ {
			err = buildEncapTraceroutePacket(sourceIP, destIP, sourceIP, sourceIP, ttl, []byte("Hello"), roundTripBuf)
			if err != nil {
				done <- err
			}
			err = buildEncapTraceroutePacket(sourceIP, destIP, destIP, sourceIP, ttl+1, []byte("Hello"), remoteProbeBuf)
			if err != nil {
				done <- err
			}
			tc.SendTo(roundTripBuf.Bytes(), destIP)
			tc.SendTo(remoteProbeBuf.Bytes(), destIP)
			<-found
		}
	}()

	go func() {
		for packet := range tc.Rx() {
			// TODO: consider using DecodingLayerParser https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			// fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(sourceIP) {
				path = append(path, ip4.SrcIP)
				found <- ip4.TTL
			} else if int(icmp.TypeCode) == icmpEchoRequest && ip4.SrcIP.Equal(destIP) {
				path = append(path, ip4.DstIP)
				found <- ip4.TTL
				done <- nil
			}
		}
	}()

	err = <-done
	if err != nil {
		return path, err
	}

	return path, nil
}

// GetPathFromSourceToDest returns a Path from a sourceIP to a destIP
func GetPathFromSourceToDest(sourceIP, destIP net.IP, tc TransportChannel) (Path, error) {
	path := make([]net.IP, 0)

	found := make(chan uint8)
	done := make(chan error)

	localIP, err := findLocalIP()
	if err != nil {
		return path, err
	}
	if localIP.Equal(sourceIP) {
		return GetPathTo(destIP, tc)
	}
	if localIP.Equal(destIP) {
		return GetPathFrom(destIP, tc)
	}

	go func() {

		var ttl uint8
		for ttl = 0; ttl <= 32; ttl++ {
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
			}
			payload := []byte("Hello")

			gopacket.SerializeLayers(buf, opts,
				buildIPIPLayer(localIP, sourceIP, uint16((ipHeaderLen*2)+icmpHeaderLen+len(payload))),
				// buildIPIPLayer(sourceIP, destIP, uint16((ipHeaderLen * 2) + icmpHeaderLen + len(payload))),
				buildIPv4ICMPLayer(localIP, destIP, uint16(ipHeaderLen+icmpHeaderLen+len(payload)), ttl),
				&layers.ICMPv4{
					TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
					Seq:      1,
				},
				gopacket.Payload(payload),
			)

			tc.SendTo(buf.Bytes(), sourceIP)
			<-found
		}

	}()

	go func() {
		for packet := range tc.Rx() {
			// TODO: consider using DecodingLayerParser https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(localIP) {
				path = append(path, ip4.SrcIP)
				found <- ip4.TTL
			} else if int(icmp.TypeCode) == icmpEchoReply && ip4.SrcIP.Equal(destIP) {
				path = append(path, ip4.DstIP)
				found <- ip4.TTL
				done <- nil
			}
		}
	}()

	err = <-done
	if err != nil {
		return path, err
	}
	return path, nil
}
