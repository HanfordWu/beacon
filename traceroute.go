package main

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Traceroute performs traditional traceroute
func Traceroute(destAddr net.IP, tc TransportChannel) error {
	log.Printf("Doing traceroute to %s", destAddr)
	done := make(chan error)
	found := make(chan uint8)

	sourceIP, err := findSourceIP()
	if err != nil {
		return err
	}

	go func() {
		for packet := range tc.Rx() {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			if icmpLayer == nil {
				continue
			}
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				continue
			}

			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if int(icmp.TypeCode) == icmpTTLExceeded && bytes.Equal(ip4.DstIP, sourceIP) {
				log.Printf("%s -> %s  %s", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
				found <- ip4.TTL
			} else if icmp.TypeCode == icmpEchoReply {
				if ip4.DstIP.Equal(sourceIP) && ip4.SrcIP.Equal(destAddr) {
					log.Printf("%s -> %s  %s", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
					found <- ip4.TTL
					done <- nil
				}
			}
		}
	}()

	go func() {
    	for ttl := 0; ttl <= 32; ttl++ {
    	    payload := []byte{'H', 'e', 'l', 'l', 'o'}
    
    	    buf := gopacket.NewSerializeBuffer()
    	    opts := gopacket.SerializeOptions{
    	    	ComputeChecksums: true,
    	    }
    
    	    // inner ip header (layer 3) https://tools.ietf.org/html/rfc791#section-3.1
    	    ipLength := uint16(ipHeaderLen + icmpHeaderLen + len(payload))
    	    ipLayer := buildIPv4ICMPLayer(sourceIP, destAddr, ipLength, uint8(ttl))
    
    	    // inner icmp header (layer 4) https://tools.ietf.org/html/rfc792#page-4
    	    icmpLayer := &layers.ICMPv4{
    	    	TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
    	    	Seq:      1,
    	    }
    
    	    err = gopacket.SerializeLayers(buf, opts,
    	    	ipLayer,
    	    	icmpLayer,
                gopacket.Payload(payload),
    	    )
    	    if err != nil {
				done <- err
    	    }
    	    packetData := buf.Bytes()
    
    	    err = tc.SendTo(packetData, destAddr)
    	    if err != nil {
    			done <- err
    		}
    
    		<- found
    	}
	}()

	err = <- done
	return err
}