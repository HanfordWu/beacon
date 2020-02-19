package main

import (
	"net"

	"github.com/google/gopacket/layers"
)

func buildIPIPLayer(sourceIP, destIP net.IP, totalLength uint16) *layers.IPv4 {
	ipipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   totalLength,
		Flags:    layers.IPv4DontFragment,
		TTL:      255,
		Protocol: layers.IPProtocolIPv4,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipipLayer
}

func buildIPv4ICMPLayer(sourceIP, destIP net.IP, totalLength uint16, ttl uint8) *layers.IPv4 {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   totalLength,
		Flags:    layers.IPv4DontFragment,
		TTL:      ttl,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    destIP,
		DstIP:    sourceIP,
	}

	return ipLayer
}