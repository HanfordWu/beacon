package beacon

import (
	"net"

	"github.com/google/gopacket"
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
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipLayer
}

func buildICMPTraceroutePacket(sourceIP, destIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	ipLength := uint16(ipHeaderLen + icmpHeaderLen + len(payload))
	ipLayer := buildIPv4ICMPLayer(sourceIP, destIP, ipLength, ttl)

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      1,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}
	return nil
}

func buildEncapTraceroutePacket(outerSourceIP, outerDestIP, innerSourceIP, innerDestIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	ipipLength := uint16(ipHeaderLen + ipHeaderLen + icmpHeaderLen + len(payload))
	ipipLayer := buildIPIPLayer(outerSourceIP, outerDestIP, ipipLength)

	ipLength := uint16(ipHeaderLen + icmpHeaderLen + len(payload))
	ipLayer := buildIPv4ICMPLayer(innerSourceIP, innerDestIP, ipLength, ttl)

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      1,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipipLayer,
		ipLayer,
		icmpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}
	return nil
}
