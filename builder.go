package beacon

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildIPIPLayer(sourceIP, destIP net.IP) *layers.IPv4 {
	ipipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TTL:      255,
		Protocol: layers.IPProtocolIPv4,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipipLayer
}

func buildIPv6IPv6Layer(sourceIP, dstIP net.IP) *layers.IPPv6 {
	ipipv6Layer := &layers.IPv6{
            Version: uint8(6),
            HopLimit: uint8(64),
            SrcIP: addressStart,
            DstIP: addressEnd,
            NextHeader: layers.IPProtocolIPv6,
            FlowLabel: uint32(0),
            TrafficClass: uint8(0xc0),
    }

    return ipipv6Layer
}

func buildIPv4ICMPLayer(sourceIP, destIP net.IP, ttl uint8) *layers.IPv4 {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TTL:      ttl,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipLayer
}

func buildIPv6ICMPLayer(sourceIP, destIP net.IP, hopLimit uint8) *layers.IPv6 {
	ipV6Layer := &layers.IPv6{
        SrcIP: srcIPAddr,
        DstIP: dstIPAddr,
        NextHeader: layers.IPProtocolICMPv6,
        HopLimit: uint8(hopLimit),
        Version: uint8(6),
        FlowLabel: uint32(0),
        TrafficClass: uint8(0xc0),
    }

    return ipV6Layer
}

func buildIPv4UDPLayer(sourceIP, destIP net.IP, ttl uint8) *layers.IPv4 {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TTL:      ttl,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipLayer
}

func buildIPv6UDPLayer(sourceIP, destIP net.IP, hopLimit uint8) *layers.IPv6 {
	ipV6Layer := &layers.IPv6{
        Version: uint8(6),
        HopLimit: uint8(hopLimit),
        SrcIP: net.ParseIP(sourceIP),
        DstIP: net.ParseIP(destIP),
        NextHeader: layers.IPProtocolUDP,
        FlowLabel: uint32(0),
        TrafficClass: uint8(0xc0),
    }

    return ipV6Layer
}

func buildICMPTraceroutePacket(sourceIP, destIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipLayer := buildIPv4ICMPLayer(sourceIP, destIP, ttl)

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

func buildICMPV6TraceroutePacket(sourceIP, destIP net.IP, hopLimit uint8, payload []byte, buf gopacket.SerializeBuffer, seqNumber, identifier uint16) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipLayer := buildIPv6ICMPLayer(sourceIP, destIP, hopLimit)

	icmpLayer := &layers.ICMPv6{
        TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
    }
    icmpLayer.SetNetworkLayerForChecksum(ipLayer)
    icmpEchoLayer := &layers.ICMPv6Echo{
        Identifier: uint16(identifier),
        SeqNumber: seqNumber,
    }

    err = gopacket.SerializeLayers(buf, opts, ipLayer, icmpLayer, icmpEchoLayer, gopacket.Payload(payload)
    if err != nil {
    	return err
    }
    return nil
}

func buildUDPTraceroutePacket(sourceIP, destIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipLayer := buildIPv4UDPLayer(sourceIP, destIP, ttl)

	udpLayer := &layers.UDP{
		SrcPort: 53576,
		DstPort: 33437,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	err := gopacket.SerializeLayers(buf, opts,
		ipLayer,
		udpLayer,
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
		FixLengths:       true,
	}

	ipipLayer := buildIPIPLayer(outerSourceIP, outerDestIP)
	ipLayer := buildIPv4ICMPLayer(innerSourceIP, innerDestIP, ttl)

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

// CreateRoundTripPacketForPath builds an IP in IP packet which will perform roundtrip traversal over the hops in the given path
func CreateRoundTripPacketForPath(path Path, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if len(path) < 2 {
		return errors.New("Path must have atleast 2 hops")
	}

	numHops := len(path)
	numLayers := 2 * (numHops - 1)
	constructedLayers := make([]gopacket.SerializableLayer, numLayers)

	for idx := range path[:len(path)-1] {
		hopA := path[idx]
		hopB := path[idx+1]

		if hopA.To4() != nil {
			constructedLayers[idx] = buildIPIPLayer(hopA, hopB)
			constructedLayers[numLayers-idx-1] = buildIPIPLayer(hopB, hopA)
		} else {
			constructedLayers[idx] = buildIPv6IPv6Layer(hopA, hopB)
			constructedLayers[numLayers-idx-1] = buildIPv6IPv6Layer(hopB, hopA)
		}
	}

	udpLayer := &layers.UDP{
		SrcPort: 25199,
		DstPort: 28525,
		Length:  uint16(udpHeaderLen + len(payload)),
	}

	if path[0].To4() != nil {
		ipLayer := buildIPv4UDPLayer(path[1], path[0], 255)
		constructedLayers = append(constructedLayers, ipLayer)
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
	} else {
		ipLayer := buildIPv6UDPLayer(path[1], path[0], 255)
		constructedLayers = append(constructedLayers, ipLayer)
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
	}

	constructedLayers = append(constructedLayers, udpLayer)
	constructedLayers = append(constructedLayers, gopacket.Payload(payload))

	err := gopacket.SerializeLayers(buf, opts, constructedLayers...)
	if err != nil {
		return err
	}
	return nil
}
