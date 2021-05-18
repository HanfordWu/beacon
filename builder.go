package beacon

import (
	"errors"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildIPv4EncapLayer(sourceIP, destIP net.IP) *layers.IPv4 {
	if sourceIP == nil {
		sourceIP = net.IPv4(uint8(rand.Intn(64)), uint8(rand.Intn(256)), uint8(rand.Intn(256)), uint8(rand.Intn(256)))
	}

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

func buildIPv6EncapLayer(sourceIP, dstIP net.IP) *layers.IPv6 {
	ipipv6Layer := &layers.IPv6{
		Version:      6,
		HopLimit:     64,
		SrcIP:        sourceIP,
		DstIP:        dstIP,
		NextHeader:   layers.IPProtocolIPv6,
		FlowLabel:    0,
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
		SrcIP:        sourceIP,
		DstIP:        destIP,
		NextHeader:   layers.IPProtocolICMPv6,
		HopLimit:     hopLimit,
		Version:      6,
		FlowLabel:    0,
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
		Id:       109,
	}

	return ipLayer
}

func buildIPv6UDPLayer(sourceIP, destIP net.IP, hopLimit uint8) *layers.IPv6 {
	ipV6Layer := &layers.IPv6{
		Version:    6,
		HopLimit:   hopLimit,
		SrcIP:      sourceIP,
		DstIP:      destIP,
		NextHeader: layers.IPProtocolUDP,
	}

	return ipV6Layer
}

func BuildICMPTraceroutePacket(sourceIP, destIP net.IP, ttl_hoplimit uint8, payload []byte, buf gopacket.SerializeBuffer, seqNumber, identifier uint16) error {
	var err error
	if sourceIP.To4() != nil {
		err = buildICMPv4TraceroutePacket(sourceIP, destIP, ttl_hoplimit, payload, buf, seqNumber, identifier)
	} else {
		err = buildICMPv6TraceroutePacket(sourceIP, destIP, ttl_hoplimit, payload, buf, seqNumber, identifier)
	}
	return err
}

func buildICMPv4TraceroutePacket(sourceIP, destIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer, seqNumber, identifier uint16) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipLayer := buildIPv4ICMPLayer(sourceIP, destIP, ttl)

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      seqNumber,
		Id:       identifier,
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

func buildICMPv6TraceroutePacket(sourceIP, destIP net.IP, hopLimit uint8, payload []byte, buf gopacket.SerializeBuffer, seqNumber, identifier uint16) error {
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
		Identifier: identifier,
		SeqNumber:  seqNumber,
	}

	err := gopacket.SerializeLayers(buf, opts, ipLayer, icmpLayer, icmpEchoLayer, gopacket.Payload(payload))
	if err != nil {
		return err
	}
	return nil
}

func buildUDPTraceroutePacket(sourceIP, destIP net.IP, sourcePort, destPort layers.UDPPort, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	serializableLayers := make([]gopacket.SerializableLayer, 3)

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	udpLayer := &layers.UDP{
		SrcPort: sourcePort,
		DstPort: destPort,
	}

	if destIP.To4() != nil {
		ipLayer := buildIPv4UDPLayer(sourceIP, destIP, ttl)
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
		serializableLayers[0] = ipLayer
	} else {
		ipLayer := buildIPv6UDPLayer(sourceIP, destIP, ttl)
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
		serializableLayers[0] = ipLayer
	}

	serializableLayers[1] = udpLayer
	serializableLayers[2] = gopacket.Payload(payload)

	err := gopacket.SerializeLayers(buf, opts, serializableLayers...)

	return err
}

func buildEncapTraceroutePacket(outerSourceIP, outerDestIP, innerSourceIP, innerDestIP net.IP, ttl uint8, payload []byte, buf gopacket.SerializeBuffer) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipipLayer := buildIPv4EncapLayer(outerSourceIP, outerDestIP)
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
			constructedLayers[idx] = buildIPv4EncapLayer(nil, hopB)
			constructedLayers[numLayers-idx-1] = buildIPv4EncapLayer(hopB, hopA)
		} else {
			constructedLayers[idx] = buildIPv6EncapLayer(hopA, hopB)
			constructedLayers[numLayers-idx-1] = buildIPv6EncapLayer(hopB, hopA)
		}
	}

	udpLayer := &layers.UDP{
		SrcPort: 25199,
		DstPort: 28525,
		Length:  uint16(udpHeaderLen + len(payload)),
	}

	if path[0].To4() != nil {
		ipLayer := buildIPv4UDPLayer(path[1], path[0], 255)
		constructedLayers[len(constructedLayers)-1] = ipLayer // overwrite the last encap layer
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
	} else {
		ipLayer := buildIPv6UDPLayer(path[1], path[0], 255)
		constructedLayers[len(constructedLayers)-1] = ipLayer
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

// generateRandomUDPPort generates a UDPPort in the range (0, 65535)
func generateRandomUDPPort() layers.UDPPort {
	generatedPort := udpMinPort + rand.Intn(udpMaxPort-udpMinPort)
	return layers.UDPPort(generatedPort)
}
