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

func buildUDPLayer(sourceIP, destIP net.IP) *layers.IPv4 {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Flags:    layers.IPv4DontFragment,
		TTL:      255,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	return ipLayer
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

		constructedLayers[idx] = buildIPIPLayer(hopA, hopB)
		constructedLayers[numLayers-idx-1] = buildIPIPLayer(hopB, hopA)
	}

	ipLayer := buildUDPLayer(path[1], path[0])
	constructedLayers = append(constructedLayers, ipLayer)

	udpLayer := &layers.UDP{
		SrcPort: 25199,
		DstPort: 28525,
		Length:  uint16(udpHeaderLen + len(payload)),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)
	constructedLayers = append(constructedLayers, udpLayer)
	constructedLayers = append(constructedLayers, gopacket.Payload(payload))

	err := gopacket.SerializeLayers(buf, opts, constructedLayers...)
	if err != nil {
		return err
	}
	return nil
}
