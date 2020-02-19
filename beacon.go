package main

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
        ipHeaderLen = 20
		icmpHeaderLen = 8
		eth0DeviceName = "eth0"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Failed to get device information from the host: %s", err)
	}

	var eth0Device pcap.Interface
	deviceFound := false
	for _, device := range devices {
		if device.Name == eth0DeviceName && len(device.Addresses) > 0 {
			deviceFound = true
			eth0Device = device
		}
	}
	if !deviceFound {
		log.Fatalf("Couldn't find a device named %s, or it did not have any addresses assigned to it", eth0DeviceName)
	}

	sourceIP := eth0Device.Addresses[0].IP
	destIP := net.IPv4(104, 44, 227, 112)

	tc, err := NewTransportChannel()
	if err != nil {
		log.Fatalf("Failed to create new TransportChannel: %s", err)
	}

	go func() {
		for packet := range tc.Rx() {
			handlePacket(packet)
		}
	}()
	
	payload := []byte{'H', 'e', 'l', 'l', 'o'}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	// outer ip in ip header (layer 3) https://tools.ietf.org/html/rfc2003#section-3
	ipipLength := uint16(ipHeaderLen + ipHeaderLen + icmpHeaderLen + len(payload))
	ipipLayer := buildIPIPLayer(sourceIP, destIP, ipipLength)

	// inner ip header (layer 3) https://tools.ietf.org/html/rfc791#section-3.1
	ipLength := uint16(ipHeaderLen + icmpHeaderLen + len(payload))
	ipLayer := buildIPv4ICMPLayer(sourceIP, destIP, ipLength, 64)

	// inner icmp header (layer 4) https://tools.ietf.org/html/rfc792#page-4
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      1,
	}

	err = gopacket.SerializeLayers(buf, opts,
		ipipLayer,
		ipLayer,
		icmpLayer,
        gopacket.Payload(payload),
	)
	if err != nil {
		log.Fatalf("Error serializing packet: %s", err)
	}
	packetData := buf.Bytes()

	err = tc.SendTo(packetData, destIP)
	if err != nil {
		log.Fatalf("sendPacket failed with error: %s", err)
	}
	log.Printf("Successfully sent a packet: %v\n", packetData)

	done := make(chan bool)
	<- done
}

func handlePacket(p gopacket.Packet) {
	icmpLayer := p.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return
	}
	ipv4Layer := p.Layer(layers.LayerTypeIPv4)

	icmp, _ := icmpLayer.(*layers.ICMPv4)
	ip4, _ := ipv4Layer.(*layers.IPv4)
	log.Printf("%s -> %s  %s", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
}