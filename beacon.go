package main

import (
	"errors"
	"log"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
        ipHeaderLen = 20
        icmpHeaderLen = 8
)

func main() {
	sourceIP := net.IPv4(10, 20, 30, 96)
	destIP := net.IPv4(104, 44, 227, 112)
	
	payload := []byte{'H', 'e', 'l', 'l', 'o'}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	// outer ip in ip header (layer 3) https://tools.ietf.org/html/rfc2003#section-3
	ipipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   uint16(ipHeaderLen + ipHeaderLen + icmpHeaderLen + len(payload)),
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolIPv4,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	// inner ip header (layer 3) https://tools.ietf.org/html/rfc791#section-3.1
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   uint16(ipHeaderLen + icmpHeaderLen + len(payload)),
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    destIP,
		DstIP:    sourceIP,
	}

	// inner icmp header (layer 4) https://tools.ietf.org/html/rfc792#page-4
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
		log.Fatalf("Error serializing packet: %s", err)
	}
	packetData := buf.Bytes()

	err = sendPacket(packetData, destIP)
	if err != nil {
		log.Fatal("Failed to call send packet: ", err)
	}
	log.Printf("Successfully sent a packet: %v\n", packetData)
}

func sendPacket(packetData []byte, dest net.IP) error {
	// open a raw socket, the IPPROTO_RAW protocol implies IP_HDRINCL is enabled
	// http://man7.org/linux/man-pages/man7/raw.7.html
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	dest = dest.To4()
	if dest == nil {
		return errors.New("dest IP must be an ipv4 address")
	}

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{dest[0], dest[1], dest[2], dest[3]},
	}
	return syscall.Sendto(fd, packetData, 0, &addr)
}
