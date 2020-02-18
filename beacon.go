package main

import (
	"log"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
        IP_HEADER_LEN = 20
        ICMP_HEADER_LEN = 8
        PAYLOAD_LEN = 20
)

func main() {
	sourceIP := net.IPv4(10, 20, 30, 96)
	destIP := net.IPv4(104, 44, 227, 112)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	ipipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   IP_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN + PAYLOAD_LEN,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolIPv4,
		SrcIP:    sourceIP,
		DstIP:    destIP,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   IP_HEADER_LEN + ICMP_HEADER_LEN + PAYLOAD_LEN,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    destIP,
		DstIP:    sourceIP,
	}

	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      1,
	}

	err := gopacket.SerializeLayers(buf, opts,
		ipipLayer,
		ipLayer,
		icmpLayer,
                gopacket.Payload([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	)
	if err != nil {
		log.Fatalf("Error serializing packet: %s", err)
	}
	packetData := buf.Bytes()

	err = sendPacketSyscall(packetData)
	if err != nil {
		log.Fatal("Sendto:", err)
	}

	log.Println("Successfully sent a packet")
}

func sendPacketSyscall(packetData []byte) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{104, 44, 227, 112},
	}
	return syscall.Sendto(fd, packetData, 0, &addr)
}
