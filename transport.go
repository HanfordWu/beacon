package main

import (
	"errors"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TransportChannel is a struct which facilitates packet tx/rx
type TransportChannel struct {
	packetSource *gopacket.PacketSource
	deviceName   string
	snaplen      int32
	filter       string
}

// TransportChannelOption modifies a TransportChannel struct
// The TransportChannel constructor accepts a variadic parameter
// of TransportChannelOptions, each of which will be invoked upon construction
type TransportChannelOption func(*TransportChannel)

// WithBPFFilter constructs an option to set BPFFilter via the TransportChannel constructor
func WithBPFFilter(filter string) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.filter = filter
	}
}

// NewTransportChannel instantiates a new transport chanel
func NewTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	tc := &TransportChannel{
		deviceName: eth0DeviceName,
		snaplen:    1600,
		filter:     "",
	}

	for _, opt := range options {
		opt(tc)
	}

	handle, err := pcap.OpenLive(tc.deviceName, tc.snaplen, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if tc.filter != "" {
		err = handle.SetBPFFilter(tc.filter)
		if err != nil {
			return nil, err
		}
	}
	tc.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	return tc, nil
}

// Rx returns a packet channel over which packets will be pushed onto
func (tc *TransportChannel) Rx() chan gopacket.Packet {
	return tc.packetSource.Packets()
}

// SendTo sends a packet to the specified ip address
func (tc *TransportChannel) SendTo(packetData []byte, destAddr net.IP) error {
	// open a raw socket, the IPPROTO_RAW protocol implies IP_HDRINCL is enabled
	// http://man7.org/linux/man-pages/man7/raw.7.html
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	destAddr = destAddr.To4()
	if destAddr == nil {
		return errors.New("dest IP must be an ipv4 address")
	}

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{destAddr[0], destAddr[1], destAddr[2], destAddr[3]},
	}
	return syscall.Sendto(fd, packetData, 0, &addr)
}
