package beacon

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TransportChannel is a struct which facilitates packet tx/rx
type TransportChannel struct {
	handle       *pcap.Handle
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

// WithInterface constructs an option to set the outbound interface to use for tx/rx
func WithInterface(device string) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.deviceName = device
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
	tc.handle = handle

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

// RxWithCondition synchronously returns the first packet from the TransportChannel's
// packetSource which satisfies the filter function.
func (tc *TransportChannel) RxWithCondition(filter func(gopacket.Packet) bool) chan gopacket.Packet {
	foundPacketChan := make(chan gopacket.Packet)
	go func() {
		for packet := range tc.Rx() {
			if filter(packet) {
				foundPacketChan <- packet
			}
		}
	}()

	return foundPacketChan
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

// SendToPath sends a packet to the first hop in the specified path
func (tc *TransportChannel) SendToPath(packetData []byte, path Path) error {
	if len(path) < 1 {
		return errors.New("path must be non-empty")
	}
	return tc.SendTo(packetData, path[1])
}

// Close cleans up resources for the transport channel instance
func (tc *TransportChannel) Close() {
	tc.handle.Close()
}

// FindLocalIP finds the IP of the interface device of the TransportChannel instance
func (tc *TransportChannel) FindLocalIP() (net.IP, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var eth0Device pcap.Interface
	deviceFound := false
	for _, device := range devices {
		if device.Name == tc.deviceName {
			deviceFound = true
			eth0Device = device
		}
	}
	if !deviceFound {
		errMsg := fmt.Sprintf("Couldn't find a device named %s, or it did not have any addresses assigned to it", tc.deviceName)
		return nil, errors.New(errMsg)
	}

	return eth0Device.Addresses[0].IP, nil
}