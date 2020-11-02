package beacon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TransportChannel is a struct which facilitates packet tx/rx
type TransportChannel struct {
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
	listenerMap  *ListenerMap
	packets      chan gopacket.Packet
	socketFD     int
	socket6FD    int
	deviceName   string
	snaplen      int
	bufferSize   int
	filter       string
	timeout      int
	useListeners bool
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

// WithTimeout sets the timeout on the enclosed pcap Handle
func WithTimeout(timeout int) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.timeout = timeout
	}
}

// WithSnapLen sets the snaplen on the enclosed pcap Handle
func WithSnapLen(snaplen int) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.snaplen = snaplen
	}
}

// WithBufferSize sets the buffer size on the enclosed pcap Handle
func WithBufferSize(bufferSize int) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.bufferSize = bufferSize
	}
}

// UseListeners sets up the TransportChannel for listener use or not
func UseListeners(useListeners bool) TransportChannelOption {
	return func(tc *TransportChannel) {
		tc.useListeners = useListeners
	}
}

// NewTransportChannel instantiates a new transport chanel
func NewTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	tc := &TransportChannel{
		snaplen:      4800,
		bufferSize:   16 * 1024 * 1024,
		deviceName:   "any",
		filter:       "",
		timeout:      100,
		listenerMap:  NewListenerMap(),
		useListeners: true,
	}

	for _, opt := range options {
		opt(tc)
	}

	inactive, err := pcap.NewInactiveHandle(tc.deviceName)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	if err := inactive.SetImmediateMode(true); err != nil {
		return nil, err
	} else if err := inactive.SetSnapLen(tc.snaplen); err != nil {
		return nil, err
	} else if err := inactive.SetBufferSize(tc.bufferSize); err != nil {
		return nil, err
	} else if err := inactive.SetTimeout(time.Millisecond * time.Duration(tc.timeout)); err != nil { // set negative timeout, mechanics described here: https://godoc.org/github.com/google/gopacket/pcap#hdr-PCAP_Timeouts
		return nil, err
	}

	handle, err := inactive.Activate()
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

	// open a raw socket, the IPPROTO_RAW protocol implies IP_HDRINCL is enabled
	// http://man7.org/linux/man-pages/man7/raw.7.html
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed to create socket for TransportChannel: %s", err)
	}
	tc.socketFD = fd

	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed to create socket for TransportChannel: %s", err)
	}
	tc.socket6FD = fd6

	if tc.useListeners {
		// activate listeners
		go func() {
			for packet := range tc.rx() {
				go tc.listenerMap.Run(packet)
			}
		}()
	}

	return tc, nil
}

// Stats displays the stats exposed by the underlying packet handle of a TransportChannel.
func (tc *TransportChannel) Stats() string {
	stats, err := tc.handle.Stats()
	if err != nil {
		return fmt.Sprintf("Encountered an error trying to produce handle stats: %s", err)
	}
	return fmt.Sprintf("%+v", stats)
}

// rx returns a packet channel over which packets will be pushed onto
// this method is private to prevent users from interfering with the listeners
func (tc *TransportChannel) rx() chan gopacket.Packet {
	// return tc.packetSource.Packets()
	if tc.packets == nil {
		tc.packets = make(chan gopacket.Packet, 1000000)
		go tc.packetsToChannel()
	}
	return tc.packets
}

// packetsToChannel reads in all packets from the packet source and sends them
// to the given channel. This routine terminates when a non-temporary error
// is returned by NextPacket().
func (tc *TransportChannel) packetsToChannel() {

	defer close(tc.packets)
	for {
		packet, err := tc.packetSource.NextPacket()
		if err == nil {
			tc.packets <- packet
			continue
		}

		// Immediately retry for temporary network errors
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			continue
		}

		// Immediately retry for EAGAIN
		if err == syscall.EAGAIN {
			continue
		}

		// Immediately break for known unrecoverable errors
		if err == io.EOF || err == io.ErrUnexpectedEOF ||
			err == io.ErrNoProgress || err == io.ErrClosedPipe || err == io.ErrShortBuffer ||
			err == syscall.EBADF ||
			strings.Contains(err.Error(), "use of closed file") {
			break
		}

		// Sleep briefly and try again
		time.Sleep(time.Millisecond * time.Duration(5))
	}
}

// SendTo sends a packet to the specified ip address
func (tc *TransportChannel) SendTo(packetData []byte, destAddr net.IP) error {
	destAddr4 := destAddr.To4()
	var err error
	if destAddr4 == nil {
		//return errors.New("dest IP must be an ipv4 address")
		destAddr16 := destAddr.To16()
		addr := syscall.SockaddrInet6{
			Addr: [16]byte{destAddr16[0], destAddr16[1], destAddr16[2], destAddr16[3], destAddr16[4], destAddr16[5], destAddr16[6], destAddr16[7], destAddr16[8], destAddr16[9], destAddr16[10], destAddr16[11], destAddr16[12], destAddr16[13], destAddr16[14], destAddr16[15]},
		}
		err = syscall.Sendto(tc.socket6FD, packetData, 0, &addr)
	} else {
		addr := syscall.SockaddrInet4{
			Addr: [4]byte{destAddr4[0], destAddr4[1], destAddr4[2], destAddr4[3]},
		}
		err = syscall.Sendto(tc.socketFD, packetData, 0, &addr)
	}
	if err != nil {
		return fmt.Errorf("Failed to send packetData to socket: %s", err)
	}
	return nil
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
	syscall.Close(tc.socketFD)
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

// Interface returns the interface the TransportChannel is listening on
func (tc *TransportChannel) Interface() string {
	return tc.deviceName
}

// Filter returns the BPF the TransportChannel uses
func (tc *TransportChannel) Filter() string {
	return tc.filter
}

func (tc *TransportChannel) Version() string {
	return pcap.Version()
}

// FindSourceIPForDest finds the IP of the interface device of the TransportChannel instance
func (tc *TransportChannel) FindSourceIPForDest(dest net.IP) (net.IP, error) {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:80", dest))
	if err != nil {
		return nil, fmt.Errorf("Failed to dial dest ip %s: %s", dest, err)
	}
	defer conn.Close()

	sourceIP := conn.LocalAddr().(*net.UDPAddr).IP

	return sourceIP, nil
}
