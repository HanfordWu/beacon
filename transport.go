package beacon

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TransportChannel is a struct which facilitates packet tx/rx
type TransportChannel struct {
	handle                 *pcap.Handle
	packetSource           *gopacket.PacketSource
	listenerMap            *ListenerMap
	portLock               sync.Mutex
	packets                chan gopacket.Packet
	socketFD               int
	socketFailureMsgQueue  chan int
	socket6FD              int
	socket6FailureMsgQueue chan int
	deviceName             string
	snaplen                int
	bufferSize             int
	srcPortOffset          int
	dstPortOffset          int
	filter                 string
	timeout                int
	useListeners           bool
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

// NewTransportChannel instantiates a new transport channel
func NewTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	rand.Seed(time.Now().UnixNano())

	tc := &TransportChannel{
		snaplen:       4800,
		bufferSize:    16 * 1024 * 1024,
		deviceName:    "any",
		filter:        "",
		timeout:       100,
		srcPortOffset: rand.Intn(maxPortOffset),
		dstPortOffset: rand.Intn(maxPortOffset),
		listenerMap:   NewListenerMap(),
		useListeners:  true,
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
		return nil, fmt.Errorf("Failed to create IPv4 socket for TransportChannel: %s", err)
	}
	tc.socketFD = fd
	tc.socketFailureMsgQueue = make(chan int)
	go tc.renewSocketFD()

	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed to create IPv6 socket for TransportChannel: %s", err)
	}
	tc.socket6FD = fd6
	tc.socket6FailureMsgQueue = make(chan int)
	go tc.renewSocket6FD()

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

// NewBoomerangTransportChannel instantiates a new transport channel with an ip packet header (id:109) for the bpf
func NewBoomerangTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	options = append(options, WithBPFFilter("ip[4:2] = 0x6d || ip6[48:4] = 0x6d6f6279"))
	return NewTransportChannel(options...)
}

func (tc *TransportChannel) renewSocketFD() error {
	for {
		brokenFD := <-tc.socketFailureMsgQueue
		if brokenFD != tc.socketFD {
			continue
		}
		log.Println("Renewing SocketFD")
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			log.Printf("Failed to create IPv4 socket for TransportChannel: %s", err)
		}
		tc.socketFD = fd
		if brokenFD != fd {
			syscall.Close(brokenFD)
		}
	}
	return nil
}

func (tc *TransportChannel) renewSocket6FD() error {
	for {
		broken6FD := <-tc.socket6FailureMsgQueue
		if broken6FD != tc.socket6FD {
			continue
		}
		log.Println("Renewing socket6FD")
		fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			log.Printf("Failed to create IPv6 socket for TransportChannel: %s", err)
		}
		tc.socket6FD = fd6
		if broken6FD != fd6 {
			syscall.Close(broken6FD)
		}
	}
	return nil
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
	var err error

	destAddrTo4 := destAddr.To4()
	if destAddrTo4 == nil {
		var destAddr16 [16]byte
		copy(destAddr16[:], destAddr.To16()[:16])
		addr := syscall.SockaddrInet6{
			Addr: destAddr16,
		}
		fd6Int := tc.socket6FD
		err = syscall.Sendto(fd6Int, packetData, 0, &addr)
		if err != nil {
			tc.socket6FailureMsgQueue <- fd6Int
			return fmt.Errorf("Failed to send packetData to socket6FD: %s", err)
		}
	} else {
		var destAddr4 [4]byte
		copy(destAddr4[:], destAddrTo4)
		addr := syscall.SockaddrInet4{
			Addr: destAddr4,
		}
		fdInt := tc.socketFD
		err = syscall.Sendto(fdInt, packetData, 0, &addr)
		if err != nil {
			tc.socketFailureMsgQueue <- fdInt
			return fmt.Errorf("Failed to send packetData to socketFD: %s", err)
		}
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
//TODO: Test router solution in prod canary docker container
func (tc *TransportChannel) FindSourceIPForDest(dest net.IP) (net.IP, error) {
	//router, err := routing.New()
	//_, _, sourceIP, err := router.Route(dest)
	//if err != nil {
	//	return nil, err
	//}

	conn, err := net.Dial("udp", fmt.Sprintf("[%s]:80", dest))
	if err != nil {
		return nil, fmt.Errorf("Failed to dial dest ip %s: %s", dest, err)
	}
	defer conn.Close()

	sourceIP := conn.LocalAddr().(*net.UDPAddr).IP

	return sourceIP, nil
}

func (tc *TransportChannel) GetFilter() (string) {
	return tc.filter
}
