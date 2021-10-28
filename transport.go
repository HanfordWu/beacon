package beacon

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// TransportChannel is a struct which facilitates packet tx/rx
type TransportChannel struct {
	handles                []*pcap.Handle
	packetSources          []*gopacket.PacketSource
	packetHashes           *packetHashMap
	listenerMap            *ListenerMap
	portLock               sync.Mutex
	packets                chan gopacket.Packet
	socketFD               int
	socketFailureMsgQueue  chan int
	socket6FD              int
	socket6FailureMsgQueue chan int
	deviceNames            []string
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
type TransportChannelOption func(*TransportChannel) error

// WithBPFFilter constructs an option to set BPFFilter via the TransportChannel constructor
func WithBPFFilter(filter string) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.filter = filter
		return nil
	}
}

// WithInterface constructs an option to set the outbound interface to use for tx/rx
func WithInterface(device string) TransportChannelOption {
	return func(tc *TransportChannel) error {
		if device == "bsdany" {
			out, err := exec.Command("/usr/sbin/cli", "-c", "show isis adjacency").Output()
			if err != nil {
				return fmt.Errorf("Listening on bsdany: failed to show interfaces: %v", err)
			}
			tc.deviceNames = []string{}
			lines := strings.Split(string(out), "\n")
			if len(lines) < 2 {
				return fmt.Errorf("Listening on bsdany: no available interfaces to listen on")
			}
			for _, line := range lines[1:] {
				// Get device name, which will be at beginning of line, e.g. 'lo0:'
				fields := strings.Fields(line)
				if len(fields) == 5 {
					device := strings.ReplaceAll(fields[0], ".0", "")

					if len(device) > 0 {
						tc.deviceNames = append(tc.deviceNames, device)
						log.Printf("Listening on bsdany: added device %s to listen on\n", device)
					}
				}
			}
			if len(tc.deviceNames) == 0 {
				return fmt.Errorf("Listening on bsdany: found no devices to listen on")
			}
		} else {
			tc.deviceNames = []string{device}
		}
		return nil
	}
}

// WithTimeout sets the timeout on the enclosed pcap Handle
func WithTimeout(timeout int) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.timeout = timeout
		return nil
	}
}

// WithSnapLen sets the snaplen on the enclosed pcap Handle
func WithSnapLen(snaplen int) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.snaplen = snaplen
		return nil
	}
}

// WithBufferSize sets the buffer size on the enclosed pcap Handle
func WithBufferSize(bufferSize int) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.bufferSize = bufferSize
		return nil
	}
}

// WithHasher attaches a hasher to a transportChannel, hashers may be expensive, only attach what you need
func WithHasher(hasher PacketHasher) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.packetHashes.AttachHasher(hasher)
		return nil
	}
}

// UseListeners sets up the TransportChannel for listener use or not
func UseListeners(useListeners bool) TransportChannelOption {
	return func(tc *TransportChannel) error {
		tc.useListeners = useListeners
		return nil
	}
}

// NewTransportChannel instantiates a new transport channel
func NewTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	rand.Seed(time.Now().UnixNano())

	tc := &TransportChannel{
		snaplen:       4800,
		bufferSize:    16 * 1024 * 1024,
		deviceNames:   []string{"any"},
		filter:        "",
		timeout:       100,
		srcPortOffset: rand.Intn(maxPortOffset),
		dstPortOffset: rand.Intn(maxPortOffset),
		listenerMap:   NewListenerMap(),
		packetHashes:  NewPacketHashMap(),
		useListeners:  true,
	}

	for _, opt := range options {
		if err := opt(tc); err != nil {
			return nil, fmt.Errorf("Failed to apply TransportChannelOption: %v", err)
		}
	}

	tc.packetSources = make([]*gopacket.PacketSource, len(tc.deviceNames))
	tc.handles = make([]*pcap.Handle, len(tc.deviceNames))

	for idx, deviceName := range tc.deviceNames {
		inactive, err := pcap.NewInactiveHandle(deviceName)
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
		tc.handles[idx] = handle

		if tc.filter != "" {
			err = handle.SetBPFFilter(tc.filter)
			if err != nil {
				return nil, err
			}
		}

		tc.packetSources[idx] = CreatePacketSource(handle)
	}

	_, err := tc.setupSocket("IPv4")
	if err != nil {
		return nil, fmt.Errorf("Failed to create IPv4 socket for TransportChannel: %s", err)
	}
	tc.socketFailureMsgQueue = make(chan int)
	go tc.renewSocketFD()

	_, err = tc.setupSocket("IPv6")
	if err != nil {
		return nil, fmt.Errorf("Failed to create IPv6 socket for TransportChannel: %s", err)
	}
	tc.socket6FailureMsgQueue = make(chan int)
	go tc.renewSocket6FD()

	if tc.useListeners {
		// activate listeners
		go func() {
			for packet := range tc.rx() {
				go tc.packetHashes.run(packet)
				go tc.listenerMap.Run(packet)
			}
		}()
	}

	return tc, nil
}

// NewBoomerangTransportChannel instantiates a new transport channel with an ip packet header (id:109) for the bpf
func NewBoomerangTransportChannel(options ...TransportChannelOption) (*TransportChannel, error) {
	BoomerangTCOptions := []TransportChannelOption{
		WithBPFFilter(fmt.Sprintf("ip[4:2] = %s || ip6[48:4] = %s", boomerangSigV4, boomerangSigV6)),
		WithHasher(BoomerangPacketHasher{}),
	}

	options = append(options, BoomerangTCOptions...)
	return NewTransportChannel(options...)
}

func (tc *TransportChannel) setupSocket(socketType string) (int, error) {
	if socketType == "IPv4" {
		// open a raw socket
		// http://man7.org/linux/man-pages/man7/raw.7.html
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return fd, fmt.Errorf("Failed to create v4 socket: %s", err)
		}
		// IPPROTO_RAW protocol implies IP_HDRINCL on linux, however on freebsd we must set it explicitly
		// so that no IP header is automatically appended to the IP packets we craft
		// https://www.freebsd.org/cgi/man.cgi?query=ip&sektion=4&manpath=FreeBSD+12.0-RELEASE
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			return fd, fmt.Errorf("Failed to set v4 socket option: %s", err)
		}
		tc.socketFD = fd
		return fd, nil

	} else if socketType == "IPv6" {
		fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			return fd6, fmt.Errorf("Failed to create v6 socket: %s", err)
		}
		tc.socket6FD = fd6
		return fd6, nil
	}

	return -1, fmt.Errorf("Failed to create socket: unrecognized socket type")
}

func (tc *TransportChannel) renewSocketFD() {
	for {
		brokenFD := <-tc.socketFailureMsgQueue
		if brokenFD != tc.socketFD {
			continue
		}
		log.Println("Renewing SocketFD")
		fd, err := tc.setupSocket("IPv4")
		if err != nil {
			log.Printf("Failed to renew v4 socket FD: %s", err)
		}
		if brokenFD != fd {
			syscall.Close(brokenFD)
		}
	}
}

func (tc *TransportChannel) renewSocket6FD() {
	for {
		broken6FD := <-tc.socket6FailureMsgQueue
		if broken6FD != tc.socket6FD {
			continue
		}
		log.Println("Renewing socket6FD")
		fd6, err := tc.setupSocket("IPv6")
		if err != nil {
			log.Printf("Failed to renew v6 socket FD: %s", err)
		}
		tc.socket6FD = fd6
		if broken6FD != fd6 {
			syscall.Close(broken6FD)
		}
	}
}

// Stats displays the stats exposed by the underlying packet handle of a TransportChannel.
func (tc *TransportChannel) Stats() string {
	statsList := ""
	for i, handle := range tc.handles {
		if i >= len(tc.deviceNames) {
			return fmt.Sprintf("Could not find device name for handle")
		}
		dev := tc.deviceNames[i]
		stats, err := handle.Stats()
		if err != nil {
			return fmt.Sprintf("Encountered an error trying to produce handle stats: %s", err)
		}
		statsList += fmt.Sprintf("Stats for device %v:\n %+v\n", dev, stats)
	}

	return statsList
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
	waitOnDevices := sync.WaitGroup{}
	waitOnDevices.Add(len(tc.packetSources))

	for _, packetSource := range tc.packetSources {
		go func(p *gopacket.PacketSource) {
			defer waitOnDevices.Done()

			for {
				packet, err := p.NextPacket()
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
		}(packetSource)
	}

	// Wait for all readers to exit so that packets chan doesn't close before that
	waitOnDevices.Wait()
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
	for _, handle := range tc.handles {
		handle.Close()
	}
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
		if device.Name == tc.deviceNames[0] {
			deviceFound = true
			eth0Device = device
		}
	}
	if !deviceFound {
		errMsg := fmt.Sprintf("Couldn't find a device named %s, or it did not have any addresses assigned to it", tc.deviceNames)
		return nil, errors.New(errMsg)
	}

	return eth0Device.Addresses[0].IP, nil
}

// Interface returns the interface the TransportChannel is listening on
func (tc *TransportChannel) Interface() string {
	return tc.deviceNames[0]
}

// Filter returns the BPF the TransportChannel uses
func (tc *TransportChannel) Filter() string {
	return tc.filter
}

func (tc *TransportChannel) Version() string {
	return pcap.Version()
}

func (tc *TransportChannel) GetFilter() string {
	return tc.filter
}
