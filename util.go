package beacon

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
)

type portPair struct {
	src layers.UDPPort
	dst layers.UDPPort
}

// ParseIPFromString attempts to parse a valid IP address from the supplied string
// the string can be in the x.x.x.x format or a hostname.
func ParseIPFromString(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip != nil {
		return ip, nil
	}

	ipAddrs, err := net.LookupIP(s)
	if err != nil {
		return nil, err
	}

	return ipAddrs[0], nil
}

// GetInterfaceDeviceFromDestString uses gopacket's routing package to attempt to
// resolve the appropriate outbound interface to use given a destination string
func GetInterfaceDeviceFromDestString(dest string) (string, error) {
	destIP, err := ParseIPFromString(dest)
	if err != nil {
		return "", err
	}

	return GetInterfaceDeviceFromDestIP(destIP)
}

// GetInterfaceDeviceFromDestIP uses gopacket's routing package to attempt to
// resolve the appropriate outbound interface to use given a destination IP
func GetInterfaceDeviceFromDestIP(destIP net.IP) (string, error) {
	router, err := routing.New()
	if err != nil {
		return "", err
	}
	iface, _, _, err := router.Route(destIP)
	if err != nil {
		return "", err
	}

	return iface.Name, nil
}

// FindSourceIPForDest performs a udp dial and inspects the resulting connection
// to extract the preferred source IP to use for the given dest IP
func FindSourceIPForDest(dest net.IP) (net.IP, error) {
	conn, err := net.Dial("udp", fmt.Sprintf("[%s]:80", dest))
	if err != nil {
		return nil, fmt.Errorf("Failed to dial dest ip %s: %s", dest, err)
	}
	defer conn.Close()

	sourceIP := conn.LocalAddr().(*net.UDPAddr).IP

	return sourceIP, nil
}

func Merge(resultChannels ...chan BoomerangResult) <-chan BoomerangResult {
	var wg sync.WaitGroup
	resultChannel := make(chan BoomerangResult)

	drain := func(c chan BoomerangResult) {
		for res := range c {
			resultChannel <- res
		}
		wg.Done()
	}

	wg.Add(len(resultChannels))
	for _, c := range resultChannels {
		go drain(c)
	}

	go func() {
		wg.Wait()
		close(resultChannel)
	}()

	return resultChannel
}

func tracerouteResponseMatchesPortPair(payload []byte, ports portPair, isV4 bool) bool {
	layerType := layers.LayerTypeIPv4
	if !isV4 {
		layerType = layers.LayerTypeIPv6
		payload = payload[4:]
	}
	decodedPayloadPacket := gopacket.NewPacket(payload, layerType, gopacket.Default)
	udpLayer := decodedPayloadPacket.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == ports.src && udp.DstPort == ports.dst {
			return true
		}
	}
	return false
}
