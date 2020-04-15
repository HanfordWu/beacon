package beacon

import (
	"net"
	"sync"

	"github.com/google/gopacket/routing"
)

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

func merge(resultChannels ...chan BoomerangResult) <-chan BoomerangResult {
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