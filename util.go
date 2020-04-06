package beacon

import (
	"log"
	"net"

	"github.com/google/gopacket/pcap"
)

// FindLocalIP finds the IP address assigned to the interface "eth0"
func FindLocalIP() (net.IP, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var eth0Device pcap.Interface
	deviceFound := false
	for _, device := range devices {
		if device.Name == eth0DeviceName {
			deviceFound = true
			eth0Device = device
		}
	}
	if !deviceFound {
		log.Fatalf("Couldn't find a device named %s, or it did not have any addresses assigned to it", eth0DeviceName)
	}

	return eth0Device.Addresses[0].IP, nil
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