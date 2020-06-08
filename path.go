package beacon

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Path is a slice of IPs which represents a path through the network
type Path []net.IP

// SubPath returns all the elements in the path up to and including 
func (p Path) SubPath(lastHop net.IP) Path {
    for idx, IP := range p {
        if lastHop.Equal(IP) {
            return p[:idx + 1]
        }
    }
    return []net.IP{}
}

// PathChannel is the channel version of a Path
type PathChannel chan net.IP

// GetPathTo returns a Path to a destination IP from the caller
func (tc *TransportChannel) GetPathTo(destIP net.IP) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelTo(destIP)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathFrom returns a Path from a destination IP back to the caller
func (tc *TransportChannel) GetPathFrom(destIP net.IP) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelFrom(destIP)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathFromSourceToDest returns a Path from a sourceIP to a destIP
func (tc *TransportChannel) GetPathFromSourceToDest(sourceIP, destIP net.IP) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelFromSourceToDest(sourceIP, destIP)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathChannelTo returns a PathChannel to a destination IP from the caller
func (tc *TransportChannel) GetPathChannelTo(destIP net.IP) (PathChannel, error) {
	if tc.filter != "icmp" {
		errMsg := fmt.Sprintf("BPF filter must be icmp: got %s instead", tc.filter)
		return nil, errors.New(errMsg)
	}

	pathChan := make(PathChannel)
	found := make(chan net.IP)
	done := make(chan error)

	sourceIP, err := tc.FindLocalIP()
	if err != nil {
		return pathChan, err
	}

	go func() {
		defer close(pathChan)
		buf := gopacket.NewSerializeBuffer()

		var ttl uint8
		for ttl = 1; ttl <= 32; ttl++ {
			err = buildICMPTraceroutePacket(sourceIP, destIP, ttl, []byte("Hello"), buf)
			if err != nil {
				done <- err
			}
			tc.SendTo(buf.Bytes(), destIP)
			select {
			case ip := <-found:
				pathChan <- ip
			case <-done:
				return
			}
		}
	}()

	go func() {
		for packet := range tc.Rx() {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			// fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(sourceIP) {
				found <- ip4.SrcIP
			} else if int(icmp.TypeCode) == icmpEchoReply && ip4.SrcIP.Equal(destIP) {
				found <- ip4.SrcIP
				done <- nil
				return
			}
		}
	}()

	return pathChan, nil
}

// GetPathChannelFrom returns a PathChannel from a destination IP back to the caller
func (tc *TransportChannel) GetPathChannelFrom(destIP net.IP) (PathChannel, error) {
	if tc.filter != "icmp" {
		errMsg := fmt.Sprintf("BPF filter must be icmp: got %s instead", tc.filter)
		return nil, errors.New(errMsg)
	}

	pathChan := make(PathChannel)
	found := make(chan net.IP)
	done := make(chan error)

	localIP, err := tc.FindLocalIP()
	if err != nil {
		return pathChan, err
	}

	go func() {
		defer close(pathChan)
		roundTripBuf := gopacket.NewSerializeBuffer()
		remoteProbeBuf := gopacket.NewSerializeBuffer()

		var ttl uint8
		for ttl = 1; ttl <= 32; ttl++ {
			err = buildEncapTraceroutePacket(localIP, destIP, localIP, localIP, ttl, []byte("Hello"), roundTripBuf)
			if err != nil {
				done <- err
			}
			err = buildEncapTraceroutePacket(localIP, destIP, destIP, localIP, ttl+1, []byte("Hello"), remoteProbeBuf)
			if err != nil {
				done <- err
			}
			tc.SendTo(roundTripBuf.Bytes(), destIP)
			tc.SendTo(remoteProbeBuf.Bytes(), destIP)

			select {
			case ip := <-found:
				pathChan <- ip
			case <-done:
				return
			}
		}
	}()

	go func() {
		for packet := range tc.Rx() {
			// TODO: consider using DecodingLayerParser https://godoc.org/github.com/google/gopacket#hdr-Fast_Decoding_With_DecodingLayerParser
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			// fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(localIP) {
				found <- ip4.SrcIP
			} else if int(icmp.TypeCode) == icmpEchoRequest && ip4.SrcIP.Equal(destIP) {
				found <- ip4.DstIP
				done <- nil
				return
			}
		}
	}()

	return pathChan, nil
}

// GetPathChannelFromSourceToDest returns a PathChannel from a sourceIP to a destIP
func (tc *TransportChannel) GetPathChannelFromSourceToDest(sourceIP, destIP net.IP) (PathChannel, error) {
	if tc.filter != "icmp" {
		errMsg := fmt.Sprintf("BPF filter must be icmp: got %s instead", tc.filter)
		return nil, errors.New(errMsg)
	}

	pathChan := make(PathChannel)
	found := make(chan net.IP)
	done := make(chan error)

	localIP, err := tc.FindLocalIP()
	if err != nil {
		return pathChan, err
	}
	if sourceIP.Equal(localIP) {
		return tc.GetPathChannelTo(destIP)
	}

	go func() {
		defer close(pathChan)
		var ttl uint8
		for ttl = 1; ttl <= 32; ttl++ {
			buf := gopacket.NewSerializeBuffer()
			payload := []byte("Hello")

			buildEncapTraceroutePacket(localIP, sourceIP, localIP, destIP, ttl, payload, buf)

			tc.SendTo(buf.Bytes(), sourceIP)

			select {
			case ip := <-found:
				pathChan <- ip
			case <-done:
				return
			}
		}
	}()

	go func() {
		for packet := range tc.Rx() {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(localIP) {
				found <- ip4.SrcIP
			} else if int(icmp.TypeCode) == icmpEchoReply && ip4.SrcIP.Equal(destIP) {
				found <- ip4.SrcIP
				done <- nil
				return
			}
		}
	}()

	return pathChan, nil
}
