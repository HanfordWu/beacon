package beacon

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Path is a slice of IPs which represents a path through the network
type Path []net.IP

// String returns the string representation of a path
func (p Path) String() string {
	stringIpArr := make([]string, len(p))
	for idx, ip := range p {
		stringIpArr[idx] = ip.String()
	}

	stringBuilder := strings.Builder{}
	stringBuilder.WriteString("[")
	stringBuilder.WriteString(strings.Join(stringIpArr, ", "))
	stringBuilder.WriteString("]")

	return stringBuilder.String()
}

// SubPath returns all the elements in the path up to and including
func (p Path) SubPath(lastHop net.IP) Path {
	for idx, IP := range p {
		if lastHop.Equal(IP) {
			return p[:idx+1]
		}
	}
	return []net.IP{}
}

// Equal checks if two given paths are equal
func (p Path) Equal(other Path) bool {
	if len(p) != len(other) {
		return false
	}

	for idx := range p {
		if !p[idx].Equal(other[idx]) {
			return false
		}
	}
	return true
}

// PathChannel is the channel version of a Path
type PathChannel chan net.IP

// PathTerminator contains the second to last and last IPs of a path
type PathTerminator struct {
	lastIP         net.IP
	secondToLastIP net.IP
}

func (tc *TransportChannel) newTraceroutePortPair() portPair {
	tc.portLock.Lock()
	defer tc.portLock.Unlock()

	tc.srcPortOffset = (tc.srcPortOffset + 1) % maxPortOffset
	tc.dstPortOffset = (tc.dstPortOffset + 1) % maxPortOffset

	return portPair{
		src: layers.UDPPort(33434 + tc.srcPortOffset),
		dst: layers.UDPPort(33434 + tc.dstPortOffset),
	}
}

// GetPathTo returns a Path to a destination IP from the caller
func (tc *TransportChannel) GetPathTo(destIP net.IP, timeout int) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelTo(destIP, nil, timeout)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathFrom returns a Path from a destination IP back to the caller
func (tc *TransportChannel) GetPathFrom(destIP net.IP, timeout int) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelFrom(destIP, timeout)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathFromSourceToDest returns a Path from a sourceIP to a destIP
func (tc *TransportChannel) GetPathFromSourceToDest(sourceIP, destIP net.IP, timeout int) (Path, error) {
	path := make([]net.IP, 0)

	pc, err := tc.GetPathChannelFromSourceToDest(sourceIP, destIP, timeout)
	if err != nil {
		return path, err
	}

	for hop := range pc {
		path = append(path, hop)
	}

	return path, nil
}

// GetPathChannelTo returns a PathChannel to a destination IP from the caller
func (tc *TransportChannel) GetPathChannelTo(destIP, sourceIP net.IP, timeout int) (PathChannel, error) {

	if tc.filter != "icmp" {
		errMsg := fmt.Sprintf("BPF filter must be icmp: got %s instead", tc.filter)
		return nil, errors.New(errMsg)
	}

	fmt.Printf("transport channel is using interface: %s\n", tc.deviceName)

	pathChan := make(PathChannel)
	found := make(chan net.IP)
	done := make(chan PathTerminator)

	var finalSourceIP net.IP
	if sourceIP == nil {
		foundSourceIP, err := tc.FindSourceIPForDest(destIP)
		if err != nil {
			return pathChan, err
		}
		finalSourceIP = foundSourceIP
	} else {
		finalSourceIP = sourceIP
	}

	ports := tc.newTraceroutePortPair()

	criteria := func(packet gopacket.Packet, payload *BoomerangPayload) bool {
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		icmp, _ := icmpLayer.(*layers.ICMPv4)

		if !tracerouteResponseMatchesPortPair(icmp.Payload, ports) {
			// packet is from a different traceroute id
			return false
		}
		return true
	}

	listener := NewPersistentListener(criteria)
	packetChan := tc.RegisterListener(listener)

	go func() {
		for matchedPacket := range packetChan {
			icmpLayer := matchedPacket.packet.Layer(layers.LayerTypeICMPv4)
			ipv4Layer := matchedPacket.packet.Layer(layers.LayerTypeIPv4)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			// fmt.Printf("%s -> %s : %s\n", ip4.SrcIP, ip4.DstIP, icmp.TypeCode)
			if int(icmp.TypeCode) == icmpTTLExceeded && ip4.DstIP.Equal(finalSourceIP) {
				found <- ip4.SrcIP
			} else if int(icmp.TypeCode) == icmpPortUnreachable && ip4.DstIP.Equal(finalSourceIP) {
				done <- PathTerminator{
					secondToLastIP: ip4.SrcIP,
					lastIP:         destIP,
				}
				return
			}
		}
	}()

	go func() {
		// wait for listener to be ready to recv
		defer close(pathChan)
		defer tc.UnregisterListener(listener)
		buf := gopacket.NewSerializeBuffer()

		var ttl uint8
		for ttl = 1; ttl <= 32; ttl++ {
			err := buildUDPTraceroutePacket(finalSourceIP, destIP, ports.src, ports.dst, ttl, []byte("traceroute"), buf)
			if err != nil {
				fmt.Printf("Failed to build udp tracert packet: %s\n", err)
			}

			err = tc.SendTo(buf.Bytes(), destIP)
			if err != nil {
				fmt.Printf("error sending packet: %s", err)
			}

			select {
			case ip := <-found:
				pathChan <- ip
			case <-time.After(time.Duration(timeout) * time.Second):
				pathChan <- nil
			case term := <-done:
				if term.lastIP.Equal(term.secondToLastIP) {
					pathChan <- term.lastIP
					return
				}
				pathChan <- term.secondToLastIP
				pathChan <- term.lastIP
				return
			}
		}
	}()

	return pathChan, nil
}

// GetPathChannelFrom returns a PathChannel from a destination IP back to the caller
func (tc *TransportChannel) GetPathChannelFrom(destIP net.IP, timeout int) (PathChannel, error) {
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
			case <-time.After(time.Duration(timeout) * time.Millisecond):
				pathChan <- nil
			case <-done:
				return
			}
		}
	}()

	go func() {
		for packet := range tc.rx() {
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
func (tc *TransportChannel) GetPathChannelFromSourceToDest(sourceIP, destIP net.IP, timeout int) (PathChannel, error) {
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
		return tc.GetPathChannelTo(destIP, nil, timeout)
	}

	go func() {
		for packet := range tc.rx() {
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
			case <-time.After(time.Duration(timeout) * time.Millisecond):
				pathChan <- nil
			case <-done:
				return
			}
		}
	}()

	return pathChan, nil
}
