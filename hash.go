package beacon

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketHasher produces some hash for a given packet which uniquely identifies a packet.
type PacketHasher interface {
	Name() string
	HashPacket(gopacket.Packet) (string, error)
}

// AttachHasher attaches a packet hasher to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (phm *packetHashMap) AttachHasher(hasher PacketHasher) error {
	hasherName := hasher.Name()
	for _, currHasher := range phm.hashers {
		currName := currHasher.Name()
		if currName == hasherName {
			return fmt.Errorf("Adding hasher that already exists in packetHashMap. Failing for efficiency.")
		}
	}
	phm.hashers = append(phm.hashers, hasher)
	return nil
}

type BoomerangPacketHasher struct{}

func (b BoomerangPacketHasher) HashPacket(p gopacket.Packet) (string, error) {
	app := p.ApplicationLayer()
	if app == nil || len(app.Payload()) < 20 {
		return "", fmt.Errorf("packet didn't have an application layer or payload was less than 20 bytes")
	}

	payloadBytes := app.Payload()[:20] // 4 bytes for "moby" + 16 bytes for guid

	return string(payloadBytes), nil
}

func (b BoomerangPacketHasher) Name() string {
	return "BoomerangPacketHasher"
}

type V6TraceRouteHasher struct{}

func (v V6TraceRouteHasher) HashPacket(packet gopacket.Packet) (string, error) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return "", fmt.Errorf("Could not find application layer in incoming traceroute packet")
	}
	icmpPayload := appLayer.Payload()
	layerType := layers.LayerTypeIPv6
	icmpPayload = icmpPayload[4:]
	decodedPayloadPacket := gopacket.NewPacket(icmpPayload, layerType, gopacket.Default)
	udpLayer := decodedPayloadPacket.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return "", fmt.Errorf("Could not find udp layer in incoming traceroute packet.")
	}
	return string(udpLayer.(*layers.UDP).BaseLayer.Contents), nil
}

func (v V6TraceRouteHasher) Name() string {
	return "V6TraceRouteHasher"
}

type V4TraceRouteHasher struct{}

func (v V4TraceRouteHasher) HashPacket(packet gopacket.Packet) (string, error) {
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return "", fmt.Errorf("Could not find application layer in incoming traceroute packet")
	}
	icmpPayload := appLayer.Payload()
	layerType := layers.LayerTypeIPv4
	decodedPayloadPacket := gopacket.NewPacket(icmpPayload, layerType, gopacket.Default)
	udpLayer := decodedPayloadPacket.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return "", fmt.Errorf("Could not find udp layer in incoming traceroute packet.")
	}
	return string(udpLayer.(*layers.UDP).BaseLayer.Contents), nil
}

func (v V4TraceRouteHasher) Name() string {
	return "V4TraceRouteHasher"
}

// RegisterHash registers a hash to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (tc *TransportChannel) RegisterHash(hash string, packetChan chan gopacket.Packet) {
	tc.packetHashes.store(hash, packetChan)
}

// UnregisterHash removes the given hash from the packetHashes map.
func (tc *TransportChannel) UnregisterHash(hash string) bool {
	return tc.packetHashes.del(hash)
}

type packetHashMap struct {
	m       sync.Map
	hashers []PacketHasher
}

func NewPacketHashMap() *packetHashMap {
	return &packetHashMap{
		m: sync.Map{},
	}
}

func (phm *packetHashMap) run(p gopacket.Packet) {
	computedHashSlice := []string{}

	for _, hasher := range phm.hashers {
		computedHash, err := hasher.HashPacket(p)
		if err != nil {
			continue
		}
		computedHashSlice = append(computedHashSlice, computedHash)
	}

	for _, computedHash := range computedHashSlice {
		if packetMatchChannel, ok := phm.m.LoadAndDelete(computedHash); ok {
			assertedChannel := packetMatchChannel.(chan gopacket.Packet)
			assertedChannel <- p
			close(assertedChannel)
		}
	}
}

func (phm *packetHashMap) store(hash string, packetChan chan gopacket.Packet) {
	phm.m.Store(hash, packetChan)

	return
}

func (phm *packetHashMap) del(hash string) bool {

	packetMatchChannel, exists := phm.m.LoadAndDelete(hash)

	if exists {

		assertedChannel := packetMatchChannel.(chan gopacket.Packet)
		close(assertedChannel)

	}

	return exists
}
