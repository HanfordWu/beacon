package beacon

import (
	"fmt"
	"reflect"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketHasher produces some hash for a given packet which uniquely identifies a packet.
type PacketHasher func(gopacket.Packet) (string, error)

// AttachHasher attaches a packet hasher to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (tc *TransportChannel) AttachHasher(hasher PacketHasher) error {
	hasherName := runtime.FuncForPC(reflect.ValueOf(hasher).Pointer()).Name()
	for _, fn := range tc.packetHashes.hashers {
		fnName := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
		if fnName == hasherName {
			return fmt.Errorf("Adding hasher that already exists in packetHashMap. Failing for efficiency.")
		}
	}
	tc.packetHashes.hashers = append(tc.packetHashes.hashers, hasher)
	return nil
}

func BoomerangPacketHasher(p gopacket.Packet) (string, error) {
	app := p.ApplicationLayer()
	if app == nil || len(app.Payload()) < 20 {
		return "", fmt.Errorf("packet didn't have an application layer or payload was less than 20 bytes")
	}

	payloadBytes := app.Payload()[:20] // 4 bytes for "moby" + 16 bytes for guid

	return string(payloadBytes), nil
}

func V6TraceRouteHasher(packet gopacket.Packet) (string, error) {
	appLayer := packet.ApplicationLayer()
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

func V4TraceRouteHasher(packet gopacket.Packet) (string, error) {
	appLayer := packet.ApplicationLayer()
	icmpPayload := appLayer.Payload()
	layerType := layers.LayerTypeIPv4
	decodedPayloadPacket := gopacket.NewPacket(icmpPayload, layerType, gopacket.Default)
	udpLayer := decodedPayloadPacket.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return "", fmt.Errorf("Could not find udp layer in incoming traceroute packet.")
	}
	return string(udpLayer.(*layers.UDP).BaseLayer.Contents), nil
}

// RegisterHash registers a hash to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (tc *TransportChannel) RegisterHash(hash string, packetChan chan gopacket.Packet) {
	tc.packetHashes.store(hash, packetChan)
}

// UnregisterHash removes the given hash from the packetHashes map.
func (tc *TransportChannel) UnregisterHash(hash string, closeChan bool) bool {
	return tc.packetHashes.del(hash, closeChan)
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
		computedHash, err := hasher(p)
		if err != nil {
			continue
		}
		computedHashSlice = append(computedHashSlice, computedHash)
	}

	for _, computedHash := range computedHashSlice {
		if packetMatchChannel, ok := phm.m.Load(computedHash); ok {
			fmt.Printf("found matching packet\n")
			assertedChannel := packetMatchChannel.(chan gopacket.Packet)
			assertedChannel <- p
		}
	}
}

func (phm *packetHashMap) store(hash string, packetChan chan gopacket.Packet) {
	phm.m.Store(hash, packetChan)

	return
}

func (phm *packetHashMap) del(hash string, closeChan bool) bool {

	packetMatchChannel, exists := phm.m.Load(hash)
	assertedChannel := packetMatchChannel.(chan gopacket.Packet)

	if exists {
		if closeChan {
			close(assertedChannel)
		}
		phm.m.Delete(hash)
	}

	return exists
}
