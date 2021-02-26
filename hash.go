package beacon

import (
	"fmt"
	"sync"
	"runtime"
	"reflect"

	"github.com/google/gopacket"
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

// RegisterHash registers a hash to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (tc *TransportChannel) RegisterHash(hash string) chan gopacket.Packet {
	return tc.packetHashes.store(hash)
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
		computedHash, err := hasher(p)
		if err != nil {
			continue
		}

		computedHashSlice = append(computedHashSlice, computedHash)
	}

	for _, computedHash := range computedHashSlice {
		if packetMatchChannel, ok := phm.m.Load(computedHash); ok {
			assertedChannel := packetMatchChannel.(chan gopacket.Packet)
			assertedChannel <- p
		}
	}
}

func (phm *packetHashMap) store(hash string) chan gopacket.Packet {

	packetMatchChannel := make(chan gopacket.Packet, 1)
	phm.m.Store(hash, packetMatchChannel)

	return packetMatchChannel
}

func (phm *packetHashMap) del(hash string) bool {

	packetMatchChannel, exists := phm.m.Load(hash)
	assertedChannel := packetMatchChannel.(chan gopacket.Packet)

	if exists {
		close(assertedChannel)
		phm.m.Delete(hash)
	}

	return exists
}
