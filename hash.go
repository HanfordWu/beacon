package beacon

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
)

// PacketHasher produces some hash for a given packet which uniquely identifies a packet.
type PacketHasher func(gopacket.Packet) (string, error)

func (tc *TransportChannel) AttachPacketHasher(ph PacketHasher) {
	tc.packetHashers = append(tc.packetHashers, ph)
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

// AttachHasher attaches a packet hasher to the current transport channel.
// When a packet is receieved by the transport channel, its hash will be computed
// by the each of the attached Hashers, and if the resulting hash identifies a packet
// being listened for, it will be sent over the returned channel.
func (tc *TransportChannel) AttachHasher(hasher PacketHasher) {
	tc.packetHashes.hashers = append(tc.packetHashes.hashers, hasher)
}

type packetHashMap struct {
	sync.Mutex

	m       map[string]chan gopacket.Packet
	hashers []PacketHasher
}

func NewPacketHashMap() *packetHashMap {
	return &packetHashMap{
		m: make(map[string]chan gopacket.Packet),
	}
}

func (phm *packetHashMap) run(p gopacket.Packet) {
	for _, hasher := range phm.hashers {
		computedHash, err := hasher(p)
		if err != nil {
			continue
		}

		if packetMatchChannel, ok := phm.m[computedHash]; ok {
			packetMatchChannel <- p
		}
	}
}

func (phm *packetHashMap) store(hash string) chan gopacket.Packet {
	phm.Lock()
	defer phm.Unlock()

	packetMatchChannel := make(chan gopacket.Packet, 1)
	phm.m[hash] = packetMatchChannel

	return packetMatchChannel
}
