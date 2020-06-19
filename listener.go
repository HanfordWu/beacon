package beacon

import (
	"encoding/json"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/uuid"
)

// PacketFilter represents a criteria that a packet can be said to meet.
type PacketFilter func(packet gopacket.Packet, payload *BoomerangPayload) bool

// Listener is represented by a uuid and a criteria
type Listener struct {
	id        uuid.UUID
	Criteria  PacketFilter
	matchChan chan gopacket.Packet
}

// NewListener return a new listener with the given criteria,
// a newly generated uuid and an initialized match channel.
func NewListener(criteria PacketFilter) *Listener {
	return &Listener{
		id:        uuid.New(),
		Criteria:  criteria,
		matchChan: make(chan gopacket.Packet, 1),
	}
}

// ListenerMap is a threadsafe map meant to be used with Listeners.
type ListenerMap struct {
	sync.Mutex

	m map[uuid.UUID]*Listener
}

// NewListenerMap returns a new ListenerMap and initializes the appropriate fields.
func NewListenerMap() *ListenerMap {
	return &ListenerMap{
		m: make(map[uuid.UUID]*Listener),
	}
}

// Store sets the value for a key.
func (lm *ListenerMap) Store(key uuid.UUID, value *Listener) {
	lm.Lock()
	defer lm.Unlock()

	lm.m[key] = value
}

// Load returns the value stored in the map for a key, or nil if no value is present.
// The ok result indicates whether value was found in the map.
func (lm *ListenerMap) Load(key uuid.UUID) (value *Listener, ok bool) {
	lm.Lock()
	defer lm.Unlock()

	value, ok = lm.m[key]
	return value, ok
}

// Delete deletes the value for a key.  no-op if key doesn't exist.
func (lm *ListenerMap) Delete(key uuid.UUID) {
	lm.Lock()
	defer lm.Unlock()

	if listener, ok := lm.m[key]; ok {
		close(listener.matchChan)
	}
	delete(lm.m, key)
}

// Run passes the supplied packet to the criteria func of each listener in the listeners map
// If the packet matches a listener, it is sent over the mapped channel, and the listener is deleted.
func (lm *ListenerMap) Run(p gopacket.Packet) {
	listenersToDelete := make([]*Listener, 0)

	unmarshalledPayload := &BoomerangPayload{}
	if app := p.ApplicationLayer(); app != nil {
		json.Unmarshal(app.Payload(), unmarshalledPayload)
	}

	lm.Lock()

	for _, listener := range lm.m {
		// packet meets criteria

		if listener.Criteria(p, unmarshalledPayload) {
			listener.matchChan <- p
			listenersToDelete = append(listenersToDelete, listener)
		}
	}

	lm.Unlock()

	for _, listener := range listenersToDelete {
		// TODO: Each iteration of this loop will lock and unlock the listenerMap
		// consider implementing bulk delete which only locks & unlocks once
		go lm.Delete(listener.id)
	}
}

// RegisterListener attaches a packet listener to the current transport channel.
// When the packet listener finds a packet matching its criteria, the packet will
// be sent to the caller over the returned channel
func (tc *TransportChannel) RegisterListener(l *Listener) chan gopacket.Packet {
	tc.listenerMap.Store(l.id, l)

	return l.matchChan
}

// UnRegisterListener removes an attached listener
func (tc *TransportChannel) UnregisterListener(l *Listener) uuid.UUID {
	tc.listenerMap.Delete(l.id)

	return l.id
}
