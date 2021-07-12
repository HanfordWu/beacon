package beacon

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
	lSyslog "github.com/sirupsen/logrus/hooks/syslog"
	"log/syslog"
)

// PacketFilter represents a criteria that a packet can be said to meet.
type PacketFilter func(packet gopacket.Packet, id []byte) bool

// Listener is represented by a uuid and a criteria.
type Listener struct {
	id         uuid.UUID
	Criteria   PacketFilter
	matchChan  chan gopacket.Packet
	persistent bool
}

var log = logrus.New()

// NewListener return a new listener with the given criteria,
// a newly generated uuid and an initialized match channel.
func NewListener(criteria PacketFilter) *Listener {
	return &Listener{
		id:         uuid.New(),
		Criteria:   criteria,
		matchChan:  make(chan gopacket.Packet, 1),
		persistent: false,
	}
}

// NewPersistentListener return a new listener with the given criteria,
// a newly generated uuid and an initialized match channel.
// PersistentListener differs from Listener in that it will not be removed
// when a match is found.
func NewPersistentListener(criteria PacketFilter) *Listener {
	return &Listener{
		id:         uuid.New(),
		Criteria:   criteria,
		matchChan:  make(chan gopacket.Packet, 1),
		persistent: true,
	}
}

// ListenerMap is a threadsafe map meant to be used with Listeners.
type ListenerMap struct {
	sync.Mutex

	m map[uuid.UUID]*Listener
}

// NewListenerMap returns a new ListenerMap and initializes the appropriate fields.
func NewListenerMap() *ListenerMap {
	var hook, err = lSyslog.NewSyslogHook("", "", syslog.LOG_INFO, "")
	if err == nil {
		log.Infof("moby-canary: Adding syslog hook")
		log.Hooks.Add(hook)
	} else {
		log.Errorf("moby-canary: Error getting syslog hook in canary main: %s", err)
	}

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

	app := p.ApplicationLayer()
	if app == nil {
		// packet doesn't have an application layer or payload < 16 bytes
		return
	}

	id := app.Payload()

	lm.Lock()

	for _, listener := range lm.m {
		// packet meets criteria

		if listener.Criteria(p, id) {
			listener.matchChan <- p
			if !listener.persistent {
				listenersToDelete = append(listenersToDelete, listener)
			}
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
// be sent to the caller over the returned channel.
func (tc *TransportChannel) RegisterListener(l *Listener) chan gopacket.Packet {
	tc.listenerMap.Store(l.id, l)

	return l.matchChan
}

// UnregisterListener removes an attached listener.
func (tc *TransportChannel) UnregisterListener(l *Listener) uuid.UUID {
	tc.listenerMap.Delete(l.id)

	return l.id
}

// ListenerCount returns an estimate of how many listeners are registered at
// a given point in time.  Note that this is only an estimate as we do not
// acquire the lock of the listenerMap in order to get its count, so the
// listenerMap may be modified as we are reading it.
func (tc *TransportChannel) ListenerCount() int {
	return len(tc.listenerMap.m)
}
