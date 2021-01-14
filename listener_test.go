package beacon

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

func TestStore(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		return true
	})

	lm.Store(l.id, l)

	actualListener, ok := lm.m[l.id]
	if !ok {
		t.Errorf("expected to find listener in listener map after store but it was not found")
		t.FailNow()
	}

	if actualListener.id != l.id {
		t.Errorf("The listener found in the ListenerMap has id: %s but we inserted a listener with id: %s", actualListener.id, l.id)
	}
}

func TestLoad(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		return true
	})

	lm.Store(l.id, l)

	_, ok := lm.Load(l.id)
	if !ok {
		t.Errorf("Coudn't find listener with id %s in ListenerMap after storing it", l.id)
	}
}

func TestNonExistentLoad(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		return true
	})

	_, ok := lm.Load(l.id)
	if ok {
		t.Errorf("Found listener with id: %s in listenerMap which shouldn't exist", l.id)
	}
}

func TestStoreAndDelete(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		return true
	})

	lm.Store(l.id, l)
	lm.Delete(l.id)

	_, ok := lm.Load(l.id)
	if ok {
		t.Errorf("Found listener with id: %s in listenerMap after it should have been deleted", l.id)
	}
}

func TestNonExistentDelete(t *testing.T) {
	lm := NewListenerMap()

	lm.Delete(uuid.New()) // doesn't raise
}

func TestRunMatch(t *testing.T) {
	lm := NewListenerMap()

	desiredBytes := []byte{156,
		40,
		214,
		79,
		19,
		48,
		68,
		114,
		131,
		52,
		211,
		254,
		63,
		212,
		217,
		42,
	}

	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		if bytes.Equal(id, desiredBytes) {
			return true
		}
		return false
	})

	lm.Store(l.id, l)

	buf := gopacket.NewSerializeBuffer()
	err := BuildICMPTraceroutePacket(
		net.IP{0, 0, 0, 0},
		net.IP{0, 0, 0, 0},
		64,
		desiredBytes,
		buf,
		0,
		96,
	)
	if err != nil {
		t.Errorf("Failed to create a packet for the test: %s", err)
		t.FailNow()
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	lm.Run(packet)

	select {
	case <-l.matchChan:
		return
	case <-time.After(100 * time.Millisecond):
		t.Errorf("Despite criteria matching, a packet never came back over the match chan")
	}
}

func TestRunNoMatch(t *testing.T) {
	lm := NewListenerMap()
	desiredBytes := []byte{156,
		40,
		214,
		79,
		19,
		48,
		68,
		114,
		131,
		52,
		211,
		254,
		63,
		212,
		217,
		42,
	}
	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		if bytes.Equal(id, desiredBytes) {
			return true
		}
		return false
	})
	lm.Store(l.id, l)

	nonMatchingBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		nonMatchingBytes[i] = 0
	}

	buf := gopacket.NewSerializeBuffer()
	err := BuildICMPTraceroutePacket(
		net.IP{0, 0, 0, 0},
		net.IP{0, 0, 0, 0},
		64,
		nonMatchingBytes,
		buf,
		0,
		96,
	)
	if err != nil {
		t.Errorf("Failed to create a packet for the test: %s", err)
		t.FailNow()
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	lm.Run(packet)

	select {
	case <-l.matchChan:
		t.Errorf("A packet came back over the match channel which should not have met the criteria")
	case <-time.After(100 * time.Millisecond):
		return
	}
}

func TestListenerCount(t *testing.T) {
	tc := TransportChannel{
		listenerMap: NewListenerMap(),
	}
	desiredBytes := []byte{156,
		40,
		214,
		79,
		19,
		48,
		68,
		114,
		131,
		52,
		211,
		254,
		63,
		212,
		217,
		42,
	}

	l := NewListener(func(p gopacket.Packet, id []byte) bool {
		if bytes.Equal(id, desiredBytes) {
			return true
		}
		return false
	})

	tc.RegisterListener(l)

	numListeners := tc.ListenerCount()

	if tc.ListenerCount() != 1 {
		t.Errorf("Registered one listener and expected ListenerCount() to be 1, got %d instead", numListeners)
	}

	tc.UnregisterListener(l)

	numListeners = tc.ListenerCount()

	if tc.ListenerCount() != 0 {
		t.Errorf("Unregistered all listeners and expected ListenerCount() to be 0, got %d instead", numListeners)
	}
}
