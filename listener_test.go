package beacon

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

func TestStore(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
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
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
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
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
		return true
	})

	_, ok := lm.Load(l.id)
	if ok {
		t.Errorf("Found listener with id: %s in listenerMap which shouldn't exist", l.id)
	}
}

func TestStoreAndDelete(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
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
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
		if payload.ID == "test ID" {
			return true
		}
		return false
	})
	lm.Store(l.id, l)

	payloadBytes, err := json.Marshal(NewBoomerangPayload(net.IP{0, 0, 0, 0}, "test ID"))
	if err != nil {
		t.Errorf("Failed to create a payload for the test: %s", err)
		t.FailNow()
	}

	buf := gopacket.NewSerializeBuffer()
	err = buildICMPTraceroutePacket(
		net.IP{0, 0, 0, 0},
		net.IP{0, 0, 0, 0},
		64,
		payloadBytes,
		buf,
	)
	if err != nil {
		t.Errorf("Failed to create a packet for the test: %s", err)
		t.FailNow()
	}

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	lm.Run(packet)

	for range l.matchChan {
		return // a match came back over the match channel
	}

	t.Errorf("Despite criteria matching, a packet never came back over the match chan")
}

func TestRunNoMatch(t *testing.T) {
	lm := NewListenerMap()
	l := NewListener(func(p gopacket.Packet, payload *BoomerangPayload) bool {
		if payload.ID == "test ID" {
			return true
		}
		return false
	})
	lm.Store(l.id, l)

	payloadBytes, err := json.Marshal(NewBoomerangPayload(net.IP{0, 0, 0, 0}, "non-matching ID"))
	if err != nil {
		t.Errorf("Failed to create a payload for the test: %s", err)
		t.FailNow()
	}

	buf := gopacket.NewSerializeBuffer()
	err = buildICMPTraceroutePacket(
		net.IP{0, 0, 0, 0},
		net.IP{0, 0, 0, 0},
		64,
		payloadBytes,
		buf,
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
