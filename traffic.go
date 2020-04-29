package beacon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// BoomerangResult represents the completion of one run of boomerang, contains information about potential errors
// or the payload of a successful run
type BoomerangResult struct {
	Err       error
	ErrorType BoomerangErrorType
	Payload   BoomerangPayload
}

// BoomerangPayload is a field of BoomerangResult which is only populated when the BoomerangResult did not encounter an error
// this struct is designed to be JSON unmarshalled from the IP payload in the boomerang packet
type BoomerangPayload struct {
	DestIP net.IP
	ID     string
}

// NewBoomerangPayload constructs a BoomerangPayload struct
func NewBoomerangPayload(destIP net.IP, id string) *BoomerangPayload {
	return &BoomerangPayload{
		DestIP: destIP,
		ID:     id,
	}

}

// BoomerangErrorType is an enum of possible errors encountered during a run of boomerang
type BoomerangErrorType int

const (
	timedOut  BoomerangErrorType = iota
	fatal     BoomerangErrorType = iota
	sendError BoomerangErrorType = iota
)

// IsFatal returns true if the error is fatal, otherwise returns false
func (b *BoomerangResult) IsFatal() bool {
	return b.ErrorType == fatal
}

// ProbeEachHopOfPath accepts a path and some configuration variables, and returns a merged channel where results
// from every hop are pushed onto
// if errors are encountered while creating the transport channel, a fatal BoomerangResult will be pushed over the
// returned channel
func ProbeEachHopOfPath(path Path, interfaceDevice string, numPackets int, timeout int) <-chan BoomerangResult {
	resultChannels := make([]chan BoomerangResult, len(path)-1)
	for i := 2; i <= len(path); i++ {
		tc, err := NewTransportChannel(
			WithBPFFilter("ip proto 4"),
			WithInterface(interfaceDevice),
			WithTimeout(100),
		)
		if err != nil {
			resultChan := make(chan BoomerangResult)
			resultChan <- BoomerangResult{Err: err, ErrorType: fatal}
			return resultChan
		}
		resultChannels[i-2] = Probe(path[0:i], tc, numPackets, timeout)
	}

	return merge(resultChannels...)
}

// ProbeEachHopOfPathSync synchronously probes each hop in a path.  That is, it waits for each round of packets to come
// back from each hop before sending the next round
func ProbeEachHopOfPathSync(path Path, interfaceDevice string, numPackets int, timeout int) <-chan BoomerangResult {
	resultChan := make(chan BoomerangResult)

	transportChannels := make([]*TransportChannel, len(path)-1)

	// initialize transport channels
	for i := 2; i <= len(path); i++ {
		tc, err := NewTransportChannel(
			WithBPFFilter("ip proto 4"),
			WithInterface(interfaceDevice),
			WithTimeout(100),
		)
		if err != nil {
			resultChan <- BoomerangResult{Err: err, ErrorType: fatal}
			return resultChan
		}
		transportChannels[i-2] = tc
	}

	go func(p Path) {
		defer close(resultChan)
		for packetCount := 1; packetCount <= numPackets; packetCount++ {
			var wg sync.WaitGroup
			wg.Add(len(path) - 1)

			fmt.Println(p)
			for i := 2; i <= len(p); i++ {
				resultChan <- Boomerang(path[0:i], transportChannels[i-2], timeout)
				wg.Done()
			}

			wg.Wait()
		}
	}(path)

	return resultChan
}

// Probe generates traffic over a given path and returns a channel of boomerang results
func Probe(path Path, tc *TransportChannel, numPackets int, timeout int) chan BoomerangResult {
	resultChan := make(chan BoomerangResult)
	var err error

	go func() {
		for i := 1; i <= numPackets; i++ {
			result := Boomerang(path, tc, timeout)
			if result.Err != nil && (result.ErrorType == timedOut || result.ErrorType == sendError) {
				go tc.Close()
				tc, err = NewTransportChannel(
					WithBPFFilter(tc.filter),
					WithInterface(tc.deviceName),
					WithTimeout(tc.timeout),
				)
				if err != nil {
					resultChan <- BoomerangResult{
						Err:       err,
						ErrorType: fatal,
					}
					return
				}
			}
			resultChan <- result
		}
		close(resultChan)
	}()

	return resultChan
}

// Boomerang sends one packet which "boomerangs" over a given path.  For example, if the path is A,B,C,D the packet will travel
// A -> B -> C -> D -> C -> B -> A
func Boomerang(path Path, tc *TransportChannel, timeout int) BoomerangResult {
	listenerReady := make(chan bool)
	seen := make(chan BoomerangResult)
	resultChan := make(chan BoomerangResult)

	destHop := path[len(path)-1]
	id := uuid.New().String()
	payload, err := json.Marshal(NewBoomerangPayload(destHop, id))
	if err != nil {
		return BoomerangResult{
			Err:       err,
			ErrorType: fatal,
		}
	}

	buf := gopacket.NewSerializeBuffer()
	err = CreateRoundTripPacketForPath(path, payload, buf)
	if err != nil {
		return BoomerangResult{
			Err:       err,
			ErrorType: fatal,
		}
	}

	go func() {
		listenerReady <- true
		for packet := range tc.Rx() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			udp, _ := udpLayer.(*layers.UDP)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if ip4.DstIP.Equal(path[0]) && ip4.SrcIP.Equal(path[1]) {
				unmarshalledPayload := &BoomerangPayload{}
				err := json.Unmarshal(udp.Payload, unmarshalledPayload)
				if err != nil {
					continue
				}
				if unmarshalledPayload.ID == id {
					seen <- BoomerangResult{
						Payload: *unmarshalledPayload,
					}
					return
				}
			}
		}
	}()

	go func() {
		<-listenerReady

		timeOutDuration := time.Duration(timeout) * time.Second
		timer := time.NewTimer(timeOutDuration)

		err := tc.SendToPath(buf.Bytes(), path)
		if err != nil {
			fmt.Printf("error in SendToPath: %s\n", err)
			resultChan <- BoomerangResult{
				Err:       err,
				ErrorType: sendError,
				Payload: BoomerangPayload{
					DestIP: path[len(path)-1],
				},
			}
			return
		}

		select {
		case result := <-seen:
			resultChan <- result
		case <-timer.C:
			resultChan <- BoomerangResult{
				Payload: BoomerangPayload{
					DestIP: path[len(path)-1],
				},
				Err:       errors.New("timed out waiting for packet from " + path[len(path)-1].String()),
				ErrorType: timedOut,
			}
		}
	}()

	return <-resultChan
}
