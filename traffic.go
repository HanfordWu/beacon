package beacon

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
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
	DestIP      net.IP
	ID          uuid.UUID
	TxTimestamp time.Time
	RxTimestamp time.Time
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

// DiscoverAndProbe first runs a traceroute from source to destination, then probes packets over the discovered path.
func (tc *TransportChannel) DiscoverAndProbe(src, dst net.IP, numPackets, timeout int) (<-chan BoomerangResult, error) {

	tracerouteTC, err := NewTransportChannel(
		WithInterface("any"),
		WithBPFFilter("icmp"),
		WithHasher(V4TraceRouteHasher{}),
		WithHasher(V6TraceRouteHasher{}),
		UseListeners(false),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to create TransportChannel for traceroute: %s", err)
	}

	path, err := tracerouteTC.GetPathTo(dst, 3)
	if err != nil {
		return nil, fmt.Errorf("Failed to run traceroute: %s", err)
	}

	tracerouteTC.Close()

	srcIP, err := FindSourceIPForDest(dst)
	if err != nil {
		return nil, err
	}
	prePath := []net.IP{srcIP}

	path = append(prePath, path...)
	log.Printf("found path: %v\n", path)

	return tc.ProbeEachHopOfPath(path, numPackets, timeout), nil
}

// ProbeEachHopOfPath probes each hop in a path, but accepts a transport channel as an argument.  This allows the caller to share
// one transport channel between many calls to Probe.  The supplied tranport channel must have a BPFFilter of "ip proto 4"
func (tc *TransportChannel) ProbeEachHopOfPath(path Path, numPackets int, timeout int) <-chan BoomerangResult {
	if !strings.Contains(tc.filter, "ip") && !strings.Contains(tc.filter, "ip6") {
		resultChan := make(chan BoomerangResult)

		go func() {
			errMsg := fmt.Sprintf("The supplied TransportChannel must contain an ip or ip6 BPFFilter. The supplied filter was: %s\n", tc.filter)
			resultChan <- BoomerangResult{Err: fmt.Errorf(errMsg), ErrorType: fatal}
		}()

		return resultChan
	}

	resultChannels := make([]chan BoomerangResult, len(path)-1)
	for i := 2; i <= len(path); i++ {
		resultChannels[i-2] = tc.Probe(path[0:i], numPackets, timeout)
	}

	return Merge(resultChannels...)
}

// ProbeEachHopOfPathSync synchronously probes each hop in a path.  That is, it waits for each round of packets to come
// back from each hop before sending the next round
func (tc *TransportChannel) ProbeEachHopOfPathSync(path Path, numPackets int, timeout int) <-chan BoomerangResult {
	if !strings.Contains(tc.filter, "ip") && !strings.Contains(tc.filter, "ip6") {
		resultChan := make(chan BoomerangResult)

		go func() {
			errMsg := fmt.Sprintf("The supplied TransportChannel must contain an ip or ip6 BPFFilter. The supplied filter was: %s\n", tc.filter)
			resultChan <- BoomerangResult{Err: fmt.Errorf(errMsg), ErrorType: fatal}
		}()

		return resultChan
	}

	resultChan := make(chan BoomerangResult)

	go func() {
		defer close(resultChan)
		for packetCount := 1; packetCount <= numPackets; packetCount++ {
			var wg sync.WaitGroup
			wg.Add(len(path) - 1)

			for i := 2; i <= len(path); i++ {
				go func(idx int) {
					resultChan <- tc.Boomerang(path[0:idx], timeout)
					wg.Done()
				}(i)
			}

			wg.Wait()
			time.Sleep(time.Duration(timeout) * time.Millisecond)
		}
	}()

	return resultChan
}

// Probe generates traffic over a given path and returns a channel of boomerang results
func (tc *TransportChannel) Probe(path Path, numPackets int, timeout int) chan BoomerangResult {
	resultChan := make(chan BoomerangResult)

	go func() {
		for i := 1; i <= numPackets; i++ {
			result := tc.Boomerang(path, timeout)
			resultChan <- result
		}
		close(resultChan)
	}()

	return resultChan
}

// Boomerang sends one packet which "boomerangs" over a given path.  For example, if the path is A,B,C,D the packet will travel
// A -> B -> C -> D -> C -> B -> A
func (tc *TransportChannel) Boomerang(path Path, timeout int) BoomerangResult {
	resultChan := make(chan BoomerangResult)

	id := uuid.New()
	tagString := []byte("moby")
	idMarshalled, _ := id.MarshalBinary() // no error is possible, this is just `return u[:], nil`
	idBytes := append(tagString, idMarshalled...)
	idHash := string(idBytes)

	buf := gopacket.NewSerializeBuffer()
	err := CreateRoundTripPacketForPath(path, idBytes, buf)
	if err != nil {
		return BoomerangResult{
			Err:       err,
			ErrorType: fatal,
		}
	}

	packetMatchChan := make(chan gopacket.Packet, 1)
	tc.RegisterHash(idHash, packetMatchChan)

	go func() {
		timeOutDuration := time.Duration(timeout) * time.Second
		timer := time.NewTimer(timeOutDuration)

		packetData := buf.Bytes()

		err := tc.SendToPath(packetData, path)
		if err != nil {
			log.Printf("error in SendToPath: %s\n", err)
			tc.UnregisterHash(idHash)

			resultChan <- BoomerangResult{
				Err:       err,
				ErrorType: sendError,
				Payload: BoomerangPayload{
					DestIP: path[len(path)-1],
				},
			}
			return
		}
		txTimestamp := time.Now().UTC()

		select {
		case matchedPacket := <-packetMatchChan:
			// extract the rx timestamp from the packet metadta
			packetMetadata := matchedPacket.Metadata()

			payload := BoomerangPayload{
				ID:          id,
				DestIP:      path[len(path)-1],
				TxTimestamp: txTimestamp,
				RxTimestamp: packetMetadata.CaptureInfo.Timestamp,
			}

			result := BoomerangResult{
				Payload: payload,
			}

			result.Payload.TxTimestamp = txTimestamp
			resultChan <- result
		case <-timer.C:
			tc.UnregisterHash(idHash)
			resultChan <- BoomerangResult{
				Payload: BoomerangPayload{
					ID:          id,
					DestIP:      path[len(path)-1],
					TxTimestamp: txTimestamp,
					RxTimestamp: time.Now().UTC(),
				},
				Err:       errors.New("timed out waiting for packet from " + path[len(path)-1].String()),
				ErrorType: timedOut,
			}
		}
	}()

	return <-resultChan
}
