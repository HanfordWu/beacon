package beacon

import (
	"errors"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	destIP net.IP
	id   string
}

func NewBoomerangPayload(destIP net.IP, id string) *BoomerangPayload {
	return &BoomerangPayload{
		destIP: destIP,
		id: id,
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
				payload := &BoomerangPayload{}
				err := json.Unmarshal(udp.Payload, payload)
				if err != nil {
					log.Printf("error unmarshalling payload: %s", err)
					continue
				}
				seen <- BoomerangResult{
					Payload: *payload,
				}
				return
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
				Payload:   BoomerangPayload{
					destIP: path[len(path)-1],
				},
			}
			return
		}

		select {
		case result := <-seen:
			resultChan <- result
		case <-timer.C:
			resultChan <- BoomerangResult{
				Payload:   BoomerangPayload{
					destIP: path[len(path)-1],
				},
				Err:       errors.New("timed out waiting for packet from " + path[len(path)-1].String()),
				ErrorType: timedOut,
			}
		}
	}()

	return <-resultChan
}
