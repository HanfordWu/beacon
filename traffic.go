package beacon

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BoomerangResult represents the completion of one run of boomerang, contains information about potential errors
// or the payload of a successful run
type BoomerangResult struct {
	Err       error
	ErrorType BoomerangErrorType
	Payload   string
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
	if b.ErrorType == fatal {
		return true
	}
	return false
}

// Spray generates traffic over a given path and returns a channel of boomerang results
func Spray(path Path, tc *TransportChannel, numPackets int, timeout int) chan BoomerangResult {
	payload := []byte(path[len(path)-1].String())
	resultChan := make(chan BoomerangResult)

	buf := gopacket.NewSerializeBuffer()
	err := CreateRoundTripPacketForPath(path, payload, buf)
	if err != nil {
		resultChan <- BoomerangResult{
			Err:       err,
			ErrorType: fatal,
		}

		return resultChan
	}

	go func() {
		for i := 1; i <= numPackets; i++ {
			result := Boomerang(path, tc, buf, payload, timeout)
			if result.Err != nil && (result.ErrorType == timedOut || result.ErrorType == sendError) {
				// tc.Close()
				tc, err = NewTransportChannel(
					WithBPFFilter(tc.filter),
					WithInterface(tc.deviceName),
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
func Boomerang(path Path, tc *TransportChannel, packetBuffer gopacket.SerializeBuffer, payload []byte, timeout int) BoomerangResult {
	seen := make(chan BoomerangResult)
	resultChan := make(chan BoomerangResult)

	go func() {
		for packet := range tc.Rx() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			udp, _ := udpLayer.(*layers.UDP)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if ip4.DstIP.Equal(path[0]) && ip4.SrcIP.Equal(path[1]) && bytes.Equal(udp.Payload, payload) {
				seen <- BoomerangResult{
					Payload: string(udp.Payload),
				}
				return
			}
		}
	}()

	go func() {
		timeOutDuration := time.Duration(timeout) * time.Second
		timer := time.NewTimer(timeOutDuration)

		err := tc.SendToPath(packetBuffer.Bytes(), path)
		if err != nil {
			fmt.Printf("error in SendToPath: %s\n", err)
			resultChan <- BoomerangResult{
				Err:       err,
				ErrorType: sendError,
				Payload:   path[len(path)-1].String(),
			}
			return
		}

		select {
		case result := <-seen:
			resultChan <- result
		case <-timer.C:
			resultChan <- BoomerangResult{
				Payload:   path[len(path)-1].String(),
				Err:       errors.New("timed out waiting for packet from " + path[len(path)-1].String()),
				ErrorType: timedOut,
			}
		}
	}()

	return <-resultChan
}
