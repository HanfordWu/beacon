package beacon

import (
	"bytes"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SrcDstTuple struct {
	src net.IP
	dst net.IP
}

func TestCreateRoundTripPacketForPath(t *testing.T) {
	path := Path{
		net.IP{10, 20, 30, 96},
		net.IP{104, 44, 22, 235},
		net.IP{104, 44, 19, 212},
	}
	expectedPayload := []byte("Test Payload")
	buf := gopacket.NewSerializeBuffer()

	err := CreateRoundTripPacketForPath(path, expectedPayload, buf)
	if err != nil {
		t.Errorf("Failed to create roundtrip packet for path: %s", err)
	}

	bufLayers := buf.Layers()

	actualNumLayers := len(bufLayers)
	expectedNumLayers := (len(path) * 2) + 1 // len(path) * 2 - 1 + 2
	if actualNumLayers != expectedNumLayers {
		t.Errorf("Expected the created packet to have %d layers, got %d layers", expectedNumLayers, actualNumLayers)
	}

	// decode the bytes into a gopacket
	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	actualPayload := packet.ApplicationLayer().Payload()
	if !bytes.Equal(expectedPayload, actualPayload) {
		t.Errorf("Expected the created packet payload contents to be %s, got %s instead", expectedPayload, actualPayload)
	}

	// if path is A, B, C then expected round trip is
	// A -> B -> C -> B -> A
	expectedSrcDstTuples := []SrcDstTuple{
		SrcDstTuple{src: net.IP{10, 20, 30, 96}, dst: net.IP{104, 44, 22, 235}},
		SrcDstTuple{src: net.IP{104, 44, 22, 235}, dst: net.IP{104, 44, 19, 212}},
		SrcDstTuple{src: net.IP{104, 44, 19, 212}, dst: net.IP{104, 44, 22, 235}},
		SrcDstTuple{src: net.IP{104, 44, 22, 235}, dst: net.IP{10, 20, 30, 96}},
	}

	// iterate over packet layers, skip last IPv4 layer, udp and payload
	for idx, l := range packet.Layers()[:4] {
		ip4, _ := l.(*layers.IPv4)

		actualSrc := ip4.SrcIP
		actualDst := ip4.DstIP

		t.Logf("layer %d: %s -> %s\n", idx, actualSrc, actualDst)

		expectedSrc := expectedSrcDstTuples[idx].src
		expectedDst := expectedSrcDstTuples[idx].dst

		if !actualSrc.Equal(expectedSrc) {
			t.Errorf("Mismatch while checking src IP of layer %d in constructed packet, expected %s, got %s", idx, expectedSrc, actualSrc)
		}
		if !actualDst.Equal(expectedDst) {
			t.Errorf("Mismatch while checking dst IP of layer %d in constructed packet, expected %s, got %s", idx, expectedDst, actualDst)
		}
	}
}

func TestCreateRoundTripPacketForShortPath(t *testing.T) {
	path := Path{net.IP{10, 20, 30, 96}}
	payload := []byte("Test Payload")
	buf := gopacket.NewSerializeBuffer()

	err := CreateRoundTripPacketForPath(path, payload, buf)
	if err == nil {
		t.Errorf("Expected an error to be raised when trying to create a round trip packet for path of len < 2")
		t.FailNow()
	}
	expectedErrMsg := "Path must have atleast 2 hops"
	if err.Error() != expectedErrMsg {
		t.Errorf("Expected error message: %s, got %s instead", expectedErrMsg, err.Error())
	}
}
