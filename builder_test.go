package beacon

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerInfo struct {
	src   net.IP
	dst   net.IP
	proto layers.IPProtocol
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
	expectedNumLayers := (len(path) * 2)
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
	expectedLayerInfos := []LayerInfo{
		LayerInfo{src: net.IP{10, 20, 30, 96}, dst: net.IP{104, 44, 22, 235}, proto: 4},
		LayerInfo{src: net.IP{104, 44, 22, 235}, dst: net.IP{104, 44, 19, 212}, proto: 4},
		LayerInfo{src: net.IP{104, 44, 19, 212}, dst: net.IP{104, 44, 22, 235}, proto: 4},
		LayerInfo{src: net.IP{104, 44, 22, 235}, dst: net.IP{10, 20, 30, 96}, proto: 17},
	}

	// iterate over packet layers, skip udp and payload
	for idx, l := range packet.Layers()[:4] {
		ip4, _ := l.(*layers.IPv4)

		actualSrc := ip4.SrcIP
		actualDst := ip4.DstIP
		actualProto := ip4.Protocol

		t.Logf("layer %d: %s -> %s, %s\n", idx, actualSrc, actualDst, actualProto)

		expectedDst := expectedLayerInfos[idx].dst
		expectedProto := expectedLayerInfos[idx].proto

		if !actualDst.Equal(expectedDst) {
			t.Errorf("Mismatch while checking dst IP of layer %d in constructed packet, expected %s, got %s", idx, expectedDst, actualDst)
		}
		if actualProto != expectedProto {
			t.Errorf("Mismatch while checking protocol of layer %d in constructed packet, expected %s, got %s", idx, expectedProto, actualProto)
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

func TestIpv4UDPLayerIDField(t *testing.T) {
	sourceIP := net.IP{0, 0, 0, 0}
	destIP := net.IP{0, 0, 0, 0}

	v4UDPLayer := buildIPv4UDPLayer(sourceIP, destIP, 0)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	err := v4UDPLayer.SerializeTo(buf, opts)
	if err != nil {
		t.Errorf("Failed to serialize ipv4UDPLayer to bytes: %s", err)
		t.FailNow()
	}

	v4UDPLayerBytes := buf.Bytes()

	// the identifier: 0x        6D
	expectedIDField := []byte{0, 109}
	// the BPF Filter syntax is ip[4:2] which is the same as slicing from [4:6]
	// the 4+2 is added here to be explicit
	actualIDField := v4UDPLayerBytes[4 : 4+2]

	if !bytes.Equal(expectedIDField, actualIDField) {
		t.Errorf("ID Field contents differed in value:\nwanted: %s\ngot:    %s", hex.Dump(expectedIDField), hex.Dump(actualIDField))
	}
}

func TestIpv6UDPLayerIDField(t *testing.T) {
	sourceIP := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	destIP := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	v6UDPLayer := buildIPv6UDPLayer(sourceIP, destIP, 0)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	err := v6UDPLayer.SerializeTo(buf, opts)
	if err != nil {
		t.Errorf("Failed to serialize ipv6UDPLayer to bytes: %s", err)
		t.FailNow()
	}

	v6UDPLayerBytes := buf.Bytes()

	// the identifier: 0x        6D
	expectedIDField := []byte{0, 0}
	// the BPF Filter syntax is ip[2:2] which is the same as slicing from [2:4]
	// the 2+2 is added here to be explicit
	actualIDField := v6UDPLayerBytes[2 : 2+2]

	if !bytes.Equal(expectedIDField, actualIDField) {
		t.Errorf("ID Field contents differed in value:\nwanted: %s\ngot:    %s", hex.Dump(expectedIDField), hex.Dump(actualIDField))
	}
}
