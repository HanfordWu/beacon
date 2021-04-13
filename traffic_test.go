package beacon

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"net"
	"sync"
	"testing"
)

func createTestIncomingBoomerangPacket(sourceIP, destIP net.IP) ([]byte, []byte) {
	id := uuid.New()
	tagString := []byte("moby")
	idMarshalled, _ := id.MarshalBinary() // no error is possible, this is just `return u[:], nil`
	idBytes := append(tagString, idMarshalled...)

	buf := gopacket.NewSerializeBuffer()
	buildUDPTraceroutePacket(sourceIP, destIP, layers.UDPPort(69), layers.UDPPort(69), 100, idBytes, buf)
	return idBytes, buf.Bytes()
}

func BenchmarkBoomerangNoLatency(b *testing.B) {
	testSize := 10000
	packetArray := make([]gopacket.Packet, testSize)
	packetChan := make(chan gopacket.Packet, testSize)
	srcIP := net.IP{0, 0, 0, 0}
	destIP := net.IP{10, 20, 8, 129}

	phm := NewPacketHashMap()
	phm.AttachHasher(BoomerangPacketHasher)

	for i := 0; i < testSize; i++ {
		// create inner packet layer
		idHash, packetBytes := createTestIncomingBoomerangPacket(srcIP, destIP)
		packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.Default)
		packetArray[i] = packet
		phm.store(string(idHash), packetChan)
	}
	for n := 0; n < b.N; n++ {
		for _, packet := range packetArray {
			phm.run(packet)
		}
		if len(packetChan) < testSize {
			b.Errorf("Did not match TestSize %d number of packets, found %d packets", testSize, len(packetChan))
		}
		numPackets := len(packetChan)
		for i := 0; i < numPackets; i++ {
			<-packetChan //drain chan for next run
		}
	}
}

func BenchmarkBoomerang(b *testing.B) {
	tc, err := NewBoomerangTransportChannel()
	if err != nil {
		b.Errorf("Failed to create a transport channel: %s", err)
		b.FailNow()
	}

	destIP := net.IP{10, 20, 8, 129}
	srcIP, err := FindSourceIPForDest(destIP)
	b.Logf("srcIP: %s", srcIP)
	if err != nil {
		b.Errorf("Failed to find a sourceIP for %s: %s", destIP, err)
		b.FailNow()
	}

	testSize := 1000
	testPaths := make([]Path, testSize)
	numFailed := 0

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			srcIP,
			destIP,
		}
	}

	timeout := 1
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		wg.Add(testSize)
		for _, path := range testPaths {
			go func(p Path) {
				defer wg.Done()
				result := tc.Boomerang(p, timeout)
				if result.Err != nil {
					numFailed += 1
				}
			}(path)
		}
		wg.Wait()
	}
	if numFailed > 0 {
		b.Errorf("number failed: %d", numFailed)
	}
}

func BenchmarkBoomerangIPV6(b *testing.B) {
	tc, err := NewBoomerangTransportChannel()
	if err != nil {
		b.Errorf("Failed to create a transport channel: %s", err)
		b.FailNow()
	}

	testSize := 1000
	testPaths := make([]Path, testSize)

	destIP := net.ParseIP("2a01:111:2000::a4")
	sourceIP, err := FindSourceIPForDest(destIP)
	if err != nil {
		b.Errorf("Failed to find source IP for dest %s: %s", destIP, err)
		b.FailNow()
	}

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			// hardcoded to work in a specific crystalnet env
			// might be useful to generalize this in some way
			sourceIP,
			destIP,
		}
	}

	timeout := 1
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		wg.Add(testSize)
		for _, path := range testPaths {
			go func(p Path) {
				defer wg.Done()
				result := tc.Boomerang(p, timeout)
				if result.Err != nil {
					b.Errorf("Boomerang call returned an error: %s", result.Err)
				}
			}(path)
		}
		wg.Wait()
	}
}

func BenchmarkV4FindSourceIPForDest(b *testing.B) {
	destIP := net.IP{207, 46, 33, 175}

	for n := 0; n < b.N; n++ {
		_, err := FindSourceIPForDest(destIP)
		if err != nil {
			b.Errorf("Failed to find a srcIP for %s: %s", destIP, err)
			b.FailNow()
		}
	}
}

func BenchmarkV6FindSourceIPForDest(b *testing.B) {
	destIPString := "2a01:111:2000::a4"
	destIP, err := ParseIPFromString(destIPString)
	if err != nil {
		b.Errorf("Failed to parse v6 IP from %s: %s", destIPString, err)
		b.FailNow()
	}

	for n := 0; n < b.N; n++ {
		_, err := FindSourceIPForDest(destIP)
		if err != nil {
			b.Errorf("Failed to find a srcIP for %s: %s", destIP, err)
			b.FailNow()
		}
	}
}
