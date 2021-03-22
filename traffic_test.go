package beacon

import (
	"net"
	"sync"
	"testing"
)

func BenchmarkBoomerang(b *testing.B) {
	tc, err := NewBoomerangTransportChannel()
	if err != nil {
		b.Errorf("Failed to create a transport channel: %s", err)
		b.FailNow()
	}

	// hardcoded to work in a specific crystalnet env
	// might be useful to generalize this in some way
	destIP := net.IP{13,106, 210, 30}
	srcIP, err := FindSourceIPForDest(destIP)
	if err != nil {
		b.Errorf("Failed to find a sourceIP for %s: %s", destIP, err)
		b.FailNow()
	}

	testSize := 1000
	testPaths := make([]Path, testSize)

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
					b.Errorf("Boomerang call returned an error: %s", result.Err)
				}
			}(path)
		}
		wg.Wait()
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

	destIP := net.ParseIP("2a01:111:2000::2:f000:e")
	sourceIP, err := FindSourceIPForDest(destIP)
	if err != nil {
		b.Errorf("Failed to find source IP for dest %s: %s", destIP, err)
		b.FailNow()
	}

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			// hardcoded to work in a specific crystalnet env
			// might be useful to generalize this in some way
			// net.ParseIP("2a01:111:2000:6::10a"),
			// net.ParseIP("2a01:111:2000::2:f000:e"),
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
	destIPString := "2a01:111:2000::2:f000:e"
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
