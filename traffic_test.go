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
	destIP := net.IP{207, 46, 33, 175}
	srcIP, err := tc.FindSourceIPForDest(destIP)
	if err != nil {
		b.Errorf("Failed to find a sourceIP for %s: %s", destIP, err)
		b.FailNow()
	}

	b.Logf("Found srcIP: %s", srcIP)

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

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			// hardcoded to work in a specific crystalnet env
			// might be useful to generalize this in some way
			net.ParseIP("2a01:111:2000:6::10a"),
			net.ParseIP("2a01:111:2000::2:f000:e"),
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

func BenchmarkFindSourceIPForDest(b *testing.B) {
	tc, err := NewBoomerangTransportChannel()
	if err != nil {
		b.Errorf("Failed to create a transport channel: %s", err)
		b.FailNow()
	}

	destIP := net.IP{207, 46, 33, 175}

	for n := 0; n < b.N; n++ {
		_, err := tc.FindSourceIPForDest(destIP)
		if err != nil {
			b.Errorf("Failed to find a srcIP for %s: %s", destIP, err)
			b.FailNow()
		}
	}
}
