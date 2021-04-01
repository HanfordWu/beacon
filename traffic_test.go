package beacon

import (
	"net"
	"sync"
	"testing"
)

func BenchmarkRoutineCreation(b *testing.B) {
	testSize := 1000
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		wg.Add(testSize)
		for i := 0; i < testSize; i++ {
			go func() {
				defer wg.Done()
				return
			}()
		}
		wg.Wait()
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

	testSize := 100
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
