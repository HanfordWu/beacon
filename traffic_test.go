package beacon

import (
	"net"
	"sync"
	"testing"
)

func BenchmarkBoomerang(b *testing.B) {
	tc, err := NewTransportChannel(
		WithBPFFilter("ip && ip[4:2]=0x6D"),
	)
	if err != nil {
		b.Errorf("Failed to create a transport channel: %s", err)
		b.FailNow()
	}

	testSize := 100
	testPaths := make([]Path, testSize)

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			// hardcoded to work in a specific crystalnet env
			// might be useful to generalize this in some way
			net.IP{192, 168, 0, 19},
			net.IP{192, 168, 255, 253},
		}
	}

	timeout := 1
	for n := 0; n < b.N; n++ {
		var wg sync.WaitGroup
		wg.Add(testSize)
		for _, path := range testPaths {
			go func(p Path) {
				defer wg.Done()
				result := tc.Boomerang(path, timeout)
				if result.Err != nil {
					b.Errorf("Boomerang call returned an error: %s", result.Err)
				}
			}(path)
		}
		wg.Wait()
	}
}
