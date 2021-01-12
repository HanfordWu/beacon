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

	testSize := 1000
	testPaths := make([]Path, testSize)

	for i := 0; i < testSize; i++ {
		testPaths[i] = Path{
			// hardcoded to work in a specific crystalnet env
			// might be useful to generalize this in some way
			net.IP{13, 106, 238, 13},
			net.IP{207, 46, 33, 175},
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
