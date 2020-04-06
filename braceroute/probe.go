package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/trstruth/beacon"

	"github.com/spf13/cobra"
)

var source string
var dest string
var timeout int
var numPackets int
var hops string

// ProbeCmd represents the probe subcommand which allows a user to send
// a probe of packets over a path from source to dest
var ProbeCmd = &cobra.Command{
	Use:   "probe",
	Short: "probe a path by generating traffic over it",
	Long:  "given a path A -> B -> C -> D, generate traffic to/from each hop and measure loss for each",
	PreRunE: probePreRun,
	RunE: probeRun,
}

func initProbe() {
	ProbeCmd.Flags().StringVarP(&source, "source", "s", "", "source IP/host (defaults to eth0 interface)")
	ProbeCmd.Flags().StringVarP(&dest, "dest", "d", "", "destination IP/host (required)")
	ProbeCmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "time (s) to wait on a packet to return")
	ProbeCmd.Flags().IntVarP(&numPackets, "num-packets", "n", 30, "number of probes to send per hop")
	ProbeCmd.Flags().StringVarP(&hops, "path", "p", "", "manually define a comma separated list of hops to probe")
}

func probePreRun(cmd *cobra.Command, args []string) error {
	if dest == "" && hops == "" {
		return errors.New("At least one of destination (-d) or path (-p) must be supplied")
	} else if dest != "" && hops != "" {
		return errors.New("Both destination (-d) and path (-p) cannot be supplied")
	} else if dest != "" && hops == "" {
		interfaceDeviceName, err := beacon.GetInterfaceDeviceFromDestString(dest)
		if err != nil {
			return err
		}
		interfaceDevice = interfaceDeviceName
	}

	return nil
}

func probeRun(cmd *cobra.Command, args []string) error {
	var err error
	var path beacon.Path

	if dest != "" {
		path, err = findPathFromSourceToDest()
	} else if hops != "" {
		path, err = parsePathFromHopsString(hops)
	} else {
		return errors.New("At least one of destination (-d) or path (-p) must be supplied")
	}
	if err != nil {
		return err
	}

	fmt.Printf("%v\n", path)

	resultChannels := make([]chan beacon.BoomerangResult, len(path)-1)
	for i := 2; i <= len(path); i++ {
		tc, err := beacon.NewTransportChannel(
			beacon.WithBPFFilter("ip proto 4"),
			beacon.WithInterface(interfaceDevice),
		)
		if err != nil {
			return err
		}
		resultChannels[i-2] = beacon.Probe(path[0:i], tc, numPackets, timeout)
	}

	stats := newProbeStats(path)

	handleResult := func(result beacon.BoomerangResult) error {
		if result.Err != nil {
			if result.IsFatal() {
				return fmt.Errorf("Fatal error while handling boomerang result: %s", result.Err)
			}
			stats.recordResponse(string(result.Payload), false)
			return nil
		}

		stats.recordResponse(string(result.Payload), true)
		return nil
	}

	for res := range merge(resultChannels...) {
		err := handleResult(res)
		if err != nil {
			return err
		}
		fmt.Println("\033[H\033[2J")
		fmt.Println(stats)
	}

	return nil
}

func findPathFromSourceToDest() (beacon.Path, error) {
	var srcIP, destIP net.IP

	pathFinderTC, err := beacon.NewTransportChannel(
		beacon.WithBPFFilter("icmp"),
		beacon.WithInterface(interfaceDevice),
	)
	if err != nil {
		return nil, err
	}

	// if no source was provided via cli flag, default to local
	if source == "" {
		srcIP, err = pathFinderTC.FindLocalIP()
	} else {
		srcIP, err = beacon.ParseIPFromString(source)
	}
	if err != nil {
		return nil, err
	}

	destIP, err = beacon.ParseIPFromString(dest)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Finding path from %s to %s\n", srcIP, destIP)

	path, err := pathFinderTC.GetPathFromSourceToDest(srcIP, destIP)
	if err != nil {
		return nil, err
	}
	pathFinderTC.Close()

	// prepend the host to the path
	vantageIP, err := pathFinderTC.FindLocalIP()
	if err != nil {
		return nil, err
	}
	if !(path[0].Equal(vantageIP)) {
		path = append([]net.IP{vantageIP}, path...)
	}

	return path, nil
}

func parsePathFromHopsString(hops string) (beacon.Path, error) {
	hopPath := strings.Split(hops, ",")
	path := make([]net.IP, len(hopPath))
	for idx, hop := range hopPath {
		ipAddr, err := beacon.ParseIPFromString(hop)
		if err != nil {
			return nil, err
		}
		path[idx] = ipAddr
	}
	return path, nil
}

func merge(resultChannels ...chan beacon.BoomerangResult) <-chan beacon.BoomerangResult {
	var wg sync.WaitGroup
	resultChannel := make(chan beacon.BoomerangResult)

	drain := func(c chan beacon.BoomerangResult) {
		for res := range c {
			resultChannel <- res
		}
		wg.Done()
	}

	wg.Add(len(resultChannels))
	for _, c := range resultChannels {
		go drain(c)
	}

	go func() {
		wg.Wait()
		close(resultChannel)
	}()

	return resultChannel
}
