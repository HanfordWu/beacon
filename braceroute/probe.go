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

var dest string
var numPackets int
var hops string
var block bool

// ProbeCmd represents the probe subcommand which allows a user to send
// a probe of packets over a path from source to dest
var ProbeCmd = &cobra.Command{
	Use:     "probe",
	Short:   "probe a path by generating traffic over it",
	Long:    "given a path A -> B -> C -> D, generate traffic to/from each hop and measure loss for each",
	PreRunE: probePreRun,
	RunE:    probeRun,
}

func initProbe() {
	ProbeCmd.Flags().StringVarP(&dest, "dest", "d", "", "destination IP/host (required)")
	ProbeCmd.Flags().IntVarP(&numPackets, "num-packets", "n", 30, "number of probes to send per hop")
	ProbeCmd.Flags().StringVarP(&hops, "path", "p", "", "manually define a comma separated list of hops to probe")
	ProbeCmd.Flags().BoolVarP(&block, "block", "b", false, "block on receiving a result from each hop per packet")
}

func probePreRun(cmd *cobra.Command, args []string) error {
	if dest == "" && hops == "" {
		return errors.New("At least one of destination (-d) or path (-p) must be supplied")
	} else if dest != "" && hops != "" {
		return errors.New("Both destination (-d) and path (-p) cannot be supplied")
	} else if dest != "" && hops == "" {
		if interfaceDevice == "" {
			interfaceDeviceName, err := beacon.GetInterfaceDeviceFromDestString(dest)
			if err != nil {
				return err
			}
			interfaceDevice = interfaceDeviceName
		}
	}

	return nil
}

func probeRun(cmd *cobra.Command, args []string) error {
	var err error
	var inputPath beacon.Path

	if dest != "" {
		inputPath, err = findPathFromSourceToDest()
	} else if hops != "" {
		inputPath, err = parsePathFromHopsString(hops)
	} else {
		return errors.New("At least one of destination (-d) or path (-p) must be supplied")
	}
	if err != nil {
		return err
	}

	var path beacon.Path
	for _, hop := range inputPath {
		if hop != nil {
			path = append(path, hop)
		}
	}

	fmt.Printf("%v\n", path)

	stats := newProbeStats(path, numPackets, interfaceDevice)

	tc, err := beacon.NewTransportChannel(
		beacon.WithBPFFilter("ip proto 4"),
		beacon.WithInterface(interfaceDevice),
		beacon.WithTimeout(100),
	)
	if err != nil {
		return fmt.Errorf("Failed to create new TransportChannel: %s", err)
	}

	handleResult := func(result beacon.BoomerangResult) error {
		if result.Err != nil {
			if result.IsFatal() {
				return fmt.Errorf("Fatal error while handling boomerang result: %s", result.Err)
			}
			stats.recordResponse(result.Payload.DestIP.String(), false)
			return nil
		}

		stats.recordResponse(result.Payload.DestIP.String(), true)
		return nil
	}

	var resultChan <-chan beacon.BoomerangResult
	if block {
		resultChan = tc.ProbeEachHopOfPathSync(path, numPackets, timeout)
	} else {
		resultChan = tc.ProbeEachHopOfPath(path, numPackets, timeout)
	}

	for res := range resultChan {
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
	)
	if err != nil {
		return nil, err
	}

	destIP, err = beacon.ParseIPFromString(dest)
	if err != nil {
		return nil, err
	}

	var path beacon.Path

	if source == "" {
		// if no source was provided via cli flag, use best source for dest
		srcIP, err = pathFinderTC.FindSourceIPForDest(destIP)
		if err != nil {
			return nil, err
		}

		fmt.Printf("Finding path to %s\n", destIP)
		path, err = pathFinderTC.GetPathTo(destIP, timeout)
		if err != nil {
			return nil, err
		}

		path = append([]net.IP{srcIP}, path...)

	} else {
		srcIP, err = beacon.ParseIPFromString(source)
		fmt.Printf("Finding path from %s to %s\n", srcIP, destIP)
		path, err = pathFinderTC.GetPathFromSourceToDest(srcIP, destIP, timeout)
		if err != nil {
			return nil, err
		}

		vantageIP, err := pathFinderTC.FindLocalIP()
		if err != nil {
			return nil, err
		}
		if !(path[0].Equal(vantageIP)) {
			path = append([]net.IP{vantageIP}, path...)
		}
	}

	pathFinderTC.Close()

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
