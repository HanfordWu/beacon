package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/cobra"
	"github.com/trstruth/beacon"
)

var source string
var dest string
var timeout int
var numPackets int

// SprayCmd represents the spray subcommand which allows a user to send
// a spray of packets over a path from source to dest
var SprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "spray packets over a path",
	Long:  "longer description for spraying packets over a path",
	RunE:  sprayRun,
}

func initSpray() {
	SprayCmd.Flags().StringVarP(&source, "source", "s", "", "source IP/host (defaults to eth0 interface)")
	SprayCmd.Flags().StringVarP(&dest, "dest", "d", "", "destination IP/host (required)")
	SprayCmd.MarkFlagRequired("dest")
	SprayCmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "time (s) to wait on a packet to return")
	SprayCmd.Flags().IntVarP(&numPackets, "num-packets", "n", 30, "number of packets to spray")
}

func sprayRun(cmd *cobra.Command, args []string) error {
	var err error
	var srcIP, destIP net.IP

	// if no source was provided via cli flag, default to local
	if source == "" {
		srcIP, err = beacon.FindLocalIP()
	} else {
		srcIP, err = beacon.ParseIPFromString(source)
	}
	if err != nil {
		return err
	}

	destIP, err = beacon.ParseIPFromString(dest)
	if err != nil {
		return err
	}

	fmt.Printf("Finding path from %s to %s\n", srcIP, destIP)
	path, err := beacon.GetPathFromSourceToDest(srcIP, destIP)
	if err != nil {
		return err
	}

	// if the caller isn't the host, prepend the host to the path
	if source != "" {
		vantageIP, err := beacon.FindLocalIP()
		if err != nil {
			return err
		}
		path = append([]net.IP{vantageIP}, path...)
	}
	// path = []net.IP{net.IP{10, 20, 30, 96}, net.IP{207, 46, 35, 118}, net.IP{104, 44, 18, 117}}
	fmt.Printf("%v\n", path)

	tc, err := beacon.NewTransportChannel(beacon.WithBPFFilter("ip proto 4"))
	if err != nil {
		return err
	}

	return spray(path, tc)
}

func spray(path beacon.Path, tc *beacon.TransportChannel) error {
	payload := []byte("boomerang mode")
	buf := gopacket.NewSerializeBuffer()

	err := beacon.CreateRoundTripPacketForPath(path, payload, buf)
	if err != nil {
		return err
	}

	seen := make(chan []byte)

	go func() {
		for packet := range tc.Rx() {
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			udp, _ := udpLayer.(*layers.UDP)
			ip4, _ := ipv4Layer.(*layers.IPv4)

			if ip4.DstIP.Equal(path[0]) && ip4.SrcIP.Equal(path[1]) {
				// fmt.Printf("%s -> %s: %s\n", path[1], path[0], udp.Payload)
				seen <- udp.Payload
			}
		}
	}()

	timeOutDuration := time.Duration(timeout) * time.Second
	timer := time.NewTimer(timeOutDuration)
	timer.Stop()

	receivedPacketCount := 0
	for i := 1; i <= numPackets; i++ {
		timer.Reset(timeOutDuration)
		err = tc.SendToPath(buf.Bytes(), path)
		if err != nil {
			return err
		}

		select {
		case payload := <-seen:
			timer.Stop()
			receivedPacketCount++
			fmt.Printf("received packet with payload: %s\n", payload)
		case <-timer.C:
			fmt.Println("timed out waiting for the packet")
		}
		packetLoss := float32(100) * float32(i-receivedPacketCount) / float32(i)
		fmt.Printf("packet success rate: %d/%d, loss: %5f%% \n", receivedPacketCount, i, packetLoss)
	}
	return nil
}
