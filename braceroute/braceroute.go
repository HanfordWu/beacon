package main

import (
	"fmt"
	"os"
)

func init() {
	RootCmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "trace the route in reverse from target back to caller")
	RootCmd.AddCommand(SprayCmd)

	SprayCmd.Flags().StringVarP(&source, "source", "s", "", "source IP/host (defaults to eth0 interface)")
	SprayCmd.Flags().StringVarP(&dest, "dest", "d", "", "destination IP/host (required)")
	SprayCmd.MarkFlagRequired("dest")
	SprayCmd.Flags().IntVarP(&timeout, "timeout", "t", 3, "time (s) to wait on a packet to return")
	SprayCmd.Flags().IntVarP(&numPackets, "num-packets", "n", 30, "number of packets to spray")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}
