package main

import (
	"github.com/spf13/cobra"
	"github.com/trstruth/beacon"
)

var reverse bool
var interfaceDevice string
var timeout int
var sourceIP string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:     "braceroute",
	Short:   "the beacon of gondor has been lit",
	Long:    "Localize network failures using IP in IP encapsulation",
	Args:    cobra.ExactArgs(1),
	RunE:    rootRun,
	Version: "v0.1.0",
}

func initRoot() {
	RootCmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "trace the route in reverse from target back to caller")
	RootCmd.PersistentFlags().StringVarP(&interfaceDevice, "interface", "i", "eth0", "outbound interface to use")
	RootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 3, "time (s) to wait on a packet to return")
	RootCmd.PersistentFlags().StringVarP(&sourceIP, "sourceIP", "s", " ", "sourceIP")
	RootCmd.AddCommand(ProbeCmd)
}

func rootRun(cmd *cobra.Command, args []string) error {
	destIP, err := beacon.ParseIPFromString(args[0])
	if err != nil {
		return err
	}

	if reverse {
		if err := ReverseTraceroute(destIP, timeout); err != nil {
			return err
		}
	} else {
		if err := Traceroute(args[0], sourceIP, int32(timeout), interfaceDevice); err != nil {
			return err
		}
	}

	return nil
}
