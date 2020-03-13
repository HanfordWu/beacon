package main

import (
	"github.com/spf13/cobra"
	"github.com/trstruth/beacon"
)

var reverse bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "braceroute",
	Short: "the beacon of gondor has been lit",
	Long:  "Localize network failures using IP in IP encapsulation",
	Args: cobra.ExactArgs(1),
	RunE:    rootRun,
	Version: "v0.1.0",
}

func initRoot() {
	RootCmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "trace the route in reverse from target back to caller")
	RootCmd.AddCommand(SprayCmd)
}

func rootRun(cmd *cobra.Command, args []string) error {
	destIP, err := beacon.ParseIPFromString(args[0])
	if err != nil {
		return err
	}

	if reverse {
		if err := ReverseTraceroute(destIP); err != nil {
			return err
		}
	} else {
		if err := Traceroute(destIP); err != nil {
			return err
		}
	}

	return nil
}