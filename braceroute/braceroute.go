package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/spf13/cobra"
)

var reverse bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "braceroute",
	Short: "the beacon of gondor has been lit",
	Long:  "Localize network failures using IP in IP encapsulation",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			cmd.Help()
			return errors.New("")
		}

		if len(args) > 1 {
			return fmt.Errorf("Expected one argument, got %d", len(args))
		}

		return nil
	},
	RunE:    bracerouteRun,
	Version: "v0.1.0",
}

func init() {
	RootCmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "trace the route in reverse from target back to caller")
}

func bracerouteRun(cmd *cobra.Command, args []string) error {
	destIP := net.ParseIP(args[0])

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
