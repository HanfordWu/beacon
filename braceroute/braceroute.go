package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "braceroute",
	Short: "the beacon of gondor has been lit",
	Long:  "Localize network failures using IP in IP encapsulation",
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of braceroute",
	Long:  `All software has versions. This is braceroute's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("v0.1.0")
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
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
