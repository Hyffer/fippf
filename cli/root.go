package cli

import (
	"github.com/spf13/cobra"
	"os"
)

var sockFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fippf",
	Short: "FIPPF: a Fake-IP Proxy Frontend",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().
		StringVarP(&sockFile, "sock", "s", "/run/fippf/fippf.sock", "unix socket file")
}
