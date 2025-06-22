package cli

import (
	"fippf/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configDir string

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launch FIPPF",
	Run: func(cmd *cobra.Command, args []string) {
		core.Launch(configDir, sockFile)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVar(&configDir, "config_dir", "/etc/fippf", "config directory")
	serveCmd.Flags().String("log_level", "info", "one of debug, info, warn, error")
	_ = viper.BindPFlag("log_level", serveCmd.Flags().Lookup("log_level"))
}
