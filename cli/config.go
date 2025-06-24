package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"github.com/spf13/cobra"
)

var requiredFormat string

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration in use",
	Run: func(cmd *cobra.Command, args []string) {
		runWithGRPCClientHandleStringResponse(sockFile,
			func(ctx context.Context, client proto.GRPCClient) (*proto.StringResponse, error) {
				var format = proto.ConfigFormat_YAML
				switch requiredFormat {
				case "json":
					format = proto.ConfigFormat_JSON
				case "yaml":
				default:
					fmt.Println("Unknown format, defaulting to yaml")
				}
				return client.InspectConfig(ctx, &proto.InspectConfigRequest{Format: format})
			},
			func(s string) {
				fmt.Println(s)
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)

	configCmd.Flags().StringVarP(&requiredFormat, "format", "f", "yaml", "one of yaml, json")
}
