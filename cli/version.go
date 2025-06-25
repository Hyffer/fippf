package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cli on %s\n", versioninfo.Short())

		runWithGRPCClientHandleStringResponse(sockFile,
			func(ctx context.Context, client proto.GRPCClient) (*proto.StringResponse, error) {
				return client.InspectVersion(ctx, &proto.InspectVersionRequest{})
			},
			func(s string) {
				fmt.Println(s)
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
