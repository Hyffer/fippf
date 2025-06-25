package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Inspect running status",
	Run: func(cmd *cobra.Command, args []string) {
		runWithGRPCClientHandleStringResponse(sockFile,
			func(ctx context.Context, client proto.GRPCClient) (*proto.StringResponse, error) {
				return client.InspectStatus(ctx, &proto.InspectStatusRequest{})
			},
			func(s string) {
				fmt.Println(s)
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
