package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"log/slog"
)

var (
	sLevel string
	plain  bool
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View log in real-time",
	Long: `View log in real-time.
This does not affect logs of daemon process.`,
	Run: func(cmd *cobra.Command, args []string) {
		runWithGRPCClientHandleSStreamResponse(sockFile,
			func(ctx context.Context, client proto.GRPCClient) (grpc.ServerStreamingClient[proto.StringResponse], error) {
				var level slog.Level
				err := level.UnmarshalText([]byte(sLevel))
				if err != nil {
					fmt.Printf("Unknown log level \"%s\", defaulting to debug", sLevel)
					level = slog.LevelDebug
				}
				return client.InspectLog(ctx, &proto.InspectLogRequest{
					Level: int32(level),
					Plain: plain,
				})
			},
			func(s string) {
				fmt.Print(s)
			},
		)
	},
}

func init() {
	rootCmd.AddCommand(logCmd)

	logCmd.Flags().StringVarP(&sLevel, "level", "l", "debug", "one of debug, info, warn, error")
	logCmd.Flags().BoolVarP(&plain, "plain", "p", false, "disable colors")
}
