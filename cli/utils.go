package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
	"time"
)

// runWithGRPCClient prepares a gRPC client for callback fn.
func runWithGRPCClient(
	sockFile string,
	fn func(ctx context.Context, client proto.GRPCClient),
) {
	conn, err := grpc.NewClient(
		"unix://"+sockFile,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		fmt.Printf("Cannot connect to %s: %v\n", sockFile, err)
		os.Exit(1)
	}
	defer func(conn *grpc.ClientConn) {
		_ = conn.Close()
	}(conn)

	client := proto.NewGRPCClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	fn(ctx, client)
}

// fn calls a gRPC method which returns a string response.
func runWithGRPCClientHandleStringResponse(
	sockFile string,
	fn func(ctx context.Context, client proto.GRPCClient) (*proto.StringResponse, error),
) {
	runWithGRPCClient(sockFile, func(ctx context.Context, client proto.GRPCClient) {
		resp, err := fn(ctx, client)
		if err != nil {
			fmt.Printf("Error calling gRPC method: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(resp.GetS())
	})
}
