package cli

import (
	"context"
	"fippf/cli/proto"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
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
	ctx := context.Background()

	fn(ctx, client)
}

// `rpcCall` calls a gRPC method which returns a string response.
func runWithGRPCClientHandleStringResponse(
	sockFile string,
	rpcCall func(ctx context.Context, client proto.GRPCClient) (*proto.StringResponse, error),
	handler func(s string),
) {
	runWithGRPCClient(sockFile, func(ctx context.Context, client proto.GRPCClient) {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		resp, err := rpcCall(ctx, client)
		if err != nil {
			fmt.Printf("Error calling gRPC method: %v\n", err)
			os.Exit(1)
		}
		handler(resp.GetS())
	})
}

// `rpcCall` calls a gRPC method which returns a stream of string.
// `handler` might be called back multiple times, once for each string received.
func runWithGRPCClientHandleSStreamResponse(
	sockFile string,
	rpcCall func(ctx context.Context, client proto.GRPCClient) (grpc.ServerStreamingClient[proto.StringResponse], error),
	handler func(s string),
) {
	runWithGRPCClient(sockFile, func(ctx context.Context, client proto.GRPCClient) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stream, err := rpcCall(ctx, client)
		if err != nil {
			fmt.Printf("Error calling gRPC method: %v\n", err)
			os.Exit(1)
		}
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Printf("Error receiving from stream: %v\n", err)
				break
			}
			handler(resp.GetS())
		}
	})
}
