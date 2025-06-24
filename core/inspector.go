package core

import (
	"context"
	"encoding/json"
	"fippf/cli/proto"
	"github.com/rs/zerolog"
	slogmulti "github.com/samber/slog-multi"
	slogzerolog "github.com/samber/slog-zerolog/v2"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type gRPCServer struct {
	proto.UnimplementedGRPCServer
	logLock sync.Mutex
}

func (server *gRPCServer) InspectConfig(_ context.Context, req *proto.InspectConfigRequest) (*proto.StringResponse, error) {
	c := viper.AllSettings()
	var out []byte
	var err error
	switch req.Format {
	case proto.ConfigFormat_JSON:
		out, err = json.MarshalIndent(c, "", "  ")
	case proto.ConfigFormat_YAML:
		out, err = yaml.Marshal(c)
	}

	var s string
	if err != nil {
		s = "Unexpected error when marshalling config:" + err.Error()
	} else {
		s = string(out)
	}
	return &proto.StringResponse{S: s}, nil
}

type RemoteWriter struct {
	stream grpc.ServerStreamingServer[proto.StringResponse]
}

func (w *RemoteWriter) Write(p []byte) (n int, err error) {
	err = w.stream.Send(&proto.StringResponse{S: string(p)})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (server *gRPCServer) InspectLog(req *proto.InspectLogRequest, stream grpc.ServerStreamingServer[proto.StringResponse]) error {
	if l := server.logLock.TryLock(); !l {
		return stream.Send(&proto.StringResponse{S: "Another log inspection is in progress.\n"})
	}
	defer server.logLock.Unlock()

	level := slog.Level(req.GetLevel())
	noColor := req.GetPlain()

	zRemoteLogger := zerolog.New(zerolog.ConsoleWriter{
		Out:        &RemoteWriter{stream: stream},
		NoColor:    noColor,
		TimeFormat: time.TimeOnly,
	})
	remoteLogger := slog.New(slogzerolog.Option{Level: level, Logger: &zRemoteLogger}.NewZerologHandler())

	oldLogger := slog.Default()
	// this `oldLogger` cannot be THE default logger of slog package, or it will be problematic.
	// see comments on `slog.SetDefault` for details.
	slog.SetDefault(slog.New(
		slogmulti.Fanout(
			oldLogger.Handler(),
			remoteLogger.Handler(),
		),
	))
	defer slog.SetDefault(oldLogger)

	<-stream.Context().Done() // wait until cli disconnects
	return nil
}

func RunInspector(sockFile string) {
	defer func() {
		slog.Warn("Inspector quited due to preceding error. Monitoring through cli is no longer available.")
	}()
	dir := filepath.Dir(sockFile)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		slog.Error("Error creating directory "+dir, "err", err)
		return
	}
	_, err = os.Stat(sockFile)
	if err == nil {
		// Socket file exists, remove it to avoid "address already in use" error
		if err = os.Remove(sockFile); err != nil {
			slog.Error("Error removing existing socket file "+sockFile, "err", err)
			return
		}
	}

	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		slog.Error("Failed to listen on "+sockFile, "err", err)
		return
	}
	defer func(listener net.Listener) {
		_ = listener.Close()
	}(listener)

	if err = os.Chmod(sockFile, 0666); err != nil {
		slog.Warn("Failed to set permission on socket file. Users may have trouble using the cli.")
	}

	s := grpc.NewServer()
	proto.RegisterGRPCServer(s, &gRPCServer{
		logLock: sync.Mutex{},
	})
	slog.Info("Inspector started, listening on " + sockFile)
	if err := s.Serve(listener); err != nil {
		slog.Error("GRPC server failed:", "err", err)
	}
}
