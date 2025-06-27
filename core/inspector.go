package core

import (
	"context"
	"encoding/json"
	"fippf/cli/proto"
	"fmt"
	"github.com/earthboundkid/versioninfo/v2"
	"github.com/rs/zerolog"
	slogmulti "github.com/samber/slog-multi"
	slogzerolog "github.com/samber/slog-zerolog/v2"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"
	"gvisor.dev/gvisor/pkg/tcpip"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Inspectee struct {
	tunIf   *TunIf
	pool    *IPPool
	dnsHdlr *DNSHandler
}

type gRPCServer struct {
	proto.UnimplementedGRPCServer
	logLock   sync.Mutex
	inspectee Inspectee
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

func (server *gRPCServer) InspectStatus(_ context.Context, req *proto.InspectStatusRequest) (*proto.StringResponse, error) {
	status := make(map[string]any)

	// gVisor network stack status
	tunStats := server.inspectee.tunIf.stack.Stats()
	tunStatsInspectProperties := []string{
		"DroppedPackets",
		"TCP.CurrentConnected",
		"TCP.EstablishedClosed",
		"TCP.ForwardMaxInFlightDrop",
		"UDP.PacketsReceived",
	}

	// getStatCounterValue only works when `tunStats.<key>` is a *tcpip.StatCounter.
	getStatCounterValue := func(key string) (v any) {
		v = "err"
		fields := strings.Split(key, ".")
		obj := reflect.ValueOf(tunStats)
		for _, field := range fields {
			if obj.Kind() == reflect.Ptr {
				obj = obj.Elem() // Dereference pointer
			}
			obj = obj.FieldByName(field)
			if !obj.IsValid() {
				return
			}
		}
		if obj.Type() == reflect.TypeOf(&tcpip.StatCounter{}) {
			return obj.Interface().(*tcpip.StatCounter).Value()
		}
		return
	}

	tunIfStatus := make(map[string]any)
	for _, key := range tunStatsInspectProperties {
		tunIfStatus[key] = getStatCounterValue(key)
	}
	status["gVisor network stack"] = tunIfStatus

	// fake-IP DNS status
	dnsStatus := make(map[string]any)

	pool := server.inspectee.pool
	dnsStatus["Victim / Alloc / Total"] =
		fmt.Sprintf("%d / %d / %d", pool.victims.Len(), pool.current, pool.size)

	dnsStatus["DNS upstream"] = server.inspectee.dnsHdlr.dnsUpstream.Load()

	status["fake-IP DNS"] = dnsStatus

	// other runtime status
	status["goroutines"] = runtime.NumGoroutine()

	out, err := yaml.Marshal(status)
	var s string
	if err != nil {
		s = "Unexpected error when marshalling status:" + err.Error()
	} else {
		s = string(out)
	}
	return &proto.StringResponse{S: s}, nil
}

func (server *gRPCServer) InspectVersion(_ context.Context, _ *proto.InspectVersionRequest) (*proto.StringResponse, error) {
	return &proto.StringResponse{
		S: fmt.Sprintf("daemon on %s\n", versioninfo.Short()),
	}, nil
}

type RemoteWriter struct {
	stream grpc.ServerStreamingServer[proto.StringResponse]
	buf    chan string // asynchronously and sequentially write to stream
}

func (w *RemoteWriter) Write(p []byte) (n int, err error) {
	select {
	case w.buf <- string(p):
	default:
		// drop message when the buffer is full
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

	writer := &RemoteWriter{
		stream: stream,
		buf:    make(chan string, 20),
	}
	go func(w *RemoteWriter) {
		for {
			select {
			case <-w.stream.Context().Done():
				return
			case msg := <-w.buf:
				if err := w.stream.Send(&proto.StringResponse{S: msg}); err != nil {
					return
				}
			}
		}
	}(writer)

	zRemoteLogger := zerolog.New(zerolog.ConsoleWriter{
		Out:        writer,
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

func RunInspector(sockFile string, inspectee Inspectee) {
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
		logLock:   sync.Mutex{},
		inspectee: inspectee,
	})
	slog.Info("Inspector started, listening on " + sockFile)
	if err := s.Serve(listener); err != nil {
		slog.Error("GRPC server failed:", "err", err)
	}
}
